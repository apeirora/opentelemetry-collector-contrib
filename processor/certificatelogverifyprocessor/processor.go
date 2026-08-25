// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor"

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor/internal/metadata"
)

const (
	verifyStatusKey        = "verify_status"
	verifyReasonKey        = "verify_reason"
	verifyDetailsKey       = "verify_details"
	verifiedAtKey          = "verified_at"
	verificationProfileKey = "verification_profile"
	tier2StatusKey         = "tier2_status"
	exportStatusKey        = "export_status_overall"
	lastStateChangeAtKey   = "last_state_change_at"
	statusPassed           = "passed"
	statusFailed           = "failed"
	reasonOK               = "ok"
	tier2VerifiedQueued    = "verified_queued"
	tier2RejectedVerify    = "rejected_verify_failed"
)

type certificateHashProcessor struct {
	config     *Config
	logger     *zap.Logger
	nextLogs   consumer.Logs
	hmacKey    []byte
	cert       *x509.Certificate
	hashChain  *hashChainStore
	deadLetter *deadLetterStore
	telemetry  *metadata.TelemetryBuilder
}

func newProcessor(cfg *Config, nextLogs consumer.Logs, settings processor.Settings) (*certificateHashProcessor, error) {
	logger := componentLogger(settings.Logger)

	hmacKey, cert, err := loadSyncVerificationKeys(cfg, logger)
	if err != nil {
		return nil, err
	}

	telemetry, err := metadata.NewTelemetryBuilder(settings.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry builder: %w", err)
	}

	return &certificateHashProcessor{
		config:    cfg,
		logger:    logger,
		nextLogs:  nextLogs,
		hmacKey:   hmacKey,
		cert:      cert,
		telemetry: telemetry,
	}, nil
}

func (p *certificateHashProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

type verifiedRecord struct {
	streamID      string
	integrityHash string
	lr            plog.LogRecord
}

func (p *certificateHashProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	var verificationErr error
	var deadLetterErr error
	verified := make([]verifiedRecord, 0)

	resourceLogs := ld.ResourceLogs()
	resourceLogs.RemoveIf(func(rl plog.ResourceLogs) bool {
		resource := rl.Resource()
		rl.ScopeLogs().RemoveIf(func(sl plog.ScopeLogs) bool {
			sl.LogRecords().RemoveIf(func(lr plog.LogRecord) bool {
				if reason, err := p.verifyAuditLogRecord(resource, lr); err != nil {
					if dlErr := p.handleVerificationFailure(ctx, resource, lr, reason, err); dlErr != nil {
						deadLetterErr = dlErr
					}
					verificationErr = fmt.Errorf("%s: %w", tier2RejectedVerify, err)
					return p.config.FailureMode == FailureModeStrict
				}
				if p.hashChain != nil {
					integrityHash, err := integrityHashHex(lr)
					if err != nil {
						if dlErr := p.handleVerificationFailure(ctx, resource, lr, "hash_chain_compute_failed", err); dlErr != nil {
							deadLetterErr = dlErr
						}
						verificationErr = fmt.Errorf("%s: %w", tier2RejectedVerify, err)
						return p.config.FailureMode == FailureModeStrict
					}
					verified = append(verified, verifiedRecord{
						streamID:      streamIDFromRecord(resource, lr),
						integrityHash: integrityHash,
						lr:            lr,
					})
				}
				p.markPassed(ctx, lr)
				return false
			})
			return sl.LogRecords().Len() == 0
		})
		return rl.ScopeLogs().Len() == 0
	})

	if deadLetterErr != nil && p.config.DeadLetter.ShouldFailOnStorageError() {
		return consumererror.NewPermanent(fmt.Errorf("dead_letter_storage_failed: %w", deadLetterErr))
	}

	if verificationErr != nil && p.config.FailureMode == FailureModeStrict {
		return consumererror.NewPermanent(verificationErr)
	}

	if ld.LogRecordCount() == 0 {
		return nil
	}

	if err := p.nextLogs.ConsumeLogs(ctx, ld); err != nil {
		return err
	}

	for _, record := range verified {
		if err := p.hashChain.commit(record.streamID, record.lr, record.integrityHash); err != nil {
			return fmt.Errorf("failed to commit hash chain state: %w", err)
		}
	}
	return nil
}

func (p *certificateHashProcessor) markPassed(ctx context.Context, lr plog.LogRecord) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	attrs := lr.Attributes()
	attrs.PutStr(verifyStatusKey, statusPassed)
	attrs.PutStr(verifyReasonKey, reasonOK)
	attrs.PutStr(verifiedAtKey, now)
	attrs.PutStr(verificationProfileKey, p.config.VerificationProfile)
	attrs.PutStr(tier2StatusKey, tier2VerifiedQueued)
	attrs.PutStr(exportStatusKey, tier2VerifiedQueued)
	attrs.PutStr(lastStateChangeAtKey, now)
	p.recordVerifyOutcome(ctx, statusPassed, reasonOK)
}

func (p *certificateHashProcessor) handleVerificationFailure(ctx context.Context, resource pcommon.Resource, lr plog.LogRecord, reason string, err error) error {
	p.markFailed(lr, reason, err)
	p.recordVerifyOutcome(ctx, statusFailed, reason)
	p.logger.Error("Failed to verify audit log record", errString(err))
	if p.deadLetter == nil {
		p.recordDeadLetter(ctx, "skipped", reason)
		return nil
	}
	stored, dlErr := p.deadLetter.store(ctx, resource, lr, reason, err, p.config.FailureMode, p.config.VerificationProfile)
	if dlErr != nil {
		p.recordDeadLetter(ctx, "failed", reason)
		p.logger.Error("Failed to store record in dead letter queue", errString(dlErr))
		if p.config.DeadLetter.ShouldFailOnStorageError() {
			return dlErr
		}
		return nil
	}
	if stored {
		p.recordDeadLetter(ctx, "stored", reason)
	} else {
		p.recordDeadLetter(ctx, "skipped", reason)
	}
	return nil
}

func (p *certificateHashProcessor) recordVerifyOutcome(ctx context.Context, outcome, reason string) {
	if p.telemetry == nil {
		return
	}
	p.telemetry.ProcessorCertificatelogverifyRecords.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
		attribute.String("reason", reason),
	))
}

func (p *certificateHashProcessor) recordDeadLetter(ctx context.Context, result, reason string) {
	if p.telemetry == nil {
		return
	}
	p.telemetry.ProcessorCertificatelogverifyDeadLetter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.String("reason", reason),
	))
}

func (p *certificateHashProcessor) markFailed(lr plog.LogRecord, reason string, err error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	attrs := lr.Attributes()
	attrs.PutStr(verifyStatusKey, statusFailed)
	attrs.PutStr(verifyReasonKey, reason)
	attrs.PutStr(verifyDetailsKey, err.Error())
	attrs.PutStr(verifiedAtKey, now)
	attrs.PutStr(verificationProfileKey, p.config.VerificationProfile)
	attrs.PutStr(tier2StatusKey, tier2RejectedVerify)
	attrs.PutStr(exportStatusKey, tier2RejectedVerify)
	attrs.PutStr(lastStateChangeAtKey, now)
}

func (p *certificateHashProcessor) Start(ctx context.Context, host component.Host) error {
	if p.config.HashChain.Enabled {
		client, err := getStorageClient(ctx, host, p.config.HashChain.StorageID, "certificatelogverify-hashchain")
		if err != nil {
			return fmt.Errorf("failed to get hash chain storage client: %w", err)
		}
		p.hashChain = newHashChainStore(client)
	}

	if p.config.DeadLetter.Enabled {
		client, err := getStorageClient(ctx, host, p.config.DeadLetter.StorageID, "certificatelogverify-deadletter")
		if err != nil {
			return fmt.Errorf("failed to get dead letter storage client: %w", err)
		}
		p.deadLetter = newDeadLetterStore(p.config.DeadLetter, client, p.logger)
		p.logger.Info("Dead letter queue enabled",
			zap.String("storage", p.config.DeadLetter.StorageID.String()),
			zap.String("key_prefix", p.config.DeadLetter.effectiveKeyPrefix()),
		)
	}

	return nil
}

func getStorageClient(ctx context.Context, host component.Host, storageID component.ID, clientName string) (storage.Client, error) {
	extensions := host.GetExtensions()
	storageExtension, exists := extensions[storageID]
	if !exists {
		return nil, fmt.Errorf("storage extension %s not found", storageID)
	}
	storageExt, ok := storageExtension.(storage.Extension)
	if !ok {
		return nil, fmt.Errorf("storage extension %s does not implement storage.Extension", storageID)
	}
	return storageExt.GetClient(ctx, component.KindProcessor, storageID, clientName)
}

func (p *certificateHashProcessor) Shutdown(ctx context.Context) error {
	if p.telemetry != nil {
		p.telemetry.Shutdown()
	}
	return nil
}
