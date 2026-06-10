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
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
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
	statusDeferred         = "deferred"
	reasonOK               = "ok"
	reasonDeferred         = "deferred_by_policy"
	tier2AcceptedPending   = "accepted_pending_verify"
	tier2VerifiedQueued    = "verified_queued"
	tier2RejectedVerify    = "rejected_verify_failed"
)

type certificateHashProcessor struct {
	config    *Config
	logger    *zap.Logger
	nextLogs  consumer.Logs
	hmacKey   []byte
	cert      *x509.Certificate
	hashChain *hashChainStore
}

func newProcessor(cfg *Config, nextLogs consumer.Logs, settings processor.Settings) (*certificateHashProcessor, error) {
	logger := componentLogger(settings.Logger)

	var hmacKey []byte
	var cert *x509.Certificate
	if cfg.Mode == ModeSync {
		if cfg.HmacKeyFile != "" || (cfg.K8sSecret != nil && cfg.K8sSecret.HMACKeyEntry != "") {
			var err error
			hmacKey, err = loadHMACKey(cfg)
			if err != nil {
				return nil, err
			}
			logger.Info("Loaded HMAC key for audit log verification")
		}
		if cfg.CertFile != "" || (cfg.K8sSecret != nil && cfg.K8sSecret.CertKeyEntry != "") {
			var err error
			cert, err = loadCertificate(cfg)
			if err != nil {
				return nil, err
			}
			logger.Info("Loaded certificate for audit log signature verification")
		}
	}

	return &certificateHashProcessor{
		config:   cfg,
		logger:   logger,
		nextLogs: nextLogs,
		hmacKey:  hmacKey,
		cert:     cert,
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
	verified := make([]verifiedRecord, 0)

	resourceLogs := ld.ResourceLogs()
	resourceLogs.RemoveIf(func(rl plog.ResourceLogs) bool {
		resource := rl.Resource()
		rl.ScopeLogs().RemoveIf(func(sl plog.ScopeLogs) bool {
			sl.LogRecords().RemoveIf(func(lr plog.LogRecord) bool {
				if p.config.Mode == ModeDeferred {
					p.markDeferred(lr)
					return false
				}

				if reason, err := p.verifyAuditLogRecord(resource, lr); err != nil {
					p.markFailed(lr, reason, err)
					p.logger.Error("Failed to verify audit log record", errString(err))
					verificationErr = fmt.Errorf("%s: %w", tier2RejectedVerify, err)
					return p.config.FailureMode == FailureModeStrict
				}
				p.markPassed(lr)
				if p.hashChain != nil {
					integrityHash, err := integrityHashHex(lr)
					if err != nil {
						verificationErr = fmt.Errorf("%s: %w", tier2RejectedVerify, err)
						return p.config.FailureMode == FailureModeStrict
					}
					verified = append(verified, verifiedRecord{
						streamID:      streamIDFromRecord(resource, lr),
						integrityHash: integrityHash,
						lr:            lr,
					})
				}
				return false
			})
			return sl.LogRecords().Len() == 0
		})
		return rl.ScopeLogs().Len() == 0
	})

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

func (p *certificateHashProcessor) markDeferred(lr plog.LogRecord) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	attrs := lr.Attributes()
	attrs.PutStr(verifyStatusKey, statusDeferred)
	attrs.PutStr(verifyReasonKey, reasonDeferred)
	attrs.PutStr(verifiedAtKey, "")
	attrs.PutStr(verificationProfileKey, p.config.VerificationProfile)
	attrs.PutStr(tier2StatusKey, tier2AcceptedPending)
	attrs.PutStr(exportStatusKey, tier2AcceptedPending)
	attrs.PutStr(lastStateChangeAtKey, now)
}

func (p *certificateHashProcessor) markPassed(lr plog.LogRecord) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	attrs := lr.Attributes()
	attrs.PutStr(verifyStatusKey, statusPassed)
	attrs.PutStr(verifyReasonKey, reasonOK)
	attrs.PutStr(verifiedAtKey, now)
	attrs.PutStr(verificationProfileKey, p.config.VerificationProfile)
	attrs.PutStr(tier2StatusKey, tier2VerifiedQueued)
	attrs.PutStr(exportStatusKey, tier2VerifiedQueued)
	attrs.PutStr(lastStateChangeAtKey, now)
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
	if !p.config.HashChain.Enabled {
		return nil
	}

	extensions := host.GetExtensions()
	storageExtension, exists := extensions[p.config.HashChain.StorageID]
	if !exists {
		return fmt.Errorf("hash chain storage extension %s not found", p.config.HashChain.StorageID)
	}

	storageExt, ok := storageExtension.(storage.Extension)
	if !ok {
		return fmt.Errorf("storage extension %s does not implement storage.Extension", p.config.HashChain.StorageID)
	}

	client, err := storageExt.GetClient(ctx, component.KindProcessor, p.config.HashChain.StorageID, "certificatelogverify")
	if err != nil {
		return fmt.Errorf("failed to get hash chain storage client: %w", err)
	}
	p.hashChain = newHashChainStore(client)
	return nil
}

func (p *certificateHashProcessor) Shutdown(ctx context.Context) error {
	return nil
}
