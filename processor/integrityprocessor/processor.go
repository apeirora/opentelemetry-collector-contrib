// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrityprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"sort"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type integrityProcessor struct {
	config        *Config
	logger        *zap.Logger
	openBaoClient *openBaoClient
	localSecret   []byte
	useOpenBao    bool
}

func newIntegrityProcessor(config *Config, logger *zap.Logger) (*integrityProcessor, error) {
	proc := &integrityProcessor{
		config: config,
		logger: logger,
	}

	if config.Sign.OpenBaoTransit != nil {
		proc.useOpenBao = true
		proc.openBaoClient = newOpenBaoClient(config.Sign.OpenBaoTransit, logger)
		logger.Info("Using OpenBao Transit for HMAC signing",
			zap.String("address", config.Sign.OpenBaoTransit.Address),
			zap.String("key_name", config.Sign.OpenBaoTransit.KeyName),
		)
	} else if config.Sign.LocalSecret != nil {
		proc.useOpenBao = false
		proc.localSecret = []byte(config.Sign.LocalSecret.Secret)
		logger.Info("Using local secret for HMAC signing")
	}

	return proc, nil
}

func (p *integrityProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		resourceAttrs := rl.Resource().Attributes()

		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			sl := sls.At(j)
			logs := sl.LogRecords()

			for k := 0; k < logs.Len(); k++ {
				logRecord := logs.At(k)

				signature, err := p.signLogRecord(ctx, logRecord, resourceAttrs)
				if err != nil {
					p.logger.Error("Failed to sign log record", zap.Error(err))
					continue
				}

				logRecord.Attributes().PutStr(p.config.Sign.SignatureAttribute, signature)
			}
		}
	}

	return ld, nil
}

func (p *integrityProcessor) signLogRecord(ctx context.Context, logRecord plog.LogRecord, resourceAttrs pcommon.Map) (string, error) {
	dataToSign, err := p.serializeLogRecord(logRecord, resourceAttrs)
	if err != nil {
		return "", fmt.Errorf("failed to serialize log record: %w", err)
	}

	if p.useOpenBao {
		return p.openBaoClient.signHMAC(ctx, dataToSign, p.config.Sign.Algorithm)
	}

	return p.signWithLocalSecret(dataToSign, p.config.Sign.Algorithm)
}

func (p *integrityProcessor) serializeLogRecord(logRecord plog.LogRecord, resourceAttrs pcommon.Map) ([]byte, error) {
	var parts []string

	parts = append(parts, logRecord.Body().AsString())
	parts = append(parts, logRecord.SeverityText())
	parts = append(parts, fmt.Sprintf("%d", logRecord.SeverityNumber()))
	parts = append(parts, fmt.Sprintf("%d", logRecord.Timestamp()))
	parts = append(parts, fmt.Sprintf("%d", logRecord.ObservedTimestamp()))
	parts = append(parts, logRecord.TraceID().String())
	parts = append(parts, logRecord.SpanID().String())

	logAttrs := logRecord.Attributes()
	attrKeys := make([]string, 0, logAttrs.Len())
	logAttrs.Range(func(k string, v pcommon.Value) bool {
		attrKeys = append(attrKeys, k)
		return true
	})
	sort.Strings(attrKeys)

	for _, k := range attrKeys {
		if k == p.config.Sign.SignatureAttribute {
			continue
		}
		v, _ := logAttrs.Get(k)
		parts = append(parts, k, v.AsString())
	}

	if p.config.Sign.IncludeResourceAttributes {
		resourceKeys := make([]string, 0, resourceAttrs.Len())
		resourceAttrs.Range(func(k string, v pcommon.Value) bool {
			resourceKeys = append(resourceKeys, k)
			return true
		})
		sort.Strings(resourceKeys)

		for _, k := range resourceKeys {
			v, _ := resourceAttrs.Get(k)
			parts = append(parts, k, v.AsString())
		}
	}

	var buf []byte
	for _, part := range parts {
		buf = append(buf, part...)
		buf = append(buf, '\n')
	}

	return buf, nil
}

func (p *integrityProcessor) signWithLocalSecret(data []byte, algorithm string) (string, error) {
	var h hash.Hash

	if algorithm == "HMAC-SHA512" {
		h = hmac.New(sha512.New, p.localSecret)
	} else {
		h = hmac.New(sha256.New, p.localSecret)
	}

	h.Write(data)
	signature := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature), nil
}
