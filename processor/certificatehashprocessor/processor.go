// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatehashprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatehashprocessor"

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

type certificateHashProcessor struct {
	config   *Config
	logger   *zap.Logger
	nextLogs consumer.Logs
	reader   *CertificateReader
	hashFunc func() hash.Hash
}

func newProcessor(cfg *Config, nextLogs consumer.Logs, settings processor.Settings) (*certificateHashProcessor, error) {
	ctx := context.Background()
	reader, err := NewCertificateReaderFromK8sSecret(ctx, cfg.K8sSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate reader from k8s secret: %w", err)
	}
	settings.Logger.Info("Using Kubernetes secret for certificates",
		zap.String("secret", cfg.K8sSecret.Name),
		zap.String("namespace", cfg.K8sSecret.Namespace),
	)

	var hashFunc func() hash.Hash
	switch cfg.GetHash() {
	case crypto.SHA256:
		hashFunc = func() hash.Hash {
			return crypto.SHA256.New()
		}
	case crypto.SHA512:
		hashFunc = func() hash.Hash {
			return crypto.SHA512.New()
		}
	default:
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	return &certificateHashProcessor{
		config:   cfg,
		logger:   settings.Logger,
		nextLogs: nextLogs,
		reader:   reader,
		hashFunc: hashFunc,
	}, nil
}

func (p *certificateHashProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *certificateHashProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		resourceLog := resourceLogs.At(i)
		scopeLogs := resourceLog.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			scopeLog := scopeLogs.At(j)
			logRecords := scopeLog.LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				logRecord := logRecords.At(k)
				if err := p.processLogRecord(logRecord); err != nil {
					p.logger.Error("Failed to process log record", zap.Error(err))
					continue
				}
			}
		}
	}

	return p.nextLogs.ConsumeLogs(ctx, ld)
}

func (p *certificateHashProcessor) processLogRecord(lr plog.LogRecord) error {
	logData, err := p.serializeLogRecord(lr)
	if err != nil {
		return fmt.Errorf("failed to serialize log record: %w", err)
	}

	h := p.hashFunc()
	if _, err := h.Write(logData); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}
	hashBytes := h.Sum(nil)
	hashBase64 := base64.StdEncoding.EncodeToString(hashBytes)

	privateKey := p.reader.GetPrivateKey()
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, p.config.GetHash(), hashBytes)
	if err != nil {
		return fmt.Errorf("failed to sign hash: %w", err)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	lr.Attributes().PutStr("otel.certificate.hash", hashBase64)
	lr.Attributes().PutStr("otel.certificate.signature", signatureBase64)

	return nil
}

func (p *certificateHashProcessor) serializeLogRecord(lr plog.LogRecord) ([]byte, error) {
	data := make(map[string]interface{})

	if lr.Body().Type() == pcommon.ValueTypeStr {
		data["body"] = lr.Body().Str()
	}

	attrs := make(map[string]interface{})
	lr.Attributes().Range(func(k string, v pcommon.Value) bool {
		attrs[k] = p.valueToInterface(v)
		return true
	})
	data["attributes"] = attrs

	if lr.Timestamp() != 0 {
		data["timestamp"] = lr.Timestamp().AsTime().UnixNano()
	}

	if lr.SeverityNumber() != 0 {
		data["severity_number"] = lr.SeverityNumber()
	}

	if lr.SeverityText() != "" {
		data["severity_text"] = lr.SeverityText()
	}

	if !lr.TraceID().IsEmpty() {
		data["trace_id"] = lr.TraceID().String()
	}

	if !lr.SpanID().IsEmpty() {
		data["span_id"] = lr.SpanID().String()
	}

	return json.Marshal(data)
}

func (p *certificateHashProcessor) valueToInterface(v pcommon.Value) interface{} {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return v.Str()
	case pcommon.ValueTypeInt:
		return v.Int()
	case pcommon.ValueTypeDouble:
		return v.Double()
	case pcommon.ValueTypeBool:
		return v.Bool()
	case pcommon.ValueTypeBytes:
		return base64.StdEncoding.EncodeToString(v.Bytes().AsRaw())
	case pcommon.ValueTypeSlice:
		slice := make([]interface{}, v.Slice().Len())
		for i := 0; i < v.Slice().Len(); i++ {
			slice[i] = p.valueToInterface(v.Slice().At(i))
		}
		return slice
	case pcommon.ValueTypeMap:
		m := make(map[string]interface{})
		v.Map().Range(func(k string, val pcommon.Value) bool {
			m[k] = p.valueToInterface(val)
			return true
		})
		return m
	default:
		return nil
	}
}

func (p *certificateHashProcessor) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *certificateHashProcessor) Shutdown(_ context.Context) error {
	return nil
}
