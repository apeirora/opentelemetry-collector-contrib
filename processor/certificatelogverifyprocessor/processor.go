// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor"

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

const (
	hashAttributeKey        = "otel.log.hash"
	signatureAttributeKey   = "otel.log.signature"
	signContentAttributeKey = "otel.log.sign_content"
)

type certificateHashProcessor struct {
	config   *Config
	logger   *zap.Logger
	nextLogs consumer.Logs
	reader   *CertificateReader
	hashAlgo crypto.Hash
}

func newProcessor(cfg *Config, nextLogs consumer.Logs, settings processor.Settings) (*certificateHashProcessor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := settings.Logger.WithOptions(zap.AddStacktrace(zap.PanicLevel))

	settings.Logger.Info("Initializing certificate reader from Kubernetes secret for verification",
		zap.String("secret", cfg.K8sSecret.Name),
		zap.String("namespace", cfg.K8sSecret.Namespace),
		zap.String("cert_key", cfg.K8sSecret.CertKey),
	)
	reader, err := NewCertificateReaderFromK8sSecretForVerification(ctx, cfg.K8sSecret, logger)
	if err != nil {
		logger.Error("Failed to initialize certificate reader from k8s secret",
			zap.Error(err),
			zap.String("secret", cfg.K8sSecret.Name),
			zap.String("namespace", cfg.K8sSecret.Namespace),
		)
		return nil, fmt.Errorf("failed to initialize certificate reader from k8s secret: %w", err)
	}
	logger.Info("Successfully initialized certificate reader from Kubernetes secret",
		zap.String("secret", cfg.K8sSecret.Name),
		zap.String("namespace", cfg.K8sSecret.Namespace),
	)

	hashAlgo := cfg.GetHash()
	if hashAlgo != crypto.SHA256 && hashAlgo != crypto.SHA512 {
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	return &certificateHashProcessor{
		config:   cfg,
		logger:   logger,
		nextLogs: nextLogs,
		reader:   reader,
		hashAlgo: hashAlgo,
	}, nil
}

func (p *certificateHashProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (p *certificateHashProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	resourceLogs := ld.ResourceLogs()
	resourceLogs.RemoveIf(func(rl plog.ResourceLogs) bool {
		rl.ScopeLogs().RemoveIf(func(sl plog.ScopeLogs) bool {
			sl.LogRecords().RemoveIf(func(lr plog.LogRecord) bool {
				if err := p.verifyLogRecord(lr); err != nil {
					p.logger.Error("Failed to verify log record", zap.Error(err))
					return true
				}
				return false
			})
			return sl.LogRecords().Len() == 0
		})
		return rl.ScopeLogs().Len() == 0
	})

	if ld.LogRecordCount() == 0 {
		return nil
	}

	return p.nextLogs.ConsumeLogs(ctx, ld)
}

func (p *certificateHashProcessor) verifyLogRecord(lr plog.LogRecord) error {
	hashAttr, hashExists := lr.Attributes().Get(hashAttributeKey)
	if !hashExists {
		return fmt.Errorf("missing required attribute: %s", hashAttributeKey)
	}

	signatureAttr, sigExists := lr.Attributes().Get(signatureAttributeKey)
	if !sigExists {
		return fmt.Errorf("missing required attribute: %s", signatureAttributeKey)
	}

	signContentAttr, signContentExists := lr.Attributes().Get(signContentAttributeKey)
	var signContent string
	if signContentExists && signContentAttr.Str() != "" {
		signContent = signContentAttr.Str()
	} else {
		signContent = p.config.SignContent
		if signContent == "" {
			signContent = defaultSignContent
		}
	}

	receivedHashBase64 := hashAttr.Str()
	receivedSignatureBase64 := signatureAttr.Str()

	if receivedHashBase64 == "" {
		return fmt.Errorf("hash attribute is empty")
	}
	if receivedSignatureBase64 == "" {
		return fmt.Errorf("signature attribute is empty")
	}

	receivedHash, err := base64.StdEncoding.DecodeString(receivedHashBase64)
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	receivedSignature, err := base64.StdEncoding.DecodeString(receivedSignatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	logData, err := p.serializeLogRecord(lr, signContent)
	if err != nil {
		return fmt.Errorf("failed to serialize log record: %w", err)
	}

	if len(logData) == 0 {
		return fmt.Errorf("serialized log data is empty (sign_content: %s)", signContent)
	}

	h := p.hashAlgo.New()
	if _, err := h.Write(logData); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}
	computedHash := h.Sum(nil)

	if !equalHashes(computedHash, receivedHash) {
		p.logger.Info("Hash mismatch detected",
			zap.String("algorithm", p.config.HashAlgorithm),
			zap.String("sign_content", signContent),
			zap.String("computed_hash", fmt.Sprintf("%x", computedHash)),
			zap.String("received_hash", fmt.Sprintf("%x", receivedHash)),
		)
		return fmt.Errorf("hash mismatch (algorithm: %s, sign_content: %s): computed %x, received %x",
			p.config.HashAlgorithm, signContent, computedHash, receivedHash)
	}

	if p.reader == nil {
		return fmt.Errorf("certificate reader is nil")
	}

	cert := p.reader.GetCertificate()
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}

	err = rsa.VerifyPKCS1v15(publicKey, p.hashAlgo, computedHash, receivedSignature)
	if err != nil {
		return fmt.Errorf("signature verification failed (algorithm: %s): %w", p.config.HashAlgorithm, err)
	}

	p.logger.Info("Log record verification successful",
		zap.String("sign_content", signContent),
	)

	return nil
}

func (p *certificateHashProcessor) serializeLogRecord(lr plog.LogRecord, signContent string) ([]byte, error) {
	data := make(map[string]interface{})

	if signContent == SignContentBody || signContent == SignContentMeta || signContent == SignContentAttr {
		if lr.Body().Type() == pcommon.ValueTypeStr {
			data["body"] = lr.Body().Str()
		}
	}

	if signContent == SignContentMeta || signContent == SignContentAttr {
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
	}

	if signContent == SignContentAttr {
		attrs := make(map[string]interface{})
		lr.Attributes().Range(func(k string, v pcommon.Value) bool {
			if !strings.HasPrefix(k, "otel.log.") {
				attrs[k] = p.valueToInterface(v)
			}
			return true
		})
		data["attributes"] = attrs
	}

	return p.marshalJSONDeterministic(data)
}

func (p *certificateHashProcessor) marshalJSONDeterministic(v interface{}) ([]byte, error) {
	sorted := p.sortMapKeys(v)
	return json.Marshal(sorted)
}

func (p *certificateHashProcessor) sortMapKeys(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		sorted := make(map[string]interface{})
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sorted[k] = p.sortMapKeys(val[k])
		}
		return sorted
	case []interface{}:
		sorted := make([]interface{}, len(val))
		for i, item := range val {
			sorted[i] = p.sortMapKeys(item)
		}
		return sorted
	default:
		return val
	}
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

func equalHashes(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func (p *certificateHashProcessor) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *certificateHashProcessor) Shutdown(_ context.Context) error {
	return nil
}
