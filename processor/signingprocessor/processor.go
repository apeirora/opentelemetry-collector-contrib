// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

type signingProcessor struct {
	config       *Config
	logger       *zap.Logger
	nextLogs     consumer.Logs
	provider     KeyMaterialProvider
	hashFunc     func() hash.Hash
	jwaAlgorithm string // audit.integrity.algorithm value (e.g. "RS256")
	certRef      string // audit.integrity.certificate value (fingerprint or full DER)
}

func newProcessor(cfg *Config, nextLogs consumer.Logs, settings processor.Settings) (*signingProcessor, error) {
	ctx := context.Background()

	provider, err := newKeyMaterialProvider(ctx, cfg, settings.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key material provider: %w", err)
	}

	var hashFunc func() hash.Hash
	switch cfg.GetHash() {
	case crypto.SHA256:
		hashFunc = func() hash.Hash { return crypto.SHA256.New() }
	case crypto.SHA512:
		hashFunc = func() hash.Hash { return crypto.SHA512.New() }
	default:
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	certRef, err := buildCertificateRef(provider, cfg.CertificateRef)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate reference: %w", err)
	}

	return &signingProcessor{
		config:       cfg,
		logger:       settings.Logger,
		nextLogs:     nextLogs,
		provider:     provider,
		hashFunc:     hashFunc,
		jwaAlgorithm: cfg.GetJWAAlgorithm(),
		certRef:      certRef,
	}, nil
}

func (p *signingProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *signingProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		resourceLog := resourceLogs.At(i)

		// audit.integrity.algorithm and audit.integrity.certificate are Resource-level
		// attributes per the audit logging spec — set once per ResourceLogs block.
		resourceLog.Resource().Attributes().PutStr("audit.integrity.algorithm", p.jwaAlgorithm)
		resourceLog.Resource().Attributes().PutStr("audit.integrity.certificate", p.certRef)

		scopeLogs := resourceLog.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			scopeLog := scopeLogs.At(j)
			logRecords := scopeLog.LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				logRecord := logRecords.At(k)
				if err := p.processLogRecord(logRecord); err != nil {
					return fmt.Errorf("failed to process log record: %w", err)
				}
			}
		}
	}

	return p.nextLogs.ConsumeLogs(ctx, ld)
}

// processLogRecord processes a single log record by computing its hash and signing it.
// It adds three attributes to the log record:
//   - audit.integrity.hash: base64-encoded hash of the serialized log content
//   - audit.integrity.value: base64-encoded RSA signature of the hash
//   - audit.integrity.sign_content: indicates what content was signed (body/meta/attr)
func (p *signingProcessor) processLogRecord(lr plog.LogRecord) error {
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

	privateKey := p.provider.GetPrivateKey()
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, p.config.GetHash(), hashBytes)
	if err != nil {
		return fmt.Errorf("failed to sign hash: %w", err)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	lr.Attributes().PutStr("audit.integrity.hash", hashBase64)
	lr.Attributes().PutStr("audit.integrity.value", signatureBase64)
	lr.Attributes().PutStr("audit.integrity.sign_content", p.config.SignContent)

	return nil
}

// serializeLogRecord serializes the log record to JSON bytes based on the configured sign_content setting.
// Returns the JSON-encoded bytes representing the log record content that will be hashed and signed.
// The content included depends on sign_content: body (body only), meta (body + metadata), or attr (body + metadata + attributes not starting with "audit.integrity.").
func (p *signingProcessor) serializeLogRecord(lr plog.LogRecord) ([]byte, error) {
	data := make(map[string]interface{})

	signContent := p.config.SignContent
	if signContent == "" {
		signContent = defaultSignContent
	}

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
			if !strings.HasPrefix(k, "audit.integrity.") {
				attrs[k] = p.valueToInterface(v)
			}
			return true
		})
		data["attributes"] = attrs
	}

	return p.marshalJSONDeterministic(data)
}

func (p *signingProcessor) marshalJSONDeterministic(v interface{}) ([]byte, error) {
	sorted := p.sortMapKeys(v)
	return json.Marshal(sorted)
}

func (p *signingProcessor) sortMapKeys(v interface{}) interface{} {
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

func (p *signingProcessor) valueToInterface(v pcommon.Value) interface{} {
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

func (p *signingProcessor) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (p *signingProcessor) Shutdown(_ context.Context) error {
	return nil
}

// buildCertificateRef computes the audit.integrity.certificate attribute value.
// "fingerprint" produces "sha256:<hex>" of the DER-encoded certificate.
// "full" produces the base64 (standard, no line wrapping) of the DER-encoded certificate.
func buildCertificateRef(provider KeyMaterialProvider, mode string) (string, error) {
	cert := provider.GetCertificate()
	if cert == nil {
		return "", fmt.Errorf("key material provider returned nil certificate")
	}
	der := cert.Raw
	switch mode {
	case CertificateRefFull:
		return base64.StdEncoding.EncodeToString(der), nil
	default: // CertificateRefFingerprint
		sum := sha256.Sum256(der)
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	}
}
