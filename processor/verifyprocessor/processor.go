// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package verifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/verifyprocessor"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

const (
	jsonMaxDepth      = 128
	jsonMaxInputBytes = 1 << 21 // 2 MiB
	// maxFailureDetails caps how many record[r,s,i] indexes appear in a
	// permanent verification error; remaining failures are summarized as
	// "and N more" so large batches cannot inflate the error string.
	maxFailureDetails = 8

	attrIntegrityValue       = "audit.integrity.value"
	attrIntegrityAlgorithm   = "audit.integrity.algorithm"
	attrIntegrityCertificate = "audit.integrity.certificate"
	attrIntegrityPrefix      = "audit.integrity."
	attrRecordID             = "audit.record.id"

	attrVerificationStatus  = "audit.verification.status"
	attrVerificationReason  = "audit.verification.reason"
	attrVerificationProfile = "audit.verification.profile"

	statusVerified = "verified"
	statusFailed   = "failed"

	reasonMissingIntegrityValue = "missing_integrity_value"
	reasonMissingAlgorithm      = "missing_algorithm"
	reasonUnsupportedAlgorithm  = "unsupported_algorithm"
	reasonCertificateMismatch   = "certificate_mismatch"
	reasonMissingCertificate    = "missing_certificate"
	reasonInvalidSignature      = "invalid_signature_encoding"
	reasonIntegrityMismatch     = "integrity_mismatch"
	reasonSerializationError    = "serialization_error"
	reasonKeyMaterialMismatch   = "key_material_mismatch"

	algorithmRS256      = "RS256"
	algorithmRS512      = "RS512"
	algorithmES256      = "ES256"
	algorithmEdDSA      = "EdDSA"
	algorithmHMACSHA256 = "HMAC-SHA256"
)

type verifyFailure struct {
	reason string
	err    error
}

func (f *verifyFailure) Error() string {
	if f.err != nil {
		return fmt.Sprintf("%s: %v", f.reason, f.err)
	}
	return f.reason
}

type logFailure struct {
	logID    string
	resource int
	scope    int
	record   int
}

type verificationBatchError struct {
	failures []logFailure
}

func (e *verificationBatchError) Error() string {
	n := len(e.failures)
	shown := n
	if shown > maxFailureDetails {
		shown = maxFailureDetails
	}
	parts := make([]string, 0, shown+1)
	parts = append(parts, fmt.Sprintf("verification failed for %d log record(s)", n))
	for i := 0; i < shown; i++ {
		parts = append(parts, e.failures[i].String())
	}
	if n > shown {
		parts = append(parts, fmt.Sprintf("and %d more", n-shown))
	}
	return strings.Join(parts, "; ")
}

func (f logFailure) String() string {
	if f.logID != "" {
		return fmt.Sprintf("id=%s", f.logID)
	}
	return fmt.Sprintf("record[%d,%d,%d]", f.resource, f.scope, f.record)
}

func recordLogID(lr plog.LogRecord) string {
	if v, ok := lr.Attributes().Get(attrRecordID); ok {
		return v.Str()
	}
	return ""
}

type verifyProcessor struct {
	config       *Config
	logger       *zap.Logger
	nextConsumer consumer.Logs
	provider     KeyMaterialProvider
}

func newProcessor(ctx context.Context, cfg *Config, nextConsumer consumer.Logs, settings processor.Settings) (*verifyProcessor, error) {
	provider, err := newKeyMaterialProvider(ctx, cfg, settings.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key material provider: %w", err)
	}

	if cfg.DeadLetter.Enabled {
		settings.Logger.Warn("dead_letter.enabled is set but dead-letter persistence is not yet implemented; verification failures will not be written to storage")
	}

	return &verifyProcessor{
		config:       cfg,
		logger:       settings.Logger,
		nextConsumer: nextConsumer,
		provider:     provider,
	}, nil
}

func (*verifyProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (*verifyProcessor) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (*verifyProcessor) Shutdown(_ context.Context) error {
	return nil
}

func (p *verifyProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	resourceLogs := ld.ResourceLogs()
	var failures []logFailure

	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		resAttrs := rl.Resource().Attributes()

		algorithm := ""
		if algoVal, hasAlgo := resAttrs.Get(attrIntegrityAlgorithm); hasAlgo {
			algorithm = algoVal.Str()
		}
		certRef := ""
		if v, ok := resAttrs.Get(attrIntegrityCertificate); ok {
			certRef = v.Str()
		}

		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			records := scopeLogs.At(j).LogRecords()
			recordIdx := 0
			records.RemoveIf(func(lr plog.LogRecord) bool {
				idx := recordIdx
				recordIdx++

				fail := p.verifyLogRecord(lr, algorithm, certRef)
				if fail == nil {
					p.stampSuccess(lr)
					return false
				}

				p.logger.Debug("log record verification failed",
					zap.String("reason", fail.reason),
					zap.Error(fail.err),
				)

				switch p.config.FailureMode {
				case failureModeMark:
					p.stampFailure(lr, fail.reason)
					return false
				case failureModeDrop:
					failures = append(failures, logFailure{
						logID:    recordLogID(lr),
						resource: i,
						scope:    j,
						record:   idx,
					})
					return true
				default:
					failures = append(failures, logFailure{
						logID:    recordLogID(lr),
						resource: i,
						scope:    j,
						record:   idx,
					})
					return false
				}
			})
		}
	}

	if p.config.FailureMode == failureModeStrict && len(failures) > 0 {
		return consumererror.NewPermanent(&verificationBatchError{failures: failures})
	}

	if err := p.nextConsumer.ConsumeLogs(ctx, ld); err != nil {
		return err
	}
	if len(failures) > 0 {
		return consumererror.NewPermanent(&verificationBatchError{failures: failures})
	}
	return nil
}

func (p *verifyProcessor) verifyLogRecord(lr plog.LogRecord, algorithm, certRef string) *verifyFailure {
	sigVal, ok := lr.Attributes().Get(attrIntegrityValue)
	if !ok || sigVal.Str() == "" {
		return &verifyFailure{reason: reasonMissingIntegrityValue}
	}

	if algorithm == "" {
		return &verifyFailure{reason: reasonMissingAlgorithm}
	}

	switch algorithm {
	case algorithmRS256, algorithmRS512, algorithmES256, algorithmEdDSA:
		if p.provider.GetCertificate() == nil {
			return &verifyFailure{reason: reasonKeyMaterialMismatch, err: errors.New("asymmetric algorithm requires a configured certificate")}
		}
		if certRef == "" {
			return &verifyFailure{reason: reasonMissingCertificate}
		}
		if !certificateRefMatches(p.provider.GetCertificate(), certRef) {
			return &verifyFailure{reason: reasonCertificateMismatch}
		}
		if err := certificateMatchesAlgorithm(p.provider.GetCertificate(), algorithm); err != nil {
			return &verifyFailure{reason: reasonKeyMaterialMismatch, err: err}
		}
	case algorithmHMACSHA256:
		if len(p.provider.GetHMACKey()) == 0 {
			return &verifyFailure{reason: reasonKeyMaterialMismatch, err: errors.New("HMAC-SHA256 requires a configured hmac_key")}
		}
	default:
		return &verifyFailure{reason: reasonUnsupportedAlgorithm, err: fmt.Errorf("algorithm %q", algorithm)}
	}

	payload, err := p.serializeLogRecord(lr)
	if err != nil {
		return &verifyFailure{reason: reasonSerializationError, err: err}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigVal.Str())
	if err != nil {
		return &verifyFailure{reason: reasonInvalidSignature, err: err}
	}

	if err := p.verifySignature(algorithm, payload, sigBytes); err != nil {
		return &verifyFailure{reason: reasonIntegrityMismatch, err: err}
	}
	return nil
}

func (p *verifyProcessor) verifySignature(algorithm string, payload, sig []byte) error {
	switch algorithm {
	case algorithmRS256:
		pub, ok := p.provider.GetCertificate().PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS256 requires an RSA certificate public key")
		}
		sum := sha256.Sum256(payload)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)

	case algorithmRS512:
		pub, ok := p.provider.GetCertificate().PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS512 requires an RSA certificate public key")
		}
		sum := crypto.SHA512.New()
		if _, err := sum.Write(payload); err != nil {
			return err
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA512, sum.Sum(nil), sig)

	case algorithmES256:
		pub, ok := p.provider.GetCertificate().PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ES256 requires an ECDSA certificate public key")
		}
		sum := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	case algorithmEdDSA:
		pub, ok := p.provider.GetCertificate().PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("EdDSA requires an Ed25519 certificate public key")
		}
		if !ed25519.Verify(pub, payload, sig) {
			return errors.New("Ed25519 signature verification failed")
		}
		return nil

	case algorithmHMACSHA256:
		mac := hmac.New(sha256.New, p.provider.GetHMACKey())
		if _, err := mac.Write(payload); err != nil {
			return err
		}
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("HMAC verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func certificateRefMatches(cert *x509.Certificate, ref string) bool {
	if cert == nil {
		return false
	}
	fingerprint := "sha256:" + hex.EncodeToString(sha256Sum(cert.Raw))
	if ref == fingerprint {
		return true
	}
	full := base64.StdEncoding.EncodeToString(cert.Raw)
	return ref == full
}

func certificateMatchesAlgorithm(cert *x509.Certificate, algorithm string) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}
	switch algorithm {
	case algorithmRS256, algorithmRS512:
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("%s requires an RSA certificate public key", algorithm)
		}
	case algorithmES256:
		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return errors.New("ES256 requires an ECDSA certificate public key")
		}
	case algorithmEdDSA:
		if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
			return errors.New("EdDSA requires an Ed25519 certificate public key")
		}
	}
	return nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func (p *verifyProcessor) stampSuccess(lr plog.LogRecord) {
	lr.Attributes().PutStr(attrVerificationStatus, statusVerified)
	lr.Attributes().PutStr(attrVerificationProfile, p.config.VerificationProfile)
	lr.Attributes().Remove(attrVerificationReason)
}

func (p *verifyProcessor) stampFailure(lr plog.LogRecord, reason string) {
	lr.Attributes().PutStr(attrVerificationStatus, statusFailed)
	lr.Attributes().PutStr(attrVerificationReason, reason)
	lr.Attributes().PutStr(attrVerificationProfile, p.config.VerificationProfile)
}

func (p *verifyProcessor) serializeLogRecord(lr plog.LogRecord) ([]byte, error) {
	data := make(map[string]any)

	if lr.EventName() != "" {
		if err := checkUTF8(lr.EventName(), "event name"); err != nil {
			return nil, err
		}
		data["event_name"] = lr.EventName()
	}

	if lr.Body().Type() != pcommon.ValueTypeEmpty {
		body, err := p.valueToInterface(lr.Body(), 0)
		if err != nil {
			return nil, fmt.Errorf("log record body: %w", err)
		}
		data["body"] = body
	}

	if lr.Timestamp() != 0 {
		data["timestamp"] = strconv.FormatInt(lr.Timestamp().AsTime().UnixNano(), 10)
	}

	if lr.ObservedTimestamp() != 0 {
		data["observed_timestamp"] = strconv.FormatInt(lr.ObservedTimestamp().AsTime().UnixNano(), 10)
	}

	if !lr.TraceID().IsEmpty() {
		data["trace_id"] = lr.TraceID().String()
	}

	if !lr.SpanID().IsEmpty() {
		data["span_id"] = lr.SpanID().String()
	}

	attrs := make(map[string]any)
	var attrErr error
	lr.Attributes().Range(func(k string, v pcommon.Value) bool {
		if strings.HasPrefix(k, attrIntegrityPrefix) {
			return true
		}
		if strings.HasPrefix(k, "audit.verification.") {
			return true
		}
		if err := checkUTF8(k, "attribute key"); err != nil {
			attrErr = err
			return false
		}
		val, err := p.valueToInterface(v, 0)
		if err != nil {
			attrErr = err
			return false
		}
		attrs[k] = val
		return true
	})
	if attrErr != nil {
		return nil, attrErr
	}
	if len(attrs) > 0 {
		data["attributes"] = attrs
	}

	return p.marshalJCS(data)
}

func (*verifyProcessor) marshalJCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw) > jsonMaxInputBytes {
		return nil, fmt.Errorf("serialized log record exceeds size limit (%d > %d bytes)", len(raw), jsonMaxInputBytes)
	}
	return jcs.Transform(raw)
}

func (p *verifyProcessor) valueToInterface(v pcommon.Value, depth int) (any, error) {
	if depth > jsonMaxDepth {
		return nil, fmt.Errorf("value exceeds nesting depth limit (%d)", jsonMaxDepth)
	}
	switch v.Type() {
	case pcommon.ValueTypeStr:
		s := v.Str()
		if err := checkUTF8(s, "string value"); err != nil {
			return nil, err
		}
		return map[string]any{"stringValue": s}, nil
	case pcommon.ValueTypeInt:
		return map[string]any{"intValue": strconv.FormatInt(v.Int(), 10)}, nil
	case pcommon.ValueTypeDouble:
		return map[string]any{"doubleValue": v.Double()}, nil
	case pcommon.ValueTypeBool:
		return map[string]any{"boolValue": v.Bool()}, nil
	case pcommon.ValueTypeBytes:
		return map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(v.Bytes().AsRaw())}, nil
	case pcommon.ValueTypeSlice:
		slice := make([]any, v.Slice().Len())
		for i := 0; i < v.Slice().Len(); i++ {
			val, err := p.valueToInterface(v.Slice().At(i), depth+1)
			if err != nil {
				return nil, err
			}
			slice[i] = val
		}
		return slice, nil
	case pcommon.ValueTypeMap:
		m := make(map[string]any)
		var mapErr error
		v.Map().Range(func(k string, val pcommon.Value) bool {
			if err := checkUTF8(k, "map key"); err != nil {
				mapErr = err
				return false
			}
			converted, err := p.valueToInterface(val, depth+1)
			if err != nil {
				mapErr = err
				return false
			}
			m[k] = converted
			return true
		})
		if mapErr != nil {
			return nil, mapErr
		}
		return m, nil
	default:
		return nil, nil
	}
}

func checkUTF8(s, what string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s contains invalid UTF-8", what)
	}
	return nil
}
