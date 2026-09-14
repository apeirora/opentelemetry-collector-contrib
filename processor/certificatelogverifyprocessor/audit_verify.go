// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	defaultK8sTimeout = 30 * time.Second

	auditIntegrityAlgorithmKey   = "audit.integrity.algorithm"
	auditIntegrityCertificateKey = "audit.integrity.certificate"

	algoRS256      = "RS256"
	algoRS512      = "RS512"
	algoES256      = "ES256"
	algoEdDSA      = "EdDSA"
	algoHMACSHA256 = "HMAC-SHA256"
)

func loadHMACKey(cfg *Config) ([]byte, error) {
	if cfg.HmacKeyFile != "" {
		data, err := os.ReadFile(cfg.HmacKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read hmac_key_file %q: %w", cfg.HmacKeyFile, err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return nil, fmt.Errorf("hmac_key_file %q is empty", cfg.HmacKeyFile)
		}
		return []byte(key), nil
	}

	if cfg.K8sSecret == nil {
		return nil, fmt.Errorf("hmac key source not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultK8sTimeout)
	defer cancel()

	data, err := fetchSecretData(ctx, cfg.K8sSecret.Name, cfg.K8sSecret.Namespace, cfg.K8sSecret.HMACKeyEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load hmac key from k8s secret: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return nil, fmt.Errorf("hmac key in k8s secret is empty")
	}
	return []byte(key), nil
}

func (p *verifyProcessor) verifyAuditLogRecord(resource pcommon.Resource, lr plog.LogRecord) (string, error) {
	integrityValue := strings.TrimSpace(attrString(lr, auditAttrIntegrityVal))
	if integrityValue == "" {
		return "missing_integrity_value", fmt.Errorf("missing required attribute: %s", auditAttrIntegrityVal)
	}

	algorithm := strings.TrimSpace(resourceAttrString(resource, auditIntegrityAlgorithmKey))
	if algorithm == "" {
		return "missing_integrity_algorithm", fmt.Errorf("missing required resource attribute: %s", auditIntegrityAlgorithmKey)
	}

	canonical, err := serializeLogRecord(lr)
	if err != nil {
		return "canonicalization_failed", fmt.Errorf("failed to canonicalize audit record: %w", err)
	}
	if len(canonical) == 0 {
		return "canonical_payload_empty", errors.New("canonical audit record payload is empty")
	}

	if reason, err := p.validateCertificateRef(resource, algorithm); err != nil {
		return reason, err
	}

	if reason, err := p.verifyIntegrityProof(algorithm, canonical, integrityValue); err != nil {
		return reason, err
	}

	if p.hashChain != nil {
		streamID := streamIDFromRecord(resource, lr)
		if reason, err := p.hashChain.validate(streamID, lr); err != nil {
			return reason, err
		}
	}

	p.logger.Debug("Audit log record verification successful")
	return reasonOK, nil
}

func (p *verifyProcessor) validateCertificateRef(resource pcommon.Resource, algorithm string) (string, error) {
	switch strings.ToUpper(algorithm) {
	case algoHMACSHA256:
		return reasonOK, nil
	case algoRS256, algoRS512, algoES256, algoEdDSA:
	default:
		return reasonOK, nil
	}

	if p.cert == nil {
		return "certificate_unavailable", fmt.Errorf("certificate is not configured")
	}

	ref := strings.TrimSpace(resourceAttrString(resource, auditIntegrityCertificateKey))
	if ref == "" {
		return reasonOK, nil
	}

	sum := sha256.Sum256(p.cert.Raw)
	expectedFingerprint := "sha256:" + hex.EncodeToString(sum[:])
	expectedFull := base64.StdEncoding.EncodeToString(p.cert.Raw)

	if strings.HasPrefix(strings.ToLower(ref), "sha256:") {
		if !strings.EqualFold(ref, expectedFingerprint) {
			return "certificate_ref_mismatch", fmt.Errorf("audit.integrity.certificate fingerprint does not match configured certificate")
		}
		return reasonOK, nil
	}

	if ref != expectedFull {
		return "certificate_ref_mismatch", fmt.Errorf("audit.integrity.certificate does not match configured certificate")
	}
	return reasonOK, nil
}

func (p *verifyProcessor) verifyIntegrityProof(algorithm string, canonical []byte, integrityValue string) (string, error) {
	switch strings.ToUpper(algorithm) {
	case algoHMACSHA256:
		return p.verifyHMACProof(crypto.SHA256, canonical, integrityValue)
	case algoRS256:
		return p.verifyRSAProof(crypto.SHA256, canonical, integrityValue)
	case algoRS512:
		return p.verifyRSAProof(crypto.SHA512, canonical, integrityValue)
	case algoES256:
		return p.verifyECDSAProof(crypto.SHA256, canonical, integrityValue)
	case algoEdDSA:
		return p.verifyEdDSAProof(canonical, integrityValue)
	default:
		return "unsupported_integrity_algorithm", fmt.Errorf("unsupported audit.integrity.algorithm %q", algorithm)
	}
}

func (p *verifyProcessor) verifyHMACProof(hashAlg crypto.Hash, canonical []byte, integrityValue string) (string, error) {
	if len(p.hmacKey) == 0 {
		return "hmac_key_unavailable", fmt.Errorf("hmac key is not configured")
	}

	received, err := decodeIntegrityValue(integrityValue)
	if err != nil {
		return "invalid_integrity_encoding", fmt.Errorf("failed to decode audit.integrity.value: %w", err)
	}

	mac := hmac.New(hashAlg.New, p.hmacKey)
	if _, err := mac.Write(canonical); err != nil {
		return "hmac_compute_failed", fmt.Errorf("failed to compute hmac: %w", err)
	}
	if !hmac.Equal(mac.Sum(nil), received) {
		return "integrity_mismatch", errors.New("audit.integrity.value mismatch")
	}
	return reasonOK, nil
}

func (p *verifyProcessor) verifyRSAProof(hashAlg crypto.Hash, canonical []byte, integrityValue string) (string, error) {
	if p.cert == nil {
		return "certificate_unavailable", fmt.Errorf("certificate is not configured")
	}
	pub, ok := p.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "certificate_key_mismatch", fmt.Errorf("configured certificate is not an RSA certificate")
	}

	receivedSig, err := decodeIntegrityValue(integrityValue)
	if err != nil {
		return "invalid_integrity_encoding", fmt.Errorf("failed to decode audit.integrity.value: %w", err)
	}

	hasher := hashAlg.New()
	if _, err := hasher.Write(canonical); err != nil {
		return "hash_compute_failed", fmt.Errorf("failed to compute content hash: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, hashAlg, hasher.Sum(nil), receivedSig); err != nil {
		return "integrity_mismatch", fmt.Errorf("rsa signature verification failed: %w", err)
	}
	return reasonOK, nil
}

func (p *verifyProcessor) verifyECDSAProof(hashAlg crypto.Hash, canonical []byte, integrityValue string) (string, error) {
	if p.cert == nil {
		return "certificate_unavailable", fmt.Errorf("certificate is not configured")
	}
	pub, ok := p.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "certificate_key_mismatch", fmt.Errorf("configured certificate is not an ECDSA certificate")
	}

	receivedSig, err := decodeIntegrityValue(integrityValue)
	if err != nil {
		return "invalid_integrity_encoding", fmt.Errorf("failed to decode audit.integrity.value: %w", err)
	}

	hasher := hashAlg.New()
	if _, err := hasher.Write(canonical); err != nil {
		return "hash_compute_failed", fmt.Errorf("failed to compute content hash: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, hasher.Sum(nil), receivedSig) {
		return "integrity_mismatch", errors.New("ecdsa signature verification failed")
	}
	return reasonOK, nil
}

func (p *verifyProcessor) verifyEdDSAProof(canonical []byte, integrityValue string) (string, error) {
	if p.cert == nil {
		return "certificate_unavailable", fmt.Errorf("certificate is not configured")
	}
	pub, ok := p.cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "certificate_key_mismatch", fmt.Errorf("configured certificate is not an Ed25519 certificate")
	}

	receivedSig, err := decodeIntegrityValue(integrityValue)
	if err != nil {
		return "invalid_integrity_encoding", fmt.Errorf("failed to decode audit.integrity.value: %w", err)
	}

	if !ed25519.Verify(pub, canonical, receivedSig) {
		return "integrity_mismatch", errors.New("eddsa signature verification failed")
	}
	return reasonOK, nil
}

func decodeIntegrityValue(value string) ([]byte, error) {
	if isUnambiguousHex(value) {
		return hex.DecodeString(value)
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("value is neither valid base64 nor hex")
}

func isUnambiguousHex(value string) bool {
	if len(value) == 0 || len(value)%2 != 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
