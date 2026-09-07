// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
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
	defaultK8sTimeout              = 30 * time.Second
	auditIntegrityAlgorithmKey     = "audit.integrity.algorithm"
	algoHMACSHA256                 = "HMAC-SHA256"
	algoHMACSHA512                 = "HMAC-SHA512"
	algoECDSAP256SHA256            = "ECDSA-P256-SHA256"
	algoRSAPKCS1SHA256             = "RSA-PKCS1-SHA256"
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

func (p *certificateHashProcessor) verifyAuditLogRecord(resource pcommon.Resource, lr plog.LogRecord) (string, error) {
	integrityValue := strings.TrimSpace(attrString(lr, auditAttrIntegrityVal))
	if integrityValue == "" {
		return "missing_integrity_value", fmt.Errorf("missing required attribute: %s", auditAttrIntegrityVal)
	}

	algorithm := strings.TrimSpace(resourceAttrString(resource, auditIntegrityAlgorithmKey))
	if algorithm == "" {
		return "missing_integrity_algorithm", fmt.Errorf("missing required resource attribute: %s", auditIntegrityAlgorithmKey)
	}

	canonical, err := jcsCanonicalAuditRecord(lr)
	if err != nil {
		return "canonicalization_failed", fmt.Errorf("failed to canonicalize audit record: %w", err)
	}
	if len(canonical) == 0 {
		return "canonical_payload_empty", errors.New("canonical audit record payload is empty")
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

	p.logger.Info("Audit log record verification successful")
	return reasonOK, nil
}

func (p *certificateHashProcessor) verifyIntegrityProof(algorithm string, canonical []byte, integrityValue string) (string, error) {
	switch strings.ToUpper(algorithm) {
	case algoHMACSHA256:
		return p.verifyHMACProof(crypto.SHA256, canonical, integrityValue)
	case algoHMACSHA512:
		return p.verifyHMACProof(crypto.SHA512, canonical, integrityValue)
	case algoECDSAP256SHA256:
		return p.verifySignatureProof(crypto.SHA256, canonical, integrityValue)
	case algoRSAPKCS1SHA256:
		return p.verifySignatureProof(crypto.SHA256, canonical, integrityValue)
	default:
		return "unsupported_integrity_algorithm", fmt.Errorf("unsupported audit.integrity.algorithm %q", algorithm)
	}
}

func (p *certificateHashProcessor) verifyHMACProof(hashAlg crypto.Hash, canonical []byte, integrityValue string) (string, error) {
	if len(p.hmacKey) == 0 {
		return "hmac_key_unavailable", fmt.Errorf("hmac key is not configured")
	}

	received, err := decodeHexOrBase64(integrityValue)
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

func (p *certificateHashProcessor) verifySignatureProof(hashAlg crypto.Hash, canonical []byte, integrityValue string) (string, error) {
	if p.cert == nil {
		return "certificate_unavailable", fmt.Errorf("certificate is not configured")
	}

	receivedSig, err := decodeHexOrBase64(integrityValue)
	if err != nil {
		return "invalid_integrity_encoding", fmt.Errorf("failed to decode audit.integrity.value: %w", err)
	}

	hasher := hashAlg.New()
	if _, err := hasher.Write(canonical); err != nil {
		return "hash_compute_failed", fmt.Errorf("failed to compute content hash: %w", err)
	}
	digest := hasher.Sum(nil)

	if err := verifyCertificateSignature(p.cert, hashAlg, digest, receivedSig); err != nil {
		return "integrity_mismatch", err
	}
	return reasonOK, nil
}

func verifyCertificateSignature(cert *x509.Certificate, hashAlg crypto.Hash, digest, signature []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return errors.New("ecdsa signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, signature); err != nil {
			return fmt.Errorf("rsa signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
	}
}

func decodeHexOrBase64(value string) ([]byte, error) {
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
