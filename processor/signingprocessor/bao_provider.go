// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	openbao "github.com/openbao/openbao/api/v2"
)

type baoKeyMaterialProvider struct {
	reader *CertificateReader
}

// newBaoKeyMaterialProvider reads a PEM certificate and private key from an
// OpenBao (or Vault-compatible) KV secret. The secret at cfg.SecretPath must
// contain the keys named by cfg.CertField and cfg.KeyField whose values are
// PEM-encoded strings.
//
// Authentication is handled entirely by the OpenBao client via the standard
// environment variables (BAO_ADDR, BAO_TOKEN, BAO_ROLE_ID, …) or the explicit
// Token field in BaoKeyConfig.
func newBaoKeyMaterialProvider(ctx context.Context, cfg *BaoKeyConfig) (KeyMaterialProvider, error) {
	clientCfg := openbao.DefaultConfig()
	if cfg.Address != "" {
		clientCfg.Address = cfg.Address
	}

	client, err := openbao.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create openbao client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	secret, err := client.Logical().ReadWithContext(ctx, cfg.SecretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret at %q: %w", cfg.SecretPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret at %q is empty or does not exist", cfg.SecretPath)
	}

	certPEM, err := secretField(secret.Data, cfg.CertField)
	if err != nil {
		return nil, fmt.Errorf("certificate field %q in secret %q: %w", cfg.CertField, cfg.SecretPath, err)
	}

	keyPEM, err := secretField(secret.Data, cfg.KeyField)
	if err != nil {
		return nil, fmt.Errorf("key field %q in secret %q: %w", cfg.KeyField, cfg.SecretPath, err)
	}

	certBytes := decodeIfBase64([]byte(certPEM))
	keyBytes := decodeIfBase64([]byte(keyPEM))
	certBytes = normalizeLineEndings(certBytes)
	keyBytes = normalizeLineEndings(keyBytes)

	reader, err := parseCertificateData(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	return &baoKeyMaterialProvider{reader: reader}, nil
}

func (p *baoKeyMaterialProvider) GetPrivateKey() *rsa.PrivateKey {
	return p.reader.GetPrivateKey()
}

func (p *baoKeyMaterialProvider) GetCertificate() *x509.Certificate {
	return p.reader.GetCertificate()
}

func secretField(data map[string]interface{}, field string) (string, error) {
	raw, ok := data[field]
	if !ok {
		return "", fmt.Errorf("field not found in secret data")
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("field value is not a string")
	}
	if s == "" {
		return "", fmt.Errorf("field value is empty")
	}
	return s, nil
}
