// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
)

type envKeyMaterialProvider struct {
	reader  *certificateReader
	hmacKey []byte
}

func newEnvKeyMaterialProvider(cfg *EnvKeyConfig) (KeyMaterialProvider, error) {
	// HMAC mode: load only the symmetric key
	if cfg.HMACKeyEnvVar != "" {
		raw := os.Getenv(cfg.HMACKeyEnvVar)
		if raw == "" {
			return nil, fmt.Errorf("environment variable %q is not set or empty", cfg.HMACKeyEnvVar)
		}
		key := decodeIfBase64(normalizeLineEndings([]byte(raw)))
		return &envKeyMaterialProvider{hmacKey: key}, nil
	}

	// Asymmetric mode: load cert + private key
	certPEM := []byte(os.Getenv(cfg.CertEnvVar))
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("environment variable %q is not set or empty", cfg.CertEnvVar)
	}
	keyPEM := []byte(os.Getenv(cfg.KeyEnvVar))
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("environment variable %q is not set or empty", cfg.KeyEnvVar)
	}
	certPEM = decodeIfBase64(certPEM)
	keyPEM = decodeIfBase64(keyPEM)
	certPEM = normalizeLineEndings(certPEM)
	keyPEM = normalizeLineEndings(keyPEM)
	reader, err := parseCertificateData(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &envKeyMaterialProvider{reader: reader}, nil
}

func (p *envKeyMaterialProvider) GetPrivateKey() crypto.Signer {
	if p.reader == nil {
		return nil
	}
	return p.reader.GetPrivateKey()
}

func (p *envKeyMaterialProvider) GetCertificate() *x509.Certificate {
	if p.reader == nil {
		return nil
	}
	return p.reader.GetCertificate()
}

func (p *envKeyMaterialProvider) GetHMACKey() []byte { return p.hmacKey }
