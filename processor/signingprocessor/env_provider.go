// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
)

type envKeyMaterialProvider struct {
	reader *CertificateReader
}

func newEnvKeyMaterialProvider(cfg *EnvKeyConfig) (KeyMaterialProvider, error) {
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

func (p *envKeyMaterialProvider) GetPrivateKey() *rsa.PrivateKey {
	return p.reader.GetPrivateKey()
}

func (p *envKeyMaterialProvider) GetCertificate() *x509.Certificate {
	return p.reader.GetCertificate()
}
