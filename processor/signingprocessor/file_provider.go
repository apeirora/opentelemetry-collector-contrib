// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
)

type fileKeyMaterialProvider struct {
	reader *CertificateReader
}

func newFileKeyMaterialProvider(cfg *FileKeyConfig) (KeyMaterialProvider, error) {
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %q: %w", cfg.CertFile, err)
	}

	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %q: %w", cfg.KeyFile, err)
	}

	certPEM = decodeIfBase64(certPEM)
	keyPEM = decodeIfBase64(keyPEM)
	certPEM = normalizeLineEndings(certPEM)
	keyPEM = normalizeLineEndings(keyPEM)

	reader, err := parseCertificateData(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &fileKeyMaterialProvider{reader: reader}, nil
}

func (p *fileKeyMaterialProvider) GetPrivateKey() *rsa.PrivateKey {
	return p.reader.GetPrivateKey()
}

func (p *fileKeyMaterialProvider) GetCertificate() *x509.Certificate {
	return p.reader.GetCertificate()
}
