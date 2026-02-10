// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatehashprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatehashprocessor"

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CertificateReader struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func NewCertificateReader(certPath, keyPath string) (*CertificateReader, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key")
	}

	var key *rsa.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	} else if keyBlock.Type == "PRIVATE KEY" {
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	} else {
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	return &CertificateReader{
		cert: cert,
		key:  key,
	}, nil
}

func (cr *CertificateReader) GetPrivateKey() *rsa.PrivateKey {
	return cr.key
}

func (cr *CertificateReader) GetCertificate() *x509.Certificate {
	return cr.cert
}
