// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// CertificateReader holds a parsed RSA private key and X.509 certificate.
// It is used by KeyMaterialProvider implementations after they have fetched
// the raw PEM data from their respective source.
type CertificateReader struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func (cr *CertificateReader) GetPrivateKey() *rsa.PrivateKey {
	return cr.key
}

func (cr *CertificateReader) GetCertificate() *x509.Certificate {
	return cr.cert
}

// parseCertificateData parses PEM-encoded certificate and private key bytes
// into a CertificateReader. Only RSA keys (PKCS1 and PKCS8) are supported.
func parseCertificateData(certPEM, keyPEM []byte) (*CertificateReader, error) {
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("certificate data is empty")
	}
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}

	certStr := string(certPEM)
	if !strings.Contains(certStr, "-----BEGIN") {
		return nil, fmt.Errorf("certificate data does not appear to be PEM format (data length: %d, first 100 bytes: %q)", len(certPEM), string(certPEM[:min(100, len(certPEM))]))
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate (data length: %d, first 100 bytes: %q)", len(certPEM), string(certPEM[:min(100, len(certPEM))]))
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyStr := string(keyPEM)
	if !strings.Contains(keyStr, "-----BEGIN") {
		return nil, fmt.Errorf("private key data does not appear to be PEM format (data length: %d, first 100 bytes: %q)", len(keyPEM), string(keyPEM[:min(100, len(keyPEM))]))
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key (data length: %d, first 100 bytes: %q)", len(keyPEM), string(keyPEM[:min(100, len(keyPEM))]))
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

func decodeIfBase64(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	dataStr := strings.TrimSpace(string(data))
	if !strings.HasPrefix(dataStr, "-----BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(dataStr)
		if err == nil && len(decoded) > 0 {
			if strings.HasPrefix(string(decoded), "-----BEGIN") {
				return decoded
			}
		}
	}
	return data
}

func normalizeLineEndings(data []byte) []byte {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return []byte(s)
}
