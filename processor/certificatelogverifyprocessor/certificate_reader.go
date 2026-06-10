// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func loadCertificate(cfg *Config) (*x509.Certificate, error) {
	if cfg.CertFile != "" {
		data, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert_file %q: %w", cfg.CertFile, err)
		}
		return parseCertificatePEM(data)
	}

	if cfg.K8sSecret == nil {
		return nil, fmt.Errorf("certificate source not configured")
	}

	if cfg.K8sSecret.CertKeyEntry == "" {
		return nil, fmt.Errorf("k8s_secret.cert_key is required for signature verification")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultK8sTimeout)
	defer cancel()

	data, err := fetchSecretData(ctx, cfg.K8sSecret.Name, cfg.K8sSecret.Namespace, cfg.K8sSecret.CertKeyEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate from k8s secret: %w", err)
	}
	return parseCertificatePEM(data)
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	rest := data
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert, nil
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("certificate PEM is empty")
	}
	return nil, fmt.Errorf("no CERTIFICATE block found in PEM data")
}
