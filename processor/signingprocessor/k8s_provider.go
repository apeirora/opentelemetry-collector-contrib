// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"go.uber.org/zap"
)

type k8sKeyMaterialProvider struct {
	reader *CertificateReader
}

func newK8sKeyMaterialProvider(ctx context.Context, cfg *K8sSecretConfig, logger *zap.Logger) (KeyMaterialProvider, error) {
	certPEM, err := fetchSecretData(ctx, cfg.Name, cfg.Namespace, cfg.CertKey, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from k8s secret: %w", err)
	}

	keyPEM, err := fetchSecretData(ctx, cfg.Name, cfg.Namespace, cfg.KeyKey, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch private key from k8s secret: %w", err)
	}

	certPEM = decodeIfBase64(certPEM)
	keyPEM = decodeIfBase64(keyPEM)
	certPEM = normalizeLineEndings(certPEM)
	keyPEM = normalizeLineEndings(keyPEM)

	reader, err := parseCertificateData(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &k8sKeyMaterialProvider{reader: reader}, nil
}

func (p *k8sKeyMaterialProvider) GetPrivateKey() *rsa.PrivateKey {
	return p.reader.GetPrivateKey()
}

func (p *k8sKeyMaterialProvider) GetCertificate() *x509.Certificate {
	return p.reader.GetCertificate()
}
