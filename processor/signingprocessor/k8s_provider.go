// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type k8sKeyMaterialProvider struct {
	reader *certificateReader
}

func newK8sKeyMaterialProvider(ctx context.Context, cfg *K8sSecretConfig, logger *zap.Logger) (KeyMaterialProvider, error) {
	client, err := getK8sClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return newK8sKeyMaterialProviderWithClient(ctx, client, cfg, logger)
}

func newK8sKeyMaterialProviderWithClient(ctx context.Context, client kubernetes.Interface, cfg *K8sSecretConfig, logger *zap.Logger) (KeyMaterialProvider, error) {
	certPEM, err := fetchSecretDataWithClient(ctx, client, cfg.Name, cfg.Namespace, cfg.CertKey, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from k8s secret: %w", err)
	}

	keyPEM, err := fetchSecretDataWithClient(ctx, client, cfg.Name, cfg.Namespace, cfg.KeyKey, logger)
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

func (p *k8sKeyMaterialProvider) GetPrivateKey() crypto.Signer {
	return p.reader.GetPrivateKey()
}

func (p *k8sKeyMaterialProvider) GetCertificate() *x509.Certificate {
	return p.reader.GetCertificate()
}

func (p *k8sKeyMaterialProvider) GetHMACKey() []byte { return nil }
