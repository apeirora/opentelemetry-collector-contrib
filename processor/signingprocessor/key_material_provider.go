// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto/rsa"
	"crypto/x509"
)

// KeyMaterialProvider supplies the RSA private key and certificate used for signing.
// Implementations may load key material from Kubernetes secrets, environment variables,
// files, or any other source.
type KeyMaterialProvider interface {
	GetPrivateKey() *rsa.PrivateKey
	GetCertificate() *x509.Certificate
}
