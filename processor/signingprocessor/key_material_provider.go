// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"crypto/x509"
)

// KeyMaterialProvider supplies the private signing key and certificate used for signing.
// The private key is returned as crypto.Signer, which is satisfied by *rsa.PrivateKey,
// *ecdsa.PrivateKey, and ed25519.PrivateKey from the Go standard library.
// Implementations may load key material from Kubernetes secrets, environment variables,
// files, or any other source.
type KeyMaterialProvider interface {
	GetPrivateKey() crypto.Signer
	GetCertificate() *x509.Certificate
}
