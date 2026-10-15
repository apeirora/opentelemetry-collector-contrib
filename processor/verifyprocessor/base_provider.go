// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package verifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/verifyprocessor"

import (
	"crypto/x509"
)

type baseKeyMaterialProvider struct {
	cert    *x509.Certificate
	hmacKey []byte
}

func (b *baseKeyMaterialProvider) GetCertificate() *x509.Certificate { return b.cert }

func (b *baseKeyMaterialProvider) GetHMACKey() []byte { return b.hmacKey }
