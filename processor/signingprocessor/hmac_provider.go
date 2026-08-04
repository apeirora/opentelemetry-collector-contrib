// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
)

type hmacKeyMaterialProvider struct {
	key []byte
}

func newHMACKeyMaterialProvider(cfg *HMACKeyConfig) (KeyMaterialProvider, error) {
	var key []byte

	switch {
	case cfg.KeyEnvVar != "":
		raw := os.Getenv(cfg.KeyEnvVar)
		if raw == "" {
			return nil, fmt.Errorf("environment variable %q is not set or empty", cfg.KeyEnvVar)
		}
		key = decodeIfBase64(normalizeLineEndings([]byte(raw)))
	case cfg.KeyFile != "":
		data, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read HMAC key file %q: %w", cfg.KeyFile, err)
		}
		key = decodeIfBase64(normalizeLineEndings(data))
	default:
		return nil, fmt.Errorf("hmac_key requires either key_env_var or key_file")
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("HMAC key is empty")
	}

	return &hmacKeyMaterialProvider{key: key}, nil
}

func (p *hmacKeyMaterialProvider) GetPrivateKey() crypto.Signer    { return nil }
func (p *hmacKeyMaterialProvider) GetCertificate() *x509.Certificate { return nil }
func (p *hmacKeyMaterialProvider) GetHMACKey() []byte              { return p.key }
