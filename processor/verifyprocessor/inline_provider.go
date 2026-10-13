// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package verifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/verifyprocessor"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type inlineKeyMaterialProvider struct {
	baseKeyMaterialProvider
}

func newInlineKeyMaterialProvider(cfg *EnvKeyConfig) (KeyMaterialProvider, error) {
	if cfg.HMACKey != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.HMACKey))
		if err != nil {
			return nil, fmt.Errorf("env.hmac_key: must be standard base64-encoded: %w", err)
		}
		if len(key) == 0 {
			return nil, errors.New("env.hmac_key: empty after base64 decoding")
		}
		return &inlineKeyMaterialProvider{baseKeyMaterialProvider{hmacKey: key}}, nil
	}

	certPEM := []byte(cfg.Certificate)
	if len(certPEM) == 0 {
		return nil, errors.New("env.certificate: value is empty")
	}
	certPEM = decodeIfBase64(certPEM)
	certPEM = normalizeLineEndings(certPEM)
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	return &inlineKeyMaterialProvider{baseKeyMaterialProvider{cert: cert}}, nil
}
