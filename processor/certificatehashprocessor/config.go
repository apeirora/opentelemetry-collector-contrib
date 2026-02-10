// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatehashprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatehashprocessor"

import (
	"crypto"
	"errors"

	"go.opentelemetry.io/collector/component"
)

const (
	defaultHashAlgorithm = "SHA256"
	defaultCertPath      = "/etc/certs/cert.pem"
	defaultKeyPath       = "/etc/certs/key.pem"
	defaultCAPath        = "/etc/certs/ca.pem"
)

var (
	errInvalidHashAlgorithm = errors.New("hash_algorithm must be SHA256 or SHA512")
	errMissingCertPath      = errors.New("cert_path is required")
	errMissingKeyPath       = errors.New("key_path is required")
)

type Config struct {
	HashAlgorithm string `mapstructure:"hash_algorithm"`
	CertPath      string `mapstructure:"cert_path"`
	KeyPath       string `mapstructure:"key_path"`
	CAPath        string `mapstructure:"ca_path"`
}

func createDefaultConfig() component.Config {
	return &Config{
		HashAlgorithm: defaultHashAlgorithm,
		CertPath:      defaultCertPath,
		KeyPath:       defaultKeyPath,
		CAPath:        defaultCAPath,
	}
}

func (c *Config) Validate() error {
	if c.HashAlgorithm != "SHA256" && c.HashAlgorithm != "SHA512" {
		return errInvalidHashAlgorithm
	}

	if c.CertPath == "" {
		return errMissingCertPath
	}

	if c.KeyPath == "" {
		return errMissingKeyPath
	}

	return nil
}

func (c *Config) GetHash() crypto.Hash {
	if c.HashAlgorithm == "SHA512" {
		return crypto.SHA512
	}
	return crypto.SHA256
}
