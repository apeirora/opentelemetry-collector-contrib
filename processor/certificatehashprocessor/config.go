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
)

var (
	errInvalidHashAlgorithm = errors.New("hash_algorithm must be SHA256 or SHA512")
)

type Config struct {
	HashAlgorithm string           `mapstructure:"hash_algorithm"`
	K8sSecret     *K8sSecretConfig `mapstructure:"k8s_secret"`
}

type K8sSecretConfig struct {
	Name      string `mapstructure:"name"`
	Namespace string `mapstructure:"namespace"`
	CertKey   string `mapstructure:"cert_key"`
	KeyKey    string `mapstructure:"key_key"`
	CAKey     string `mapstructure:"ca_key"`
}

func createDefaultConfig() component.Config {
	return &Config{
		HashAlgorithm: defaultHashAlgorithm,
	}
}

func (c *Config) Validate() error {
	if c.HashAlgorithm != "SHA256" && c.HashAlgorithm != "SHA512" {
		return errInvalidHashAlgorithm
	}

	if c.K8sSecret == nil {
		return errors.New("k8s_secret is required")
	}

	if c.K8sSecret.Name == "" {
		return errors.New("k8s_secret.name is required")
	}
	if c.K8sSecret.CertKey == "" {
		return errors.New("k8s_secret.cert_key is required")
	}
	if c.K8sSecret.KeyKey == "" {
		return errors.New("k8s_secret.key_key is required")
	}
	if c.K8sSecret.Namespace == "" {
		c.K8sSecret.Namespace = "default"
	}

	return nil
}

func (c *Config) GetHash() crypto.Hash {
	if c.HashAlgorithm == "SHA512" {
		return crypto.SHA512
	}
	return crypto.SHA256
}

var _ component.Config = (*Config)(nil)
