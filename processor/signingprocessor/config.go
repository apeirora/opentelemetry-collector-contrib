// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"errors"

	"go.opentelemetry.io/collector/component"
)

const (
	defaultHashAlgorithm = "SHA256"
	defaultSignContent   = "body"

	KeySourceK8sSecret = "k8s_secret"
	KeySourceEnv       = "env"
)

const (
	SignContentBody = "body"
	SignContentMeta = "meta"
	SignContentAttr = "attr"
)

var (
	errInvalidHashAlgorithm  = errors.New("hash_algorithm must be SHA256 or SHA512")
	errInvalidSignContent    = errors.New("sign_content must be body, meta, or attr")
	errInvalidKeySourceType  = errors.New("key_source.type must be k8s_secret or env")
	errMissingKeySourceConfig = errors.New("key_source config block is missing for the specified type")
)

type Config struct {
	HashAlgorithm string          `mapstructure:"hash_algorithm"`
	SignContent   string          `mapstructure:"sign_content"`
	KeySource     KeySourceConfig `mapstructure:"key_source"`
}

type KeySourceConfig struct {
	Type      string           `mapstructure:"type"`
	K8sSecret *K8sSecretConfig `mapstructure:"k8s_secret"`
	Env       *EnvKeyConfig    `mapstructure:"env"`
}

type K8sSecretConfig struct {
	Name      string `mapstructure:"name"`
	Namespace string `mapstructure:"namespace"`
	CertKey   string `mapstructure:"cert_key"`
	KeyKey    string `mapstructure:"key_key"`
	CAKey     string `mapstructure:"ca_key"`
}

type EnvKeyConfig struct {
	CertEnvVar string `mapstructure:"cert_env_var"`
	KeyEnvVar  string `mapstructure:"key_env_var"`
}

func createDefaultConfig() component.Config {
	return &Config{
		HashAlgorithm: defaultHashAlgorithm,
		SignContent:   defaultSignContent,
	}
}

func (c *Config) Validate() error {
	if c.HashAlgorithm != "SHA256" && c.HashAlgorithm != "SHA512" {
		return errInvalidHashAlgorithm
	}

	if c.SignContent == "" {
		c.SignContent = defaultSignContent
	} else if c.SignContent != SignContentBody && c.SignContent != SignContentMeta && c.SignContent != SignContentAttr {
		return errInvalidSignContent
	}

	switch c.KeySource.Type {
	case KeySourceK8sSecret:
		if c.KeySource.K8sSecret == nil {
			return errMissingKeySourceConfig
		}
		if c.KeySource.K8sSecret.Name == "" {
			return errors.New("key_source.k8s_secret.name is required")
		}
		if c.KeySource.K8sSecret.CertKey == "" {
			return errors.New("key_source.k8s_secret.cert_key is required")
		}
		if c.KeySource.K8sSecret.KeyKey == "" {
			return errors.New("key_source.k8s_secret.key_key is required")
		}
		if c.KeySource.K8sSecret.Namespace == "" {
			c.KeySource.K8sSecret.Namespace = "default"
		}
	case KeySourceEnv:
		if c.KeySource.Env == nil {
			return errMissingKeySourceConfig
		}
		if c.KeySource.Env.CertEnvVar == "" {
			return errors.New("key_source.env.cert_env_var is required")
		}
		if c.KeySource.Env.KeyEnvVar == "" {
			return errors.New("key_source.env.key_env_var is required")
		}
	default:
		return errInvalidKeySourceType
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
