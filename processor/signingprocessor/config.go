// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"errors"

	"go.opentelemetry.io/collector/component"
)

const (
	defaultHashAlgorithm    = "SHA256"
	defaultSignContent      = "body"
	defaultCertificateRef   = "fingerprint"

	KeySourceK8sSecret = "k8s_secret"
	KeySourceEnv       = "env"
	KeySourceFile      = "file"
	KeySourceBao       = "bao"

	CertificateRefFingerprint = "fingerprint"
	CertificateRefFull        = "full"
)

const (
	SignContentBody = "body"
	SignContentMeta = "meta"
	SignContentAttr = "attr"
)

var (
	errInvalidHashAlgorithm    = errors.New("hash_algorithm must be SHA256 or SHA512")
	errInvalidSignContent      = errors.New("sign_content must be body, meta, or attr")
	errInvalidKeySourceType    = errors.New("key_source.type must be k8s_secret, env, file, or bao")
	errMissingKeySourceConfig  = errors.New("key_source config block is missing for the specified type")
	errInvalidCertificateRef   = errors.New("certificate_ref must be fingerprint or full")
)

type Config struct {
	HashAlgorithm  string          `mapstructure:"hash_algorithm"`
	SignContent    string          `mapstructure:"sign_content"`
	CertificateRef string          `mapstructure:"certificate_ref"`
	KeySource      KeySourceConfig `mapstructure:"key_source"`
}

type KeySourceConfig struct {
	Type      string           `mapstructure:"type"`
	K8sSecret *K8sSecretConfig `mapstructure:"k8s_secret"`
	Env       *EnvKeyConfig    `mapstructure:"env"`
	File      *FileKeyConfig   `mapstructure:"file"`
	Bao       *BaoKeyConfig    `mapstructure:"bao"`
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

type FileKeyConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// BaoKeyConfig configures the OpenBao (Vault-compatible) key material source.
// Address and Token are optional: if omitted, the client reads BAO_ADDR and
// BAO_TOKEN (or any other supported BAO_* environment variables) automatically.
type BaoKeyConfig struct {
	Address    string `mapstructure:"address"`
	Token      string `mapstructure:"token"`
	SecretPath string `mapstructure:"secret_path"`
	CertField  string `mapstructure:"cert_field"`
	KeyField   string `mapstructure:"key_field"`
}

func createDefaultConfig() component.Config {
	return &Config{
		HashAlgorithm:  defaultHashAlgorithm,
		SignContent:    defaultSignContent,
		CertificateRef: defaultCertificateRef,
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

	if c.CertificateRef == "" {
		c.CertificateRef = defaultCertificateRef
	} else if c.CertificateRef != CertificateRefFingerprint && c.CertificateRef != CertificateRefFull {
		return errInvalidCertificateRef
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
	case KeySourceFile:
		if c.KeySource.File == nil {
			return errMissingKeySourceConfig
		}
		if c.KeySource.File.CertFile == "" {
			return errors.New("key_source.file.cert_file is required")
		}
		if c.KeySource.File.KeyFile == "" {
			return errors.New("key_source.file.key_file is required")
		}
	case KeySourceBao:
		if c.KeySource.Bao == nil {
			return errMissingKeySourceConfig
		}
		if c.KeySource.Bao.SecretPath == "" {
			return errors.New("key_source.bao.secret_path is required")
		}
		if c.KeySource.Bao.CertField == "" {
			return errors.New("key_source.bao.cert_field is required")
		}
		if c.KeySource.Bao.KeyField == "" {
			return errors.New("key_source.bao.key_field is required")
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

// GetJWAAlgorithm returns the JWA algorithm identifier (RFC 7518) for the
// configured hash algorithm combined with RSA PKCS1v15 signing.
func (c *Config) GetJWAAlgorithm() string {
	if c.HashAlgorithm == "SHA512" {
		return "RS512"
	}
	return "RS256"
}

var _ component.Config = (*Config)(nil)
