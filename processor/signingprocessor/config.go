// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/signingprocessor"

import (
	"crypto"
	"errors"

	"go.opentelemetry.io/collector/component"
)

const (
	defaultAlgorithm      = "RS256"
	defaultCertificateRef = "fingerprint"

	// Algorithm constants — JWA identifiers (RFC 7518 / RFC 8037 / IANA).
	AlgorithmRS256     = "RS256"
	AlgorithmRS512     = "RS512"
	AlgorithmES256     = "ES256"
	AlgorithmEdDSA     = "EdDSA"
	AlgorithmHMACSHA256 = "HMAC-SHA256"

	KeySourceK8sSecret = "k8s_secret"
	KeySourceEnv       = "env"
	KeySourceFile      = "file"
	KeySourceBao       = "bao"
	KeySourceHMACKey   = "hmac_key"

	CertificateRefFingerprint = "fingerprint"
	CertificateRefFull        = "full"
)

var (
	errInvalidAlgorithm       = errors.New("algorithm must be RS256, RS512, ES256, EdDSA, or HMAC-SHA256")
	errInvalidKeySourceType   = errors.New("key_source.type must be k8s_secret, env, file, bao, or hmac_key")
	errMissingKeySourceConfig = errors.New("key_source config block is missing for the specified type")
	errInvalidCertificateRef  = errors.New("certificate_ref must be fingerprint or full")
	errHMACNoCertRef          = errors.New("certificate_ref must not be set for HMAC-SHA256 (symmetric algorithm has no certificate)")
)

type Config struct {
	// Algorithm is the JWA signing algorithm.
	// Valid values: RS256, RS512, ES256, EdDSA, HMAC-SHA256. Default: RS256.
	Algorithm string `mapstructure:"algorithm"`
	// CertificateRef controls how the certificate is encoded in the
	// audit.integrity.certificate resource attribute. Not used for HMAC-SHA256.
	CertificateRef string          `mapstructure:"certificate_ref"`
	KeySource      KeySourceConfig `mapstructure:"key_source"`
}

type KeySourceConfig struct {
	Type      string           `mapstructure:"type"`
	K8sSecret *K8sSecretConfig `mapstructure:"k8s_secret"`
	Env       *EnvKeyConfig    `mapstructure:"env"`
	File      *FileKeyConfig   `mapstructure:"file"`
	Bao       *BaoKeyConfig    `mapstructure:"bao"`
	HMACKey   *HMACKeyConfig   `mapstructure:"hmac_key"`
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

// HMACKeyConfig configures the symmetric HMAC-SHA256 key source.
// Exactly one of KeyEnvVar or KeyFile must be set.
// The key may be raw bytes or base64-encoded.
type HMACKeyConfig struct {
	// KeyEnvVar is the name of an environment variable containing the HMAC key.
	KeyEnvVar string `mapstructure:"key_env_var"`
	// KeyFile is the path to a file containing the HMAC key.
	KeyFile string `mapstructure:"key_file"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Algorithm:      defaultAlgorithm,
		CertificateRef: defaultCertificateRef,
	}
}

func (c *Config) Validate() error {
	switch c.Algorithm {
	case AlgorithmRS256, AlgorithmRS512, AlgorithmES256, AlgorithmEdDSA, AlgorithmHMACSHA256:
		// valid
	case "":
		c.Algorithm = defaultAlgorithm
	default:
		return errInvalidAlgorithm
	}

	if c.Algorithm == AlgorithmHMACSHA256 {
		// certificate_ref is meaningless for a symmetric algorithm
		if c.CertificateRef != "" && c.CertificateRef != defaultCertificateRef {
			return errHMACNoCertRef
		}
	} else {
		if c.CertificateRef == "" {
			c.CertificateRef = defaultCertificateRef
		} else if c.CertificateRef != CertificateRefFingerprint && c.CertificateRef != CertificateRefFull {
			return errInvalidCertificateRef
		}
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
	case KeySourceHMACKey:
		if c.KeySource.HMACKey == nil {
			return errMissingKeySourceConfig
		}
		if c.KeySource.HMACKey.KeyEnvVar == "" && c.KeySource.HMACKey.KeyFile == "" {
			return errors.New("key_source.hmac_key requires either key_env_var or key_file")
		}
		if c.KeySource.HMACKey.KeyEnvVar != "" && c.KeySource.HMACKey.KeyFile != "" {
			return errors.New("key_source.hmac_key: set only one of key_env_var or key_file, not both")
		}
	default:
		return errInvalidKeySourceType
	}

	return nil
}

// GetHash returns the crypto.Hash for the configured algorithm.
// Returns crypto.Hash(0) for EdDSA (hashes internally).
func (c *Config) GetHash() crypto.Hash {
	switch c.Algorithm {
	case AlgorithmRS512:
		return crypto.SHA512
	case AlgorithmEdDSA:
		return crypto.Hash(0)
	default: // RS256, ES256, HMAC-SHA256
		return crypto.SHA256
	}
}

// GetJWAAlgorithm returns the JWA/IANA algorithm identifier — identical to Algorithm.
func (c *Config) GetJWAAlgorithm() string {
	return c.Algorithm
}

var _ component.Config = (*Config)(nil)
