// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor"

import (
	"errors"

	"go.opentelemetry.io/collector/component"
)

const (
	defaultMode        = "sync"
	defaultFailureMode = "strict"
	defaultProfile     = "default"
)

const (
	ModeSync     = "sync"
	ModeDeferred = "deferred"
)

const (
	FailureModeStrict = "strict"
	FailureModeMark   = "mark"
)

var (
	errInvalidMode        = errors.New("mode must be sync or deferred")
	errInvalidFailureMode = errors.New("failure_mode must be strict or mark")
	errSyncNeedsKeySource   = errors.New("sync mode requires hmac_key_file, cert_file, or k8s_secret for integrity verification")
	errHashChainNeedsStorage = errors.New("hash_chain.enabled requires hash_chain.storage")
)

type Config struct {
	Mode                string           `mapstructure:"mode"`
	FailureMode         string           `mapstructure:"failure_mode"`
	VerificationProfile string           `mapstructure:"verification_profile"`
	HmacKeyFile         string           `mapstructure:"hmac_key_file"`
	CertFile            string           `mapstructure:"cert_file"`
	K8sSecret           *K8sSecretConfig `mapstructure:"k8s_secret"`
	HashChain           HashChainConfig  `mapstructure:"hash_chain"`
}

type HashChainConfig struct {
	Enabled   bool         `mapstructure:"enabled"`
	StorageID component.ID `mapstructure:"storage"`
}

type K8sSecretConfig struct {
	Name         string `mapstructure:"name"`
	Namespace    string `mapstructure:"namespace"`
	HMACKeyEntry string `mapstructure:"hmac_key_entry"`
	CertKeyEntry string `mapstructure:"cert_key"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Mode:                defaultMode,
		FailureMode:         defaultFailureMode,
		VerificationProfile: defaultProfile,
	}
}

func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = defaultMode
	} else if c.Mode != ModeSync && c.Mode != ModeDeferred {
		return errInvalidMode
	}

	if c.FailureMode == "" {
		c.FailureMode = defaultFailureMode
	} else if c.FailureMode != FailureModeStrict && c.FailureMode != FailureModeMark {
		return errInvalidFailureMode
	}

	if c.VerificationProfile == "" {
		c.VerificationProfile = defaultProfile
	}

	if c.Mode == ModeDeferred {
		return nil
	}

	hasHMACKey := c.HmacKeyFile != "" || (c.K8sSecret != nil && c.K8sSecret.HMACKeyEntry != "")
	hasCert := c.CertFile != "" || (c.K8sSecret != nil && c.K8sSecret.CertKeyEntry != "")
	if !hasHMACKey && !hasCert {
		return errSyncNeedsKeySource
	}

	if c.HashChain.Enabled && c.HashChain.StorageID == (component.ID{}) {
		return errHashChainNeedsStorage
	}

	if c.K8sSecret != nil {
		if c.K8sSecret.Name == "" {
			return errors.New("k8s_secret.name is required")
		}
		if c.K8sSecret.Namespace == "" {
			c.K8sSecret.Namespace = "default"
		}
	}

	return nil
}

var _ component.Config = (*Config)(nil)
