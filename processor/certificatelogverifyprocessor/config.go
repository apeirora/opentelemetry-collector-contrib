// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor"

import (
	"errors"
	"fmt"
	"time"

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

const (
	defaultDeadLetterKeyPrefix = "dead_letter/"
)

var (
	errInvalidMode             = errors.New("mode must be sync or deferred")
	errInvalidFailureMode      = errors.New("failure_mode must be strict or mark")
	errSyncNeedsKeySource      = errors.New("sync mode requires hmac_key_file, cert_file, or k8s_secret for integrity verification")
	errHashChainNeedsStorage   = errors.New("hash_chain.enabled requires hash_chain.storage")
	errDeadLetterNeedsStorage  = errors.New("dead_letter.enabled requires dead_letter.storage")
	errInvalidDeadLetterMode   = errors.New("dead_letter.failure_modes entries must be strict or mark")
)

type Config struct {
	Mode                string           `mapstructure:"mode"`
	FailureMode         string           `mapstructure:"failure_mode"`
	VerificationProfile string           `mapstructure:"verification_profile"`
	HmacKeyFile         string           `mapstructure:"hmac_key_file"`
	CertFile            string           `mapstructure:"cert_file"`
	K8sSecret           *K8sSecretConfig `mapstructure:"k8s_secret"`
	HashChain           HashChainConfig  `mapstructure:"hash_chain"`
	DeadLetter          DeadLetterConfig `mapstructure:"dead_letter"`
}

type DeadLetterConfig struct {
	Enabled               bool         `mapstructure:"enabled"`
	StorageID             component.ID `mapstructure:"storage"`
	KeyPrefix             string       `mapstructure:"key_prefix"`
	IncludeRecord         *bool        `mapstructure:"include_record"`
	IncludeResource       *bool        `mapstructure:"include_resource"`
	Reasons               []string     `mapstructure:"reasons"`
	FailureModes          []string     `mapstructure:"failure_modes"`
	MaxEntrySizeBytes     int          `mapstructure:"max_entry_size_bytes"`
	FailOnStorageError    *bool        `mapstructure:"fail_on_storage_error"`
	PartitionByStream     bool         `mapstructure:"partition_by_stream"`
	DeduplicateByRecordID bool         `mapstructure:"deduplicate_by_record_id"`
	MaintainIndex         bool         `mapstructure:"maintain_index"`
	TTL                   time.Duration `mapstructure:"ttl"`
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
		return c.DeadLetter.validate()
	}

	hasHMACKey := c.hasHMACKeySource()
	hasCert := c.hasCertKeySource()
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

	return c.DeadLetter.validate()
}

func (c *Config) hasHMACKeySource() bool {
	return c.HmacKeyFile != "" || (c.K8sSecret != nil && c.K8sSecret.HMACKeyEntry != "")
}

func (c *Config) hasCertKeySource() bool {
	return c.CertFile != "" || (c.K8sSecret != nil && c.K8sSecret.CertKeyEntry != "")
}

func (dl *DeadLetterConfig) validate() error {
	if !dl.Enabled {
		return nil
	}
	if dl.StorageID == (component.ID{}) {
		return errDeadLetterNeedsStorage
	}
	if dl.KeyPrefix == "" {
		dl.KeyPrefix = defaultDeadLetterKeyPrefix
	}
	for _, mode := range dl.FailureModes {
		if mode != FailureModeStrict && mode != FailureModeMark {
			return errInvalidDeadLetterMode
		}
	}
	if dl.MaxEntrySizeBytes < 0 {
		return fmt.Errorf("dead_letter.max_entry_size_bytes must be >= 0")
	}
	if dl.TTL < 0 {
		return fmt.Errorf("dead_letter.ttl must be >= 0")
	}
	return nil
}

func (dl *DeadLetterConfig) ShouldIncludeRecord() bool {
	if dl.IncludeRecord == nil {
		return true
	}
	return *dl.IncludeRecord
}

func (dl *DeadLetterConfig) ShouldIncludeResource() bool {
	if dl.IncludeResource == nil {
		return true
	}
	return *dl.IncludeResource
}

func (dl *DeadLetterConfig) ShouldFailOnStorageError() bool {
	if dl.FailOnStorageError == nil {
		return false
	}
	return *dl.FailOnStorageError
}

func (dl *DeadLetterConfig) effectiveKeyPrefix() string {
	if dl.KeyPrefix == "" {
		return defaultDeadLetterKeyPrefix
	}
	return dl.KeyPrefix
}

func (dl *DeadLetterConfig) effectiveFailureModes() []string {
	if len(dl.FailureModes) == 0 {
		return []string{FailureModeStrict, FailureModeMark}
	}
	return dl.FailureModes
}

var _ component.Config = (*Config)(nil)
