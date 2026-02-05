// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrityprocessor

import (
	"errors"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	Sign SignConfig `mapstructure:"sign"`
}

type SignConfig struct {
	Algorithm string `mapstructure:"algorithm"`
	
	LocalSecret *LocalSecretConfig `mapstructure:"local_secret,omitempty"`
	
	OpenBaoTransit *OpenBaoTransitConfig `mapstructure:"openbao_transit,omitempty"`
	
	SignatureAttribute string `mapstructure:"signature_attribute"`
	
	IncludeResourceAttributes bool `mapstructure:"include_resource_attributes"`
}

type LocalSecretConfig struct {
	Secret string `mapstructure:"secret"`
}

type OpenBaoTransitConfig struct {
	Address   string `mapstructure:"address"`
	Token     string `mapstructure:"token"`
	KeyName    string `mapstructure:"key_name"`
	MountPath string `mapstructure:"mount_path"`
}

var _ component.Config = (*Config)(nil)

func createDefaultConfig() component.Config {
	return &Config{
		Sign: SignConfig{
			Algorithm:                "HMAC-SHA256",
			SignatureAttribute:       "otel.integrity.signature",
			IncludeResourceAttributes: true,
		},
	}
}

func (cfg *Config) Validate() error {
	if cfg.Sign.Algorithm != "HMAC-SHA256" && cfg.Sign.Algorithm != "HMAC-SHA512" {
		return errors.New("algorithm must be HMAC-SHA256 or HMAC-SHA512")
	}
	
	if cfg.Sign.LocalSecret == nil && cfg.Sign.OpenBaoTransit == nil {
		return errors.New("either local_secret or openbao_transit must be configured")
	}
	
	if cfg.Sign.LocalSecret != nil && cfg.Sign.OpenBaoTransit != nil {
		return errors.New("only one of local_secret or openbao_transit can be configured")
	}
	
	if cfg.Sign.LocalSecret != nil && cfg.Sign.LocalSecret.Secret == "" {
		return errors.New("local_secret.secret cannot be empty")
	}
	
	if cfg.Sign.OpenBaoTransit != nil {
		if cfg.Sign.OpenBaoTransit.Address == "" {
			return errors.New("openbao_transit.address cannot be empty")
		}
		if cfg.Sign.OpenBaoTransit.Token == "" {
			return errors.New("openbao_transit.token cannot be empty")
		}
		if cfg.Sign.OpenBaoTransit.KeyName == "" {
			return errors.New("openbao_transit.key_name cannot be empty")
		}
		if cfg.Sign.OpenBaoTransit.MountPath == "" {
			cfg.Sign.OpenBaoTransit.MountPath = "transit"
		}
	}
	
	if cfg.Sign.SignatureAttribute == "" {
		return errors.New("signature_attribute cannot be empty")
	}
	
	return nil
}
