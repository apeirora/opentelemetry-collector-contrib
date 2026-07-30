// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
)

type Config struct {
	confighttp.ServerConfig `mapstructure:",squash"`

	// StorageID specifies the ID of the storage extension to use for persistent storage
	StorageID component.ID `mapstructure:"storage"`

	// ProcessInterval specifies how often the receiver processes stored logs
	// Default: 60s
	ProcessInterval time.Duration `mapstructure:"process_interval"`

	// ProcessAgeThreshold specifies how old logs must be before they are processed
	// Default: 60s
	ProcessAgeThreshold time.Duration `mapstructure:"process_age_threshold"`

	// CircuitBreaker configuration
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
}

// CircuitBreakerConfig defines circuit breaker behavior
type CircuitBreakerConfig struct {
	// Enabled specifies whether the circuit breaker is enabled
	// Default: true
	Enabled bool `mapstructure:"enabled"`

	// CircuitOpenThreshold specifies the number of consecutive failures before circuit opens
	// Default: 5
	CircuitOpenThreshold int `mapstructure:"circuit_open_threshold"`

	// CircuitOpenDuration specifies how long the circuit stays open before trying half-open
	// Default: 1m
	CircuitOpenDuration time.Duration `mapstructure:"circuit_open_duration"`
}
