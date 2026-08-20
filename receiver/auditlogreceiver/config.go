// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
)

const (
	ResponseModeSync = "sync"

	CircuitOpenReject = "reject"
	CircuitOpenAccept = "accept"

	defaultResponseMode        = ResponseModeSync
	defaultCircuitOpenBehavior = CircuitOpenReject
	defaultDeliveryInitial     = 1 * time.Second
	defaultDeliveryMax         = 5 * time.Minute
)

var (
	errStorageRequired            = errors.New("storage extension is required")
	errInvalidResponseMode        = errors.New("response_mode must be sync")
	errInvalidCircuitOpenBehavior = errors.New("circuit_breaker.open_behavior must be reject or accept")
	errEmptyEndpoint              = errors.New("endpoint must be specified")
)

type Config struct {
	confighttp.ServerConfig `mapstructure:",squash"`

	Path string `mapstructure:"path"`

	// StorageID is required. Sync mode uses it as a write-ahead log before pipeline
	// delivery (crash recovery).
	StorageID component.ID `mapstructure:"storage"`

	// ResponseMode controls HTTP semantics and supports only sync mode.
	ResponseMode string `mapstructure:"response_mode"`

	Delivery DeliveryConfig `mapstructure:"delivery"`

	ProcessInterval time.Duration `mapstructure:"process_interval"`

	ProcessAgeThreshold time.Duration `mapstructure:"process_age_threshold"`

	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
}

type DeliveryConfig struct {
	MaxRetries      int           `mapstructure:"max_retries"`
	InitialInterval time.Duration `mapstructure:"initial_interval"`
	MaxInterval     time.Duration `mapstructure:"max_interval"`
}

type CircuitBreakerConfig struct {
	Enabled *bool `mapstructure:"enabled"`

	CircuitOpenThreshold int `mapstructure:"circuit_open_threshold"`

	CircuitOpenDuration time.Duration `mapstructure:"circuit_open_duration"`

	// OpenBehavior controls sync-mode ingest when the circuit is open:
	// reject (default) returns 503 without WAL; accept persists to WAL and returns 202.
	OpenBehavior string `mapstructure:"open_behavior"`
}

func (cb *CircuitBreakerConfig) IsEnabled() bool {
	if cb.Enabled == nil {
		return true
	}
	return *cb.Enabled
}

func (cb *CircuitBreakerConfig) OpenBehaviorMode() string {
	if cb.OpenBehavior == "" {
		return defaultCircuitOpenBehavior
	}
	return cb.OpenBehavior
}

func (cb *CircuitBreakerConfig) applyDefaults() {
	if cb.CircuitOpenThreshold == 0 {
		cb.CircuitOpenThreshold = 5
	}
	if cb.CircuitOpenDuration == 0 {
		cb.CircuitOpenDuration = time.Minute
	}
}

func (c *Config) Validate() error {
	if c.NetAddr.Endpoint == "" {
		return errEmptyEndpoint
	}

	if c.ResponseMode == "" {
		c.ResponseMode = defaultResponseMode
	} else if c.ResponseMode != ResponseModeSync {
		return errInvalidResponseMode
	}

	if c.StorageID == (component.ID{}) {
		return errStorageRequired
	}

	c.CircuitBreaker.applyDefaults()

	if ob := c.CircuitBreaker.OpenBehaviorMode(); ob != CircuitOpenReject && ob != CircuitOpenAccept {
		return errInvalidCircuitOpenBehavior
	}

	if c.Delivery.InitialInterval == 0 {
		c.Delivery.InitialInterval = defaultDeliveryInitial
	}
	if c.Delivery.MaxInterval == 0 {
		c.Delivery.MaxInterval = defaultDeliveryMax
	}
	if c.Delivery.MaxInterval < c.Delivery.InitialInterval {
		return fmt.Errorf("delivery.max_interval must be >= delivery.initial_interval")
	}

	return nil
}
