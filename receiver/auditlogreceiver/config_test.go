// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/confignet"
)

func configWithEndpoint(endpoint string) *Config {
	netAddr := confignet.NewDefaultAddrConfig()
	netAddr.Transport = confignet.TransportTypeTCP
	netAddr.Endpoint = endpoint
	return &Config{ServerConfig: confighttp.ServerConfig{NetAddr: netAddr}}
}

func TestConfigValidateRequiresEndpoint(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: ResponseModeSync,
	}
	if err := cfg.Validate(); !errors.Is(err, errEmptyEndpoint) {
		t.Fatalf("expected empty endpoint error, got %v", err)
	}
}

func TestConfigValidateRequiresStorage(t *testing.T) {
	t.Parallel()
	cfg := configWithEndpoint("localhost:4310")
	cfg.ResponseMode = ResponseModeSync
	if err := cfg.Validate(); !errors.Is(err, errStorageRequired) {
		t.Fatalf("expected storage required, got %v", err)
	}
}

func TestConfigValidateSyncWithStorage(t *testing.T) {
	t.Parallel()
	cfg := configWithEndpoint("localhost:4310")
	cfg.ResponseMode = ResponseModeSync
	cfg.StorageID = component.NewIDWithName(component.MustNewType("file_storage"), "")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("sync with storage should validate, got %v", err)
	}
	if !cfg.CircuitBreaker.IsEnabled() {
		t.Fatal("circuit breaker should default to enabled")
	}
}

func TestConfigValidateAsyncRequiresStorage(t *testing.T) {
	t.Parallel()
	cfg := configWithEndpoint("localhost:4310")
	cfg.ResponseMode = ResponseModeAsync
	if err := cfg.Validate(); !errors.Is(err, errStorageRequired) {
		t.Fatalf("expected storage required for async, got %v", err)
	}
}

func TestConfigValidateResponseMode(t *testing.T) {
	t.Parallel()
	cfg := configWithEndpoint("localhost:4310")
	cfg.StorageID = component.NewIDWithName(component.MustNewType("file_storage"), "")
	cfg.ResponseMode = "invalid"
	if err := cfg.Validate(); err != errInvalidResponseMode {
		t.Fatalf("expected invalid response mode, got %v", err)
	}
}

func TestCircuitBreakerCanBeDisabled(t *testing.T) {
	t.Parallel()
	disabled := false
	cfg := configWithEndpoint("localhost:4310")
	cfg.StorageID = component.NewIDWithName(component.MustNewType("file_storage"), "")
	cfg.ResponseMode = ResponseModeSync
	cfg.CircuitBreaker = CircuitBreakerConfig{Enabled: &disabled}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.CircuitBreaker.IsEnabled() {
		t.Fatal("circuit breaker should be disabled")
	}
}

func TestCircuitBreakerOpenBehaviorValidation(t *testing.T) {
	t.Parallel()
	cfg := configWithEndpoint("localhost:4310")
	cfg.StorageID = component.NewIDWithName(component.MustNewType("file_storage"), "")
	cfg.ResponseMode = ResponseModeSync
	cfg.CircuitBreaker.OpenBehavior = "queue"
	if err := cfg.Validate(); !errors.Is(err, errInvalidCircuitOpenBehavior) {
		t.Fatalf("expected invalid open_behavior error, got %v", err)
	}
	cfg.CircuitBreaker.OpenBehavior = CircuitOpenAccept
	if err := cfg.Validate(); err != nil {
		t.Fatalf("accept should validate, got %v", err)
	}
}
