// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"testing"

	"go.opentelemetry.io/collector/component"
)

func TestConfigValidateRequiresStorage(t *testing.T) {
	t.Parallel()
	cfg := &Config{ResponseMode: ResponseModeSync}
	if err := cfg.Validate(); !errors.Is(err, errStorageRequired) {
		t.Fatalf("expected storage required, got %v", err)
	}
}

func TestConfigValidateSyncWithStorage(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		ResponseMode: ResponseModeSync,
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("sync with storage should validate, got %v", err)
	}
	if !cfg.CircuitBreaker.IsEnabled() {
		t.Fatal("circuit breaker should default to enabled")
	}
}

func TestConfigValidateAsyncRequiresStorage(t *testing.T) {
	t.Parallel()
	cfg := &Config{ResponseMode: ResponseModeAsync}
	if err := cfg.Validate(); !errors.Is(err, errStorageRequired) {
		t.Fatalf("expected storage required for async, got %v", err)
	}
}

func TestConfigValidateResponseMode(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: "invalid",
	}
	if err := cfg.Validate(); err != errInvalidResponseMode {
		t.Fatalf("expected invalid response mode, got %v", err)
	}
}

func TestCircuitBreakerCanBeDisabled(t *testing.T) {
	t.Parallel()
	disabled := false
	cfg := &Config{
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: ResponseModeSync,
		CircuitBreaker: CircuitBreakerConfig{
			Enabled: &disabled,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.CircuitBreaker.IsEnabled() {
		t.Fatal("circuit breaker should be disabled")
	}
}
