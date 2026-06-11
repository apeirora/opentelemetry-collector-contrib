// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"testing"

	"go.opentelemetry.io/collector/component"
)

func TestValidateDeferredModeDoesNotRequireSecret(t *testing.T) {
	cfg := &Config{
		Mode: ModeDeferred,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateSyncModeRequiresKeySource(t *testing.T) {
	cfg := &Config{Mode: ModeSync}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateSyncModeWithHMACKeyFile(t *testing.T) {
	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: "hmac.key",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateHashChainRequiresStorage(t *testing.T) {
	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: "hmac.key",
		HashChain: HashChainConfig{
			Enabled: true,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for hash chain without storage")
	}
}

func TestValidateHashChainWithStorage(t *testing.T) {
	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: "hmac.key",
		HashChain: HashChainConfig{
			Enabled:   true,
			StorageID: component.NewIDWithName(component.MustNewType("file_storage"), ""),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateDeadLetterRequiresStorage(t *testing.T) {
	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: "hmac.key",
		DeadLetter: DeadLetterConfig{
			Enabled: true,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateDeadLetterWithStorage(t *testing.T) {
	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: "hmac.key",
		DeadLetter: DeadLetterConfig{
			Enabled:   true,
			StorageID: component.NewIDWithName(component.MustNewType("file_storage"), ""),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if cfg.DeadLetter.KeyPrefix != defaultDeadLetterKeyPrefix {
		t.Fatalf("key_prefix = %q", cfg.DeadLetter.KeyPrefix)
	}
}
