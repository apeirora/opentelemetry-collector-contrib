// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package signingprocessor

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"os"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// ---------------------------------------------------------------------------
// Config validation — HMAC-SHA256
// ---------------------------------------------------------------------------

func TestConfigValidateHMAC(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid env",
			cfg: Config{
				Algorithm: AlgorithmHMACSHA256,
				KeySource: KeySourceConfig{
					Type:    KeySourceHMACKey,
					HMACKey: &HMACKeyConfig{KeyEnvVar: "MY_HMAC_KEY"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid file",
			cfg: Config{
				Algorithm: AlgorithmHMACSHA256,
				KeySource: KeySourceConfig{
					Type:    KeySourceHMACKey,
					HMACKey: &HMACKeyConfig{KeyFile: "/etc/signing/hmac.key"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing hmac_key block",
			cfg: Config{
				Algorithm: AlgorithmHMACSHA256,
				KeySource: KeySourceConfig{Type: KeySourceHMACKey},
			},
			wantErr: true,
		},
		{
			name: "neither env nor file",
			cfg: Config{
				Algorithm: AlgorithmHMACSHA256,
				KeySource: KeySourceConfig{
					Type:    KeySourceHMACKey,
					HMACKey: &HMACKeyConfig{},
				},
			},
			wantErr: true,
		},
		{
			name: "both env and file set",
			cfg: Config{
				Algorithm: AlgorithmHMACSHA256,
				KeySource: KeySourceConfig{
					Type:    KeySourceHMACKey,
					HMACKey: &HMACKeyConfig{KeyEnvVar: "K", KeyFile: "/f"},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate_ref explicitly set — rejected",
			cfg: Config{
				Algorithm:      AlgorithmHMACSHA256,
				CertificateRef: "full",
				KeySource: KeySourceConfig{
					Type:    KeySourceHMACKey,
					HMACKey: &HMACKeyConfig{KeyEnvVar: "K"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigGetHashHMAC(t *testing.T) {
	if (&Config{Algorithm: AlgorithmHMACSHA256}).GetHash() != crypto.SHA256 {
		t.Error("HMAC-SHA256 GetHash() should return crypto.SHA256")
	}
}

// ---------------------------------------------------------------------------
// hmacKeyMaterialProvider
// ---------------------------------------------------------------------------

func TestHMACProviderFromEnv(t *testing.T) {
	t.Setenv("TEST_HMAC_KEY", "super-secret-key")
	prov, err := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "TEST_HMAC_KEY"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(prov.GetHMACKey()) != "super-secret-key" {
		t.Error("unexpected HMAC key value")
	}
	if prov.GetPrivateKey() != nil {
		t.Error("GetPrivateKey() should return nil for HMAC provider")
	}
	if prov.GetCertificate() != nil {
		t.Error("GetCertificate() should return nil for HMAC provider")
	}
}

func TestHMACProviderFromFile(t *testing.T) {
	f := writeTempFile(t, []byte("file-secret-key"))
	prov, err := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyFile: f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(prov.GetHMACKey()) != "file-secret-key" {
		t.Error("unexpected HMAC key value from file")
	}
}

func TestHMACProviderMissingEnv(t *testing.T) {
	os.Unsetenv("MISSING_HMAC_KEY")
	_, err := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "MISSING_HMAC_KEY"})
	if err == nil {
		t.Error("expected error for missing env var")
	}
}

func TestHMACProviderMissingFile(t *testing.T) {
	_, err := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyFile: "/no/such/file.key"})
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 sign + verify round-trip
// ---------------------------------------------------------------------------

func TestSignVerifyHMACSHA256(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-padded!")
	prov, _ := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "X"})
	// Override key directly via env
	t.Setenv("HMAC_TEST_KEY", string(secret))
	prov, _ = newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "HMAC_TEST_KEY"})

	p := &signingProcessor{
		config:       &Config{Algorithm: AlgorithmHMACSHA256},
		provider:     prov,
		hashFunc:     func() hash.Hash { return crypto.SHA256.New() },
		jwaAlgorithm: AlgorithmHMACSHA256,
		certRef:      "",
	}

	lr := plog.NewLogRecord()
	lr.SetEventName("user.login.success")
	lr.SetTimestamp(pcommon.Timestamp(1714041600000000000))
	lr.Attributes().PutStr("audit.actor.id", "u1")
	lr.Attributes().PutStr("audit.action", "LOGIN")

	if err := p.processLogRecord(lr); err != nil {
		t.Fatalf("processLogRecord: %v", err)
	}

	sigVal, ok := lr.Attributes().Get("audit.integrity.value")
	if !ok {
		t.Fatal("audit.integrity.value missing")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigVal.Str())
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	// Re-derive canonical payload and verify HMAC
	payload, err := p.serializeLogRecord(lr)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expected) {
		t.Error("HMAC verification failed: computed MAC does not match stored value")
	}
	t.Logf("✅ HMAC-SHA256 MAC verifies")
}

// ---------------------------------------------------------------------------
// ConsumeLogs — no audit.integrity.certificate for HMAC
// ---------------------------------------------------------------------------

func TestConsumeLogsHMACNoCertAttribute(t *testing.T) {
	t.Setenv("HMAC_NO_CERT_KEY", "secret")
	prov, _ := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "HMAC_NO_CERT_KEY"})
	sink := &logSink{}

	p := &signingProcessor{
		config:       &Config{Algorithm: AlgorithmHMACSHA256},
		provider:     prov,
		nextLogs:     sink,
		hashFunc:     func() hash.Hash { return crypto.SHA256.New() },
		jwaAlgorithm: AlgorithmHMACSHA256,
		certRef:      "", // HMAC: no cert ref
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.SetTimestamp(pcommon.Timestamp(1000))
	lr.Attributes().PutStr("audit.actor.id", "u1")

	if err := p.ConsumeLogs(context.Background(), ld); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}

	res := sink.logs[0].ResourceLogs().At(0).Resource().Attributes()

	// algorithm must be present
	algo, ok := res.Get("audit.integrity.algorithm")
	if !ok || algo.Str() != AlgorithmHMACSHA256 {
		t.Errorf("audit.integrity.algorithm: got %q, want %q", algo.Str(), AlgorithmHMACSHA256)
	}

	// certificate must NOT be present for HMAC
	if _, exists := res.Get("audit.integrity.certificate"); exists {
		t.Error("audit.integrity.certificate should not be set for HMAC-SHA256")
	}

	t.Logf("✅ HMAC ConsumeLogs: algorithm set, certificate absent")
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

func TestHMACTamperedPayloadDetected(t *testing.T) {
	t.Setenv("HMAC_TAMPER_KEY", "tamper-test-secret")
	prov, _ := newHMACKeyMaterialProvider(&HMACKeyConfig{KeyEnvVar: "HMAC_TAMPER_KEY"})

	p := &signingProcessor{
		config:       &Config{Algorithm: AlgorithmHMACSHA256},
		provider:     prov,
		hashFunc:     func() hash.Hash { return crypto.SHA256.New() },
		jwaAlgorithm: AlgorithmHMACSHA256,
	}

	lr := plog.NewLogRecord()
	lr.SetEventName("original.event")
	lr.SetTimestamp(pcommon.Timestamp(2000000))

	if err := p.processLogRecord(lr); err != nil {
		t.Fatalf("processLogRecord: %v", err)
	}

	sigVal, _ := lr.Attributes().Get("audit.integrity.value")
	storedMAC, _ := base64.StdEncoding.DecodeString(sigVal.Str())

	// Tamper: change EventName
	lr.SetEventName("tampered.event")
	tamperedPayload, _ := p.serializeLogRecord(lr)

	mac := hmac.New(sha256.New, []byte("tamper-test-secret"))
	mac.Write(tamperedPayload)
	newMAC := mac.Sum(nil)

	if hmac.Equal(storedMAC, newMAC) {
		t.Error("❌ tampered EventName did not change HMAC")
	} else {
		t.Logf("🔍 tampered EventName correctly produces different HMAC")
	}
}
