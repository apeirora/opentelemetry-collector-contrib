// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSupportedIntegrityAlgorithms(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{algoHMACSHA256, algoHMACSHA512}, supportedIntegrityAlgorithms(true, false))
	assert.Equal(t, []string{algoECDSAP256SHA256, algoRSAPKCS1SHA256}, supportedIntegrityAlgorithms(false, true))
	assert.Equal(t,
		[]string{algoHMACSHA256, algoHMACSHA512, algoECDSAP256SHA256, algoRSAPKCS1SHA256},
		supportedIntegrityAlgorithms(true, true),
	)
}

func TestStartupLoadsBothKeySources(t *testing.T) {
	t.Parallel()
	core, observed := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cfg := &Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		CertFile:    filepath.Join("k8s", "certificates", "cert.pem"),
	}
	hmacKey, cert, err := loadSyncVerificationKeys(cfg, logger)
	require.NoError(t, err)
	require.NotEmpty(t, hmacKey)
	require.NotNil(t, cert)

	entries := observed.FilterMessage("Audit integrity verification ready").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, true, fields["hmac_key_loaded"])
	assert.Equal(t, true, fields["certificate_loaded"])
}

func TestStartupWarnsWhenOnlyHMACConfigured(t *testing.T) {
	t.Parallel()
	_, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	require.NoError(t, err)
}

func TestStartupFailsOnMissingHMACFile(t *testing.T) {
	t.Parallel()
	_, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: "testdata/does-not-exist.txt",
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	require.Error(t, err)
}
