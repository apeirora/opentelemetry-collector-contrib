// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redisstorageextension

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/confmap/xconfmap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/redisstorageextension/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id       component.ID
		expected component.Config
	}{
		{
			id: component.NewID(metadata.Type),
			expected: func() component.Config {
				ret := NewFactory().CreateDefaultConfig()
				ret.(*Config).Endpoint = "localhost:1234"
				return ret
			}(),
		},
		{
			id: component.NewIDWithName(metadata.Type, "all_settings"),
			expected: func() component.Config {
				cfg := createDefaultConfig().(*Config)
				cfg.Endpoint = "localhost:1234"
				cfg.Password = "passwd"
				cfg.DB = 1
				cfg.Expiration = 3 * time.Hour
				cfg.Prefix = "test_"
				cfg.TLS = configtls.ClientConfig{Insecure: true}
				return cfg
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
			require.NoError(t, err)
			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()
			sub, err := cm.Sub(tt.id.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(&cfg))

			assert.NoError(t, xconfmap.Validate(cfg))
			assert.Equal(t, tt.expected, cfg)
		})
	}
}
