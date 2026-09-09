// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redisstorageextension

import (
	"errors"
	"testing"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestFactory(t *testing.T) {
	f := NewFactory()

	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "Default",
			config: func() *Config {
				cfg := createDefaultConfig().(*Config)
				cfg.Endpoint = "localhost:6379"
				cfg.TLS = configtls.ClientConfig{
					Insecure: true,
				}
				return cfg
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prev := newRedisClient
			t.Cleanup(func() { newRedisClient = prev })

			mockedClient, mock := redismock.NewClientMock()
			mock.ExpectPing().SetVal("PONG")
			t.Cleanup(func() {
				if err := mockedClient.Close(); err != nil && !errors.Is(err, redis.ErrClosed) {
					require.NoError(t, err)
				}
			})
			newRedisClient = func(opt *redis.Options) *redis.Client {
				return mockedClient
			}

			e, err := f.Create(
				t.Context(),
				extensiontest.NewNopSettings(f.Type()),
				test.config,
			)
			require.NoError(t, err)
			require.NotNil(t, e)
			ctx := t.Context()
			require.NoError(t, e.Start(ctx, componenttest.NewNopHost()))
			require.NoError(t, e.Shutdown(ctx))
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
