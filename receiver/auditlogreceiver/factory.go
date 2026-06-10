// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver/internal/metadata"
)

// defaultPath is the Tier-2 audit ingest endpoint per the audit collector spec.
const defaultPath = "/v1/audit"

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	circuitEnabled := true
	return &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
		Path:         defaultPath,
		ResponseMode: defaultResponseMode,
		Delivery: DeliveryConfig{
			InitialInterval: defaultDeliveryInitial,
			MaxInterval:     defaultDeliveryMax,
		},
		CircuitBreaker: CircuitBreakerConfig{
			Enabled: &circuitEnabled,
		},
	}
}

func createLogsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	return NewReceiver(cfg.(*Config), set, consumer)
}
