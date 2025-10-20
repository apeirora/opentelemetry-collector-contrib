// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver"
)

type testConsumer struct {
	logger *zap.Logger
}

func (*testConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (tc *testConsumer) ConsumeLogs(_ context.Context, logs plog.Logs) error {
	tc.logger.Info("Received logs", zap.Int("count", logs.LogRecordCount()))
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		for j := 0; j < logs.ResourceLogs().At(i).ScopeLogs().Len(); j++ {
			for k := 0; k < logs.ResourceLogs().At(i).ScopeLogs().At(j).LogRecords().Len(); k++ {
				logRecord := logs.ResourceLogs().At(i).ScopeLogs().At(j).LogRecords().At(k)
				tc.logger.Info("Log received",
					zap.String("body", logRecord.Body().AsString()),
					zap.Any("timestamp", logRecord.Timestamp()))
			}
		}
	}
	return nil
}

func main() {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	// Create the receiver factory
	factory := auditlogreceiver.NewFactory()

	// Create config with specific endpoint
	cfg := factory.CreateDefaultConfig().(*auditlogreceiver.Config)
	cfg.Endpoint = "0.0.0.0:4310"

	// Create consumer
	consumer := &testConsumer{logger: logger}

	// Create receiver settings
	settings := receiver.Settings{
		ID:                component.NewID(factory.Type()),
		TelemetrySettings: component.TelemetrySettings{Logger: logger},
	}

	recv, err := auditlogreceiver.NewReceiver(cfg, settings, consumer)
	if err != nil {
		logger.Error("Failed to create receiver", zap.Error(err))
		_ = logger.Sync()
		os.Exit(1)
	}

	// Start the receiver
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = recv.Start(ctx, nil)
	if err != nil {
		logger.Error("Failed to start receiver", zap.Error(err))
		_ = logger.Sync()
		os.Exit(1)
	}

	logger.Info("Audit log receiver started successfully")
	logger.Info("You can now send POST requests to http://localhost:4310/v1/logs with JSON data")

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down...")

	err = recv.Shutdown(ctx)
	if err != nil {
		logger.Error("Failed to shutdown receiver", zap.Error(err))
		_ = logger.Sync()
		os.Exit(1)
	}
}
