// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver"
)

var errCounter = 0

type testConsumer struct {
	logger *zap.Logger
}

func (*testConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (tc *testConsumer) ConsumeLogs(_ context.Context, logs plog.Logs) error {
	tc.logger.Info("ErrCounter:%v", zap.Int("errCounter", errCounter))
	if errCounter < 10 {
		errCounter++
		return errors.New("test error")
	}
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

	// Clean up any existing storage directory to avoid corruption issues
	storageDir := "./auditlog_storage"
	if _, err := os.Stat(storageDir); err == nil {
		logger.Info("Removing existing storage directory to avoid corruption")
		if err := os.RemoveAll(storageDir); err != nil {
			logger.Warn("Failed to remove existing storage directory", zap.Error(err))
		}
	}

	// Create file storage extension
	storageFactory := filestorage.NewFactory()
	storageCfg := storageFactory.CreateDefaultConfig().(*filestorage.Config)
	storageCfg.Directory = storageDir
	storageCfg.CreateDirectory = true

	ctx := context.Background()
	storageExt, err := storageFactory.Create(ctx, extension.Settings{
		ID:                component.NewID(component.MustNewType("file_storage")),
		TelemetrySettings: component.TelemetrySettings{Logger: logger},
	}, storageCfg)
	if err != nil {
		_ = logger.Sync()
		log.Fatalf("Failed to create storage extension: %v", err)
	}

	if startErr := storageExt.Start(context.Background(), nil); startErr != nil {
		log.Fatalf("Failed to start storage extension: %v", startErr)
	}

	// Test file storage connection with timeout
	logger.Info("Testing file storage connection...")
	storageExtTyped, ok := storageExt.(storage.Extension)
	if !ok {
		log.Fatalf("Storage extension does not implement storage.Extension")
	}

	// Create a timeout context for storage operations
	storageCtx, storageCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer storageCancel()

	testClient, err := storageExtTyped.GetClient(storageCtx, component.KindReceiver, component.NewID(component.MustNewType("file_storage")), "test")
	if err != nil {
		log.Fatalf("Failed to get file storage test client: %v", err)
	}

	testKey := "connection_test"
	testValue := []byte("test_value")
	if setErr := testClient.Set(storageCtx, testKey, testValue); setErr != nil {
		log.Fatalf("Failed to set test value in file storage: %v", setErr)
	}

	retrievedValue, getErr := testClient.Get(storageCtx, testKey)
	if getErr != nil {
		log.Fatalf("Failed to get test value from file storage: %v", getErr)
	}

	if !bytes.Equal(retrievedValue, testValue) {
		log.Fatalf("File storage test failed: expected %s, got %s", string(testValue), string(retrievedValue))
	}

	if deleteErr := testClient.Delete(storageCtx, testKey); deleteErr != nil {
		logger.Warn("Failed to clean up test data", zap.Error(deleteErr))
	}

	logger.Info("File storage connection test successful!")

	// Create the receiver factory
	factory := auditlogreceiver.NewFactory()

	// Create config with specific endpoint and storage
	cfg := factory.CreateDefaultConfig().(*auditlogreceiver.Config)
	cfg.Endpoint = "0.0.0.0:4310"
	cfg.StorageID = component.NewID(component.MustNewType("file_storage"))

	// Create consumer
	consumer := &testConsumer{logger: logger}

	// Create receiver settings with proper telemetry
	settings := receiver.Settings{
		ID:                component.NewID(factory.Type()),
		TelemetrySettings: componenttest.NewNopTelemetrySettings(),
	}

	// Create the receiver directly using the internal function
	recv, err := auditlogreceiver.NewReceiver(cfg, settings, consumer)
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
	}

	// Create a simple host that provides the storage extension
	host := &simpleHost{
		Host:       componenttest.NewNopHost(),
		storageExt: storageExt,
	}

	// Start the receiver
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = recv.Start(ctx, host)
	if err != nil {
		log.Fatalf("Failed to start receiver: %v", err)
	}

	logger.Info("Audit log receiver started successfully with file storage")
	logger.Info("You can now send POST requests to http://localhost:4310/v1/logs with JSON data")

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down...")

	// Shutdown the receiver
	err = recv.Shutdown(ctx)
	if err != nil {
		log.Fatalf("Failed to shutdown receiver: %v", err)
	}

	// Shutdown storage extension
	if err := storageExt.Shutdown(ctx); err != nil {
		log.Fatalf("Failed to shutdown storage extension: %v", err)
	}
}

// simpleHost extends componenttest.NewNopHost() to provide storage extension
type simpleHost struct {
	component.Host
	storageExt extension.Extension
}

func (h *simpleHost) GetExtensions() map[component.ID]component.Component {
	return map[component.ID]component.Component{
		component.NewID(component.MustNewType("file_storage")): h.storageExt,
	}
}
