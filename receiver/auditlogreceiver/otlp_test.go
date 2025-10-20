// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver/internal/metadata"
)

type mockConsumer struct {
	logs []plog.Logs
}

func (m *mockConsumer) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	m.logs = append(m.logs, logs)
	return nil
}

func (m *mockConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func TestHandleOTLPProtobuf(t *testing.T) {
	// Create a mock consumer
	mockConsumer := &mockConsumer{}

	// Create receiver config
	cfg := &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
	}

	// Create receiver
	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, mockConsumer)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	// Create OTLP logs
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.Body().SetStr("test audit log")
	logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord.SetSeverityText("INFO")

	// Create OTLP request
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		t.Fatalf("Failed to marshal OTLP request: %v", err)
	}

	// Create HTTP request
	req := httptest.NewRequest("POST", "/v1/logs", bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle the request
	r.handleAuditLogs(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-protobuf" {
		t.Errorf("Expected content type 'application/x-protobuf', got '%s'", contentType)
	}

	// Check that logs were consumed
	if len(mockConsumer.logs) == 0 {
		t.Error("Expected logs to be consumed")
	}

	// Verify the response is valid OTLP protobuf
	responseData := w.Body.Bytes()
	otlpResp := plogotlp.NewExportResponse()
	if err := otlpResp.UnmarshalProto(responseData); err != nil {
		t.Errorf("Failed to unmarshal OTLP response: %v", err)
	}
}

func TestHandleOTLPProtobufEmptyLogs(t *testing.T) {
	// Create a mock consumer
	mockConsumer := &mockConsumer{}

	// Create receiver config
	cfg := &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
	}

	// Create receiver
	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, mockConsumer)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	// Create empty OTLP logs
	logs := plog.NewLogs()
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		t.Fatalf("Failed to marshal OTLP request: %v", err)
	}

	// Create HTTP request
	req := httptest.NewRequest("POST", "/v1/logs", bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle the request
	r.handleAuditLogs(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-protobuf" {
		t.Errorf("Expected content type 'application/x-protobuf', got '%s'", contentType)
	}

	// Verify the response is valid OTLP protobuf
	responseData := w.Body.Bytes()
	otlpResp := plogotlp.NewExportResponse()
	if err := otlpResp.UnmarshalProto(responseData); err != nil {
		t.Errorf("Failed to unmarshal OTLP response: %v", err)
	}
}

func TestHandleOTLPProtobufInvalidData(t *testing.T) {
	// Create a mock consumer
	mockConsumer := &mockConsumer{}

	// Create receiver config
	cfg := &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
	}

	// Create receiver
	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, mockConsumer)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	// Create HTTP request with invalid protobuf data
	req := httptest.NewRequest("POST", "/v1/logs", bytes.NewReader([]byte("invalid protobuf data")))
	req.Header.Set("Content-Type", "application/x-protobuf")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle the request
	r.handleAuditLogs(w, req)

	// Check response
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}
