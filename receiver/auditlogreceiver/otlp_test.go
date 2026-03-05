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

func (m *mockConsumer) ConsumeLogs(_ context.Context, logs plog.Logs) error {
	m.logs = append(m.logs, logs)
	return nil
}

func (*mockConsumer) Capabilities() consumer.Capabilities {
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

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()

	r.handleAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-protobuf" {
		t.Errorf("Expected content type 'application/x-protobuf', got '%s'", contentType)
	}

	if len(mockConsumer.logs) == 0 {
		t.Error("Expected logs to be consumed")
	}

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

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()

	r.handleAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-protobuf" {
		t.Errorf("Expected content type 'application/x-protobuf', got '%s'", contentType)
	}

	responseData := w.Body.Bytes()
	otlpResp := plogotlp.NewExportResponse()
	if err := otlpResp.UnmarshalProto(responseData); err != nil {
		t.Errorf("Failed to unmarshal OTLP response: %v", err)
	}
}

func TestHandleOTLPProtobufInvalidData(t *testing.T) {
	mockConsumer := &mockConsumer{}

	cfg := &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, mockConsumer)
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader([]byte("invalid protobuf data")))
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
