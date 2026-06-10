// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver/internal/metadata"
)

type mockConsumer struct {
	logs []plog.Logs
	err  error
}

func (m *mockConsumer) ConsumeLogs(_ context.Context, logs plog.Logs) error {
	if m.err != nil {
		return m.err
	}
	copied := plog.NewLogs()
	logs.CopyTo(copied)
	m.logs = append(m.logs, copied)
	return nil
}

func (*mockConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func testSyncConfig() *Config {
	return &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: ResponseModeSync,
	}
}

func testAsyncConfig() *Config {
	return &Config{
		ServerConfig: confighttp.NewDefaultServerConfig(),
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: ResponseModeAsync,
		Delivery: DeliveryConfig{
			InitialInterval: time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
		},
		ProcessInterval:     time.Millisecond,
		ProcessAgeThreshold: 0,
	}
}

func newTestReceiver(t *testing.T, cfg *Config, consumer consumer.Logs, withStorage bool) *auditLogReceiver {
	t.Helper()
	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, consumer)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	if withStorage {
		r.storage = newMapStorageClient()
	}
	return r
}

func testOTLPRequest(t *testing.T) []byte {
	t.Helper()
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test audit log")
	lr.SetSeverityNumber(plog.SeverityNumberInfo)

	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return requestData
}

func TestHandleOTLPSyncDelivery(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), mockConsumer, true)

	requestData := testOTLPRequest(t)
	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	r.handleAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if len(mockConsumer.logs) != 1 {
		t.Fatalf("expected 1 consumed batch, got %d", len(mockConsumer.logs))
	}
}

func TestHandleOTLPAsyncAccepted(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testAsyncConfig(), mockConsumer, true)

	requestData := testOTLPRequest(t)
	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	r.handleAuditLogs(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", w.Code, w.Body.String())
	}
	if len(mockConsumer.logs) != 0 {
		t.Fatal("async accept must not consume synchronously")
	}

	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 pending key, got %d", len(keys))
	}
}

func TestHandleOTLPAsyncWorkerDelivers(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testAsyncConfig(), mockConsumer, true)

	requestData := testOTLPRequest(t)
	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	r.handleAuditLogs(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}

	r.processPendingLogs()

	if len(mockConsumer.logs) != 1 {
		t.Fatalf("expected worker delivery, got %d batches", len(mockConsumer.logs))
	}
	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected pending queue drained, got %d", len(keys))
	}
}

func TestHandleOTLPProtobufEmptyLogs(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), mockConsumer, true)

	logs := plog.NewLogs()
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	r.handleAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleOTLPProtobufInvalidData(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), mockConsumer, true)

	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader([]byte("invalid protobuf data")))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	r.handleAuditLogs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestNewReceiverRequiresStorage(t *testing.T) {
	t.Parallel()
	cfg := &Config{ResponseMode: ResponseModeSync}
	_, err := NewReceiver(cfg, receivertest.NewNopSettings(metadata.Type), &mockConsumer{})
	if err == nil {
		t.Fatal("expected validation error without storage")
	}
}

func TestSyncDeliveryClearsPending(t *testing.T) {
	t.Parallel()
	mockConsumer := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), mockConsumer, true)

	requestData := testOTLPRequest(t)
	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(requestData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	r.handleAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected pending queue drained after sync delivery, got %d", len(keys))
	}
}
