// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

type fanOutLogsConsumer struct {
	sinks []consumer.Logs
}

func newFanOutLogsConsumer(sinks ...consumer.Logs) consumer.Logs {
	return &fanOutLogsConsumer{sinks: sinks}
}

func (f *fanOutLogsConsumer) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	var joined error
	for _, sink := range f.sinks {
		batch := plog.NewLogs()
		ld.CopyTo(batch)
		if err := sink.ConsumeLogs(ctx, batch); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func (*fanOutLogsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func testOTLPBatchRequest(t *testing.T, recordCount int, asJSON bool) []byte {
	t.Helper()
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	for i := 0; i < recordCount; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(fmt.Sprintf("audit-record-%d", i))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
	}
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	if asJSON {
		data, err := otlpReq.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal json: %v", err)
		}
		return data
	}
	data, err := otlpReq.MarshalProto()
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	return data
}

func postSyncOTLP(t *testing.T, r *auditLogReceiver, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, defaultPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	r.handleAuditLogs(w, req)
	return w
}

func TestSyncMultiRecordOTLPBatchProtobuf(t *testing.T) {
	t.Parallel()
	sink := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	body := testOTLPBatchRequest(t, 5, false)
	w := postSyncOTLP(t, r, body, "application/x-protobuf")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if len(sink.logs) != 1 {
		t.Fatalf("expected 1 consume call, got %d", len(sink.logs))
	}
	if sink.logs[0].LogRecordCount() != 5 {
		t.Fatalf("expected 5 records, got %d", sink.logs[0].LogRecordCount())
	}
}

func TestSyncMultiRecordOTLPBatchJSON(t *testing.T) {
	t.Parallel()
	sink := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	body := testOTLPBatchRequest(t, 3, true)
	w := postSyncOTLP(t, r, body, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if sink.logs[0].LogRecordCount() != 3 {
		t.Fatalf("expected 3 records, got %d", sink.logs[0].LogRecordCount())
	}
}

func TestSyncFanOutAllSinksSuccess(t *testing.T) {
	t.Parallel()
	sinkA := &mockConsumer{}
	sinkB := &mockConsumer{}
	sinkC := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), newFanOutLogsConsumer(sinkA, sinkB, sinkC), true)

	w := postSyncOTLP(t, r, testOTLPBatchRequest(t, 2, false), "application/x-protobuf")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	for i, sink := range []*mockConsumer{sinkA, sinkB, sinkC} {
		if len(sink.logs) != 1 {
			t.Fatalf("sink %d: expected 1 batch, got %d", i, len(sink.logs))
		}
		if sink.logs[0].LogRecordCount() != 2 {
			t.Fatalf("sink %d: expected 2 records, got %d", i, sink.logs[0].LogRecordCount())
		}
	}
}

func TestSyncFanOutOneSinkFailsReturnsError(t *testing.T) {
	t.Parallel()
	sinkA := &mockConsumer{}
	sinkB := &mockConsumer{err: errors.New("sink B unavailable")}
	sinkC := &mockConsumer{}
	r := newTestReceiver(t, testSyncConfig(), newFanOutLogsConsumer(sinkA, sinkB, sinkC), true)

	w := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", w.Code, w.Body.String())
	}
	if len(sinkA.logs) != 1 {
		t.Fatalf("sink A should have received data before fan-out error, got %d batches", len(sinkA.logs))
	}
	if len(sinkC.logs) != 1 {
		t.Fatalf("sink C is still invoked in fan-out, got %d batches", len(sinkC.logs))
	}

	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected WAL entry retained after transient failure, got %d keys", len(keys))
	}
}

func TestSyncFanOutRetryDuplicatesSuccessfulSink(t *testing.T) {
	t.Parallel()
	sinkA := &mockConsumer{}
	flakyB := &mockConsumer{err: errors.New("sink B down")}
	r := newTestReceiver(t, testSyncConfig(), newFanOutLogsConsumer(sinkA, flakyB), true)

	w1 := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w1.Code != http.StatusServiceUnavailable {
		t.Fatalf("first attempt: expected 503, got %d", w1.Code)
	}

	flakyB.err = nil
	w2 := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w2.Code != http.StatusOK {
		t.Fatalf("second attempt: expected 200, got %d", w2.Code)
	}
	if len(sinkA.logs) != 2 {
		t.Fatalf("sink A received duplicate delivery on client retry, got %d batches", len(sinkA.logs))
	}
	if len(flakyB.logs) != 1 {
		t.Fatalf("sink B only receives data once flaky sink recovers, got %d batches", len(flakyB.logs))
	}
}

func TestSyncPermanentFailureClearsWAL(t *testing.T) {
	t.Parallel()
	sink := &mockConsumer{
		err: consumererror.NewPermanent(errors.New("rejected_verify_failed: integrity mismatch")),
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	w := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("permanent failure should not retain WAL entry, got %d keys", len(keys))
	}
}

func TestSyncRecoverPendingAfterCrash(t *testing.T) {
	t.Parallel()
	sink := &mockConsumer{err: errors.New("pipeline down")}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	w := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 pending WAL entry, got %d", len(keys))
	}

	sink.err = nil
	r.recoverSyncPending()

	if len(sink.logs) != 1 {
		t.Fatalf("expected recovery delivery, got %d batches", len(sink.logs))
	}
	keys, err = r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected WAL drained after recovery, got %d keys", len(keys))
	}
}

func TestSyncCircuitBreakerOpenReturns503(t *testing.T) {
	t.Parallel()
	cfg := testSyncConfig()
	enabled := true
	cfg.CircuitBreaker.Enabled = &enabled
	cfg.CircuitBreaker.CircuitOpenThreshold = 1

	sink := &mockConsumer{}
	r := newTestReceiver(t, cfg, sink, true)
	r.circuitBreaker.RecordFailure()

	w := postSyncOTLP(t, r, testOTLPRequest(t), "application/x-protobuf")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("circuit open: expected 503, got %d body=%s", w.Code, w.Body.String())
	}
	if len(sink.logs) != 0 {
		t.Fatalf("circuit open must block delivery, consumer got %d batches", len(sink.logs))
	}
}
