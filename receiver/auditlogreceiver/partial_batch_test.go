// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

func acceptedRecordIDs(sink *selectiveFailConsumer) []string {
	ids := make([]string, 0, len(sink.logs))
	for _, batch := range sink.logs {
		ids = append(ids, auditRecordIDFromLogs(batch, ""))
	}
	return ids
}

func parseRejectedRecordIDs(t *testing.T, errorMessage string) []string {
	t.Helper()
	var payload struct {
		RejectedRecordIDs []string `json:"rejected_record_ids"`
	}
	if err := json.Unmarshal([]byte(errorMessage), &payload); err != nil {
		t.Fatalf("unmarshal partial success error message: %v", err)
	}
	return payload.RejectedRecordIDs
}

func TestDeliverLogsByRecordPartialSuccess(t *testing.T) {
	t.Parallel()

	sink := &selectiveFailConsumer{
		failBodies: map[string]error{
			"bad": consumererror.NewPermanent(errors.New("rejected_verify_failed: integrity mismatch")),
		},
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	logs := plog.NewLogs()
	sl := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, id := range []string{"good-1", "bad", "good-2"} {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(id)
		lr.Attributes().PutStr(auditAttrRecordID, id)
	}

	result, err := r.deliverLogsByRecord(context.Background(), logs)
	if err != nil {
		t.Fatalf("deliverLogsByRecord: %v", err)
	}
	if result.accepted != 2 {
		t.Fatalf("expected 2 accepted, got %d", result.accepted)
	}
	if result.rejectedCount() != 1 {
		t.Fatalf("expected 1 rejected, got %d", result.rejectedCount())
	}
	if got := parseRejectedRecordIDs(t, result.partialSuccessMessage()); len(got) != 1 || got[0] != "bad" {
		t.Fatalf("unexpected rejected ids: %v", got)
	}
}

func TestSyncPartialBatchMultipleRejectedRecords(t *testing.T) {
	t.Parallel()

	sink := &selectiveFailConsumer{
		failBodies: map[string]error{
			"bad-1": consumererror.NewPermanent(errors.New("rejected_verify_failed: bad hmac")),
			"bad-2": consumererror.NewPermanent(errors.New("rejected_verify_failed: bad cert")),
		},
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	body := testOTLPBatchRequestWithIDs(t, []string{"good-1", "bad-1", "good-2", "bad-2"}, false)
	w := postSyncOTLP(t, r, body, "application/x-protobuf")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	resp := plogotlp.NewExportResponse()
	if err := resp.UnmarshalProto(w.Body.Bytes()); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	partial := resp.PartialSuccess()
	if partial.RejectedLogRecords() != 2 {
		t.Fatalf("expected 2 rejected records, got %d", partial.RejectedLogRecords())
	}

	rejected := parseRejectedRecordIDs(t, partial.ErrorMessage())
	wantRejected := []string{"bad-1", "bad-2"}
	if len(rejected) != len(wantRejected) {
		t.Fatalf("expected rejected ids %v, got %v", wantRejected, rejected)
	}
	for _, id := range wantRejected {
		if !slices.Contains(rejected, id) {
			t.Fatalf("missing rejected id %q in %v", id, rejected)
		}
	}

	gotAccepted := acceptedRecordIDs(sink)
	wantAccepted := []string{"good-1", "good-2"}
	if len(gotAccepted) != len(wantAccepted) {
		t.Fatalf("expected accepted ids %v, got %v", wantAccepted, gotAccepted)
	}
	for _, id := range wantAccepted {
		if !slices.Contains(gotAccepted, id) {
			t.Fatalf("missing accepted id %q in %v", id, gotAccepted)
		}
	}
}

func TestSyncPartialBatchLegacyRecordIDInResponse(t *testing.T) {
	t.Parallel()

	sink := &selectiveFailConsumer{
		failBodies: map[string]error{
			"bad-body": consumererror.NewPermanent(errors.New("rejected_verify_failed: malformed")),
		},
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	logs := plog.NewLogs()
	sl := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	good := sl.LogRecords().AppendEmpty()
	good.Body().SetStr("good-body")
	good.Attributes().PutStr(auditAttrRecordIDLegacy, "legacy-good-id")
	bad := sl.LogRecords().AppendEmpty()
	bad.Body().SetStr("bad-body")
	bad.Attributes().PutStr(auditAttrRecordIDLegacy, "legacy-bad-id")

	body, err := plogotlp.NewExportRequestFromLogs(logs).MarshalProto()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	w := postSyncOTLP(t, r, body, "application/x-protobuf")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	resp := plogotlp.NewExportResponse()
	if err := resp.UnmarshalProto(w.Body.Bytes()); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	rejected := parseRejectedRecordIDs(t, resp.PartialSuccess().ErrorMessage())
	if len(rejected) != 1 || rejected[0] != "legacy-bad-id" {
		t.Fatalf("expected legacy-bad-id in rejected ids, got %v", rejected)
	}
	if got := acceptedRecordIDs(sink); len(got) != 1 || got[0] != "legacy-good-id" {
		t.Fatalf("expected legacy-good-id accepted, got %v", got)
	}
}

func TestSyncPartialBatchAllRejectedReturns400(t *testing.T) {
	t.Parallel()

	sink := &selectiveFailConsumer{
		failBodies: map[string]error{
			"bad-1": consumererror.NewPermanent(errors.New("rejected_verify_failed: bad hmac")),
			"bad-2": consumererror.NewPermanent(errors.New("rejected_verify_failed: bad cert")),
		},
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	body := testOTLPBatchRequestWithIDs(t, []string{"bad-1", "bad-2"}, false)
	w := postSyncOTLP(t, r, body, "application/x-protobuf")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when all records rejected, got %d body=%s", w.Code, w.Body.String())
	}
	if len(sink.logs) != 0 {
		t.Fatalf("expected no accepted deliveries, got %d", len(sink.logs))
	}
	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("all rejected should clear WAL, got %d keys", len(keys))
	}
}

func TestSyncPartialBatchTransientFailureRetainsWAL(t *testing.T) {
	t.Parallel()

	sink := &selectiveFailConsumer{
		failBodies: map[string]error{
			"bad":    consumererror.NewPermanent(errors.New("rejected_verify_failed: integrity mismatch")),
			"flaky":  errors.New("exporter unavailable"),
		},
	}
	r := newTestReceiver(t, testSyncConfig(), sink, true)

	body := testOTLPBatchRequestWithIDs(t, []string{"good-1", "bad", "flaky"}, false)
	w := postSyncOTLP(t, r, body, "application/x-protobuf")

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on transient failure, got %d body=%s", w.Code, w.Body.String())
	}
	if len(sink.logs) != 1 {
		t.Fatalf("expected 1 record delivered before transient failure, got %d", len(sink.logs))
	}
	if got := acceptedRecordIDs(sink); len(got) != 1 || got[0] != "good-1" {
		t.Fatalf("expected good-1 delivered before failure, got %v", got)
	}

	keys, err := r.getPendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("transient failure should retain WAL for retry, got %d keys", len(keys))
	}
}
