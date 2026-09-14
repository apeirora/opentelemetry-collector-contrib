// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"encoding/json"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestSplitLogsByRecord(t *testing.T) {
	t.Parallel()

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "audit")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("audit-scope")
	for i := 0; i < 3; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr("record")
		lr.Attributes().PutStr(auditAttrRecordID, "rec-"+string(rune('a'+i)))
	}

	batches := splitLogsByRecord(logs)
	if len(batches) != 3 {
		t.Fatalf("expected 3 single-record batches, got %d", len(batches))
	}
	for i, batch := range batches {
		if batch.LogRecordCount() != 1 {
			t.Fatalf("batch %d: expected 1 record, got %d", i, batch.LogRecordCount())
		}
		if got := auditRecordIDFromLogs(batch, ""); got != "rec-"+string(rune('a'+i)) {
			t.Fatalf("batch %d: expected rec-%c, got %q", i, 'a'+i, got)
		}
	}
}

func TestPartialSuccessMessageIncludesIDs(t *testing.T) {
	t.Parallel()

	result := &syncDeliveryResult{
		accepted: 1,
		failedRecords: []failedAuditRecord{
			{ID: "rec-bad", Reason: "rejected_verify_failed: hmac mismatch"},
		},
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result.partialSuccessMessage()), &payload); err != nil {
		t.Fatalf("unmarshal partial success message: %v", err)
	}
	ids, ok := payload["rejected_record_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "rec-bad" {
		t.Fatalf("unexpected rejected_record_ids: %#v", payload["rejected_record_ids"])
	}
}

func TestAuditRecordIDFallbackTraceSpan(t *testing.T) {
	t.Parallel()

	lr := plog.NewLogRecord()
	lr.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3}))
	lr.SetSpanID(pcommon.SpanID([8]byte{4, 5, 6}))

	got := auditRecordID(lr)
	if got == "" {
		t.Fatal("expected trace/span fallback id")
	}
}
