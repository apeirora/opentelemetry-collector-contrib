// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"
)

func TestDeadLetterStoresFailedRecord(t *testing.T) {
	storage := newMapStorageClient()
	dlq := newDeadLetterStore(DeadLetterConfig{
		Enabled:   true,
		KeyPrefix: "dlq/",
	}, storage, zap.NewNop())

	resource := pcommon.NewResource()
	resource.Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
	lr := plog.NewLogRecord()
	lr.Attributes().PutStr(auditAttrRecordID, "rec-dlq-1")
	lr.Attributes().PutStr(auditAttrSourceID, "stream-a")

	err := dlq.store(context.Background(), resource, lr, "integrity_mismatch", errTestIntegrityMismatch, FailureModeStrict, "default")
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	var data []byte
	for key, value := range storage.data {
		if strings.HasPrefix(key, "dlq/") {
			data = value
			break
		}
	}
	if data == nil {
		t.Fatal("expected dead letter entry with dlq/ prefix")
	}

	var entry deadLetterEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if entry.VerifyReason != "integrity_mismatch" {
		t.Fatalf("verify_reason = %q", entry.VerifyReason)
	}
	if entry.AuditRecordID != "rec-dlq-1" {
		t.Fatalf("audit_record_id = %q", entry.AuditRecordID)
	}
	if entry.Record == nil || entry.Resource == nil {
		t.Fatal("expected record and resource payloads")
	}
}

func TestDeadLetterReasonFilter(t *testing.T) {
	storage := newMapStorageClient()
	dlq := newDeadLetterStore(DeadLetterConfig{
		Enabled: true,
		Reasons: []string{"integrity_mismatch"},
	}, storage, zap.NewNop())

	resource := pcommon.NewResource()
	lr := plog.NewLogRecord()
	lr.Attributes().PutStr(auditAttrRecordID, "rec-1")

	if err := dlq.store(context.Background(), resource, lr, "missing_integrity_value", errTestMissingIntegrity, FailureModeStrict, "default"); err != nil {
		t.Fatalf("store: %v", err)
	}
	if len(storage.data) != 0 {
		t.Fatal("expected no dead letter entry for filtered reason")
	}

	if err := dlq.store(context.Background(), resource, lr, "integrity_mismatch", errTestIntegrityMismatch, FailureModeStrict, "default"); err != nil {
		t.Fatalf("store: %v", err)
	}
	if len(storage.data) != 1 {
		t.Fatal("expected dead letter entry")
	}
}

func TestDeadLetterPartitionByStream(t *testing.T) {
	storage := newMapStorageClient()
	dlq := newDeadLetterStore(DeadLetterConfig{
		Enabled:           true,
		PartitionByStream: true,
	}, storage, zap.NewNop())

	resource := pcommon.NewResource()
	lr := plog.NewLogRecord()
	lr.Attributes().PutStr(auditAttrRecordID, "rec-1")
	lr.Attributes().PutStr(auditAttrSourceID, "stream-1")

	if err := dlq.store(context.Background(), resource, lr, "integrity_mismatch", errTestIntegrityMismatch, FailureModeStrict, "default"); err != nil {
		t.Fatalf("store: %v", err)
	}
	found := false
	for key := range storage.data {
		if strings.HasPrefix(key, "dead_letter/stream-1/") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stream-partitioned dead letter key")
	}
}

func TestConsumeLogsWritesDeadLetterOnFailure(t *testing.T) {
	storage := newMapStorageClient()
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().UTC()))
	lr.Attributes().PutStr(auditAttrRecordID, "rec-fail")
	lr.Attributes().PutStr(auditAttrIntegrityVal, "deadbeef")

	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode: FailureModeMark,
		DeadLetter: DeadLetterConfig{
			Enabled: true,
		},
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.deadLetter = newDeadLetterStore(DeadLetterConfig{Enabled: true}, storage, zap.NewNop())

	sink := &consumertest.LogsSink{}
	p.nextLogs = sink
	if err := p.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	if len(storage.data) != 1 {
		t.Fatalf("expected 1 dead letter entry, got %d", len(storage.data))
	}
	if sink.AllLogs()[0].LogRecordCount() != 1 {
		t.Fatal("expected failed record to continue in mark mode")
	}
}

var (
	errTestIntegrityMismatch = errStringValue("integrity mismatch")
	errTestMissingIntegrity  = errStringValue("missing integrity")
)

type errStringValue string

func (e errStringValue) Error() string {
	return string(e)
}
