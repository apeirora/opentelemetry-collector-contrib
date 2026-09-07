// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"
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

func buildVerifiedAuditLogs(t *testing.T, recordCount int) plog.Logs {
	t.Helper()
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Date(2026, 5, 18, 9, 35, 39, 0, time.UTC)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < recordCount; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
		lr.SetEventName("user.login")
		lr.Body().SetStr(`{"event":"user.login"}`)
		attrs := lr.Attributes()
		attrs.PutStr(auditAttrRecordID, fmt.Sprintf("rec-%d", i))
		attrs.PutStr(auditAttrActorID, "alice@example.com")
		attrs.PutStr(auditAttrAction, "login")
		attrs.PutStr(auditAttrOutcome, "success")
		attrs.PutStr(auditAttrSourceID, "testapp")

		canonical, err := jcsCanonicalAuditRecord(lr)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(canonical)
		attrs.PutStr(auditAttrIntegrityVal, hex.EncodeToString(mac.Sum(nil)))
	}
	return logs
}

func newTestProcessorWithFanOut(t *testing.T, sinks ...consumer.Logs) *certificateHashProcessor {
	t.Helper()
	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode: FailureModeStrict,
	}, newFanOutLogsConsumer(sinks...), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	return p
}

func TestPipelineSyncBatchFanOutAllSinks(t *testing.T) {
	t.Parallel()
	sinkA := &consumertest.LogsSink{}
	sinkB := &consumertest.LogsSink{}
	sinkC := &consumertest.LogsSink{}
	p := newTestProcessorWithFanOut(t, sinkA, sinkB, sinkC)

	logs := buildVerifiedAuditLogs(t, 4)
	if err := p.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	for i, sink := range []*consumertest.LogsSink{sinkA, sinkB, sinkC} {
		if len(sink.AllLogs()) != 1 {
			t.Fatalf("sink %d: expected 1 batch, got %d", i, len(sink.AllLogs()))
		}
		if sink.AllLogs()[0].LogRecordCount() != 4 {
			t.Fatalf("sink %d: expected 4 records, got %d", i, sink.AllLogs()[0].LogRecordCount())
		}
	}
}

func TestPipelineSyncFanOutOneSinkFails(t *testing.T) {
	t.Parallel()
	sinkA := &consumertest.LogsSink{}
	failing := &failingLogsConsumer{err: errors.New("primary sink down")}
	sinkC := &consumertest.LogsSink{}
	p := newTestProcessorWithFanOut(t, sinkA, failing, sinkC)

	logs := buildVerifiedAuditLogs(t, 1)
	err := p.ConsumeLogs(context.Background(), logs)
	if err == nil {
		t.Fatal("expected fan-out failure")
	}
	if len(sinkA.AllLogs()) != 1 {
		t.Fatalf("sink A should receive data, got %d batches", len(sinkA.AllLogs()))
	}
	if len(sinkC.AllLogs()) != 1 {
		t.Fatalf("sink C should still be invoked, got %d batches", len(sinkC.AllLogs()))
	}
}

func TestPipelineSyncFanOutRetryDuplicatesSuccessfulSink(t *testing.T) {
	t.Parallel()
	sinkA := &consumertest.LogsSink{}
	flaky := &failingLogsConsumer{err: errors.New("secondary sink down")}
	p := newTestProcessorWithFanOut(t, sinkA, flaky)

	if err := p.ConsumeLogs(context.Background(), buildVerifiedAuditLogs(t, 1)); err == nil {
		t.Fatal("expected first attempt to fail")
	}

	flaky.err = nil
	if err := p.ConsumeLogs(context.Background(), buildVerifiedAuditLogs(t, 1)); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if len(sinkA.AllLogs()) != 2 {
		t.Fatalf("successful sink duplicated on retry, got %d batches", len(sinkA.AllLogs()))
	}
}

func TestPipelineSyncVerifyFailureBlocksAllSinks(t *testing.T) {
	t.Parallel()
	sinkA := &consumertest.LogsSink{}
	sinkB := &consumertest.LogsSink{}
	p := newTestProcessorWithFanOut(t, sinkA, sinkB)

	logs := buildVerifiedAuditLogs(t, 1)
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	lr.Attributes().PutStr(auditAttrIntegrityVal, "deadbeef")

	err := p.ConsumeLogs(context.Background(), logs)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if !consumererror.IsPermanent(err) {
		t.Fatalf("expected permanent verify error, got %v", err)
	}
	if len(sinkA.AllLogs()) != 0 || len(sinkB.AllLogs()) != 0 {
		t.Fatalf("verify failure must block all sinks: A=%d B=%d", len(sinkA.AllLogs()), len(sinkB.AllLogs()))
	}
}

type failingLogsConsumer struct {
	err error
}

func (f *failingLogsConsumer) ConsumeLogs(context.Context, plog.Logs) error {
	return f.err
}

func (*failingLogsConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}
