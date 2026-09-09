// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"

)

func TestVerifyIntegrityHMACSHA256(t *testing.T) {
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	body := `{"event":"user.login","id":"rec-test","n":0}`

	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.Body().SetStr(body)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-test")
	attrs.PutStr("base", "testapp")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutStr(auditAttrSourceID, "testapp")
	attrs.PutStr(auditAttrSchemaVersion, "1.0")

	canonical, err := jcsCanonicalAuditRecord(lr)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	attrs.PutStr(auditAttrIntegrityVal, hex.EncodeToString(mac.Sum(nil)))

	resource := pcommon.NewResource()
	resource.Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)

	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode: FailureModeStrict,
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}

	if reason, err := p.verifyAuditLogRecord(resource, lr); err != nil {
		t.Fatalf("verifyAuditLogRecord (%s): %v", reason, err)
	}
}

func TestDecodeHexOrBase64(t *testing.T) {
	t.Parallel()
	hexBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := decodeHexOrBase64(hex.EncodeToString(hexBytes))
	require.NoError(t, err)
	assert.Equal(t, hexBytes, got)

	b64 := base64.StdEncoding.EncodeToString(hexBytes)
	got, err = decodeHexOrBase64(b64)
	require.NoError(t, err)
	assert.Equal(t, hexBytes, got)

	_, err = decodeHexOrBase64("not-valid-encoding!!!")
	require.Error(t, err)
}

func TestVerifyIntegrityHMACSHA256_Base64(t *testing.T) {
	t.Parallel()
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	body := `{"event":"user.login","id":"rec-test-b64","n":0}`

	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.Body().SetStr(body)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-test-b64")
	attrs.PutStr("base", "testapp")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutStr(auditAttrSourceID, "testapp")
	attrs.PutStr(auditAttrSchemaVersion, "1.0")

	canonical, err := jcsCanonicalAuditRecord(lr)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	attrs.PutStr(auditAttrIntegrityVal, base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	resource := pcommon.NewResource()
	resource.Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)

	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode: FailureModeStrict,
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	require.NoError(t, err)

	reason, err := p.verifyAuditLogRecord(resource, lr)
	require.NoError(t, err, "reason=%s", reason)
	assert.Equal(t, reasonOK, reason)
}

func TestConsumeLogsAuditRecordPasses(t *testing.T) {
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Now().UTC().Truncate(time.Nanosecond)
	body := `{"event":"user.login","id":"rec-consume","n":0}`

	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.Body().SetStr(body)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-consume")
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

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
	sl := rl.ScopeLogs().AppendEmpty()
	lr.CopyTo(sl.LogRecords().AppendEmpty())

	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode: FailureModeStrict,
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}

	sink := &consumertest.LogsSink{}
	p.nextLogs = sink
	if err := p.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	if len(sink.AllLogs()) != 1 || sink.AllLogs()[0].LogRecordCount() != 1 {
		t.Fatalf("expected 1 exported log record, got %d batches", len(sink.AllLogs()))
	}
}

func TestHashChainValidation(t *testing.T) {
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Date(2026, 5, 18, 9, 35, 39, 0, time.UTC)

	buildRecord := func(recordID string, seq int64, prevHash string) (pcommon.Resource, plog.LogRecord) {
		lr := plog.NewLogRecord()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
		lr.SetEventName("user.login")
		lr.Body().SetStr(`{"event":"user.login"}`)
		attrs := lr.Attributes()
		attrs.PutStr(auditAttrRecordID, recordID)
		attrs.PutStr(auditAttrSourceID, "stream-1")
		attrs.PutInt(auditAttrSequenceNo, seq)
		if prevHash != "" {
			attrs.PutStr(auditAttrPrevHash, prevHash)
		}

		canonical, err := jcsCanonicalAuditRecord(lr)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(canonical)
		attrs.PutStr(auditAttrIntegrityVal, hex.EncodeToString(mac.Sum(nil)))

		resource := pcommon.NewResource()
		resource.Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
		return resource, lr
	}

	storage := newMapStorageClient()
	p, err := newProcessor(&Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
	}, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	if err != nil {
		t.Fatalf("newProcessor: %v", err)
	}
	p.hashChain = newHashChainStore(storage)

	resource1, lr1 := buildRecord("rec-1", 1, "")
	if reason, err := p.verifyAuditLogRecord(resource1, lr1); err != nil {
		t.Fatalf("first record (%s): %v", reason, err)
	}
	hash1, err := integrityHashHex(lr1)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.hashChain.commit("stream-1", lr1, hash1); err != nil {
		t.Fatal(err)
	}

	resource2, lr2 := buildRecord("rec-2", 2, hash1)
	if reason, err := p.verifyAuditLogRecord(resource2, lr2); err != nil {
		t.Fatalf("second record (%s): %v", reason, err)
	}

	hash2, err := integrityHashHex(lr2)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.hashChain.commit("stream-1", lr2, hash2); err != nil {
		t.Fatal(err)
	}

	_, lr3 := buildRecord("rec-3", 2, hash2)
	if reason, err := p.verifyAuditLogRecord(resource2, lr3); err == nil || reason != "sequence_not_increasing" {
		t.Fatalf("expected sequence_not_increasing, got reason=%q err=%v", reason, err)
	}
}
