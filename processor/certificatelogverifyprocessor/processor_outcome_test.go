// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

func buildSignedHMACRecord(t *testing.T, recordID string) plog.Logs {
	t.Helper()
	key := []byte("testapp-dev-hmac-key-change-in-production")
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)

	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.Body().SetStr(`{"event":"user.login"}`)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, recordID)
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutStr(auditAttrSourceID, "testapp")

	canonical, err := jcsCanonicalAuditRecord(lr)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	attrs.PutStr(auditAttrIntegrityVal, hex.EncodeToString(mac.Sum(nil)))

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr(auditIntegrityAlgorithmKey, algoHMACSHA256)
	sl := rl.ScopeLogs().AppendEmpty()
	lr.CopyTo(sl.LogRecords().AppendEmpty())
	return logs
}

func newTestProcessor(t *testing.T, cfg *Config) *certificateHashProcessor {
	t.Helper()
	p, err := newProcessor(cfg, consumertest.NewNop(), processortest.NewNopSettings(component.MustNewType("certificatelogverify")))
	require.NoError(t, err)
	return p
}

func TestMarkPassedSetsOutcomeAttributes(t *testing.T) {
	t.Parallel()
	logs := buildSignedHMACRecord(t, "rec-outcome-pass")
	sink := &consumertest.LogsSink{}
	p := newTestProcessor(t, &Config{
		Mode:                ModeSync,
		HmacKeyFile:         filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode:         FailureModeStrict,
		VerificationProfile: "tier2-prod",
	})
	p.nextLogs = sink

	require.NoError(t, p.ConsumeLogs(context.Background(), logs))
	require.Len(t, sink.AllLogs(), 1)

	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := lr.Attributes()
	status, _ := attrs.Get(verifyStatusKey)
	assert.Equal(t, status.Str(), statusPassed)
	reason, _ := attrs.Get(verifyReasonKey)
	assert.Equal(t, reason.Str(), reasonOK)
	verifiedAt, ok := attrs.Get(verifiedAtKey)
	require.True(t, ok)
	assert.NotEmpty(t, verifiedAt.Str())
	profile, _ := attrs.Get(verificationProfileKey)
	assert.Equal(t, profile.Str(), "tier2-prod")
	tier2, _ := attrs.Get(tier2StatusKey)
	assert.Equal(t, tier2.Str(), tier2VerifiedQueued)
	export, _ := attrs.Get(exportStatusKey)
	assert.Equal(t, export.Str(), tier2VerifiedQueued)
	changed, ok := attrs.Get(lastStateChangeAtKey)
	require.True(t, ok)
	assert.NotEmpty(t, changed.Str())
	_, hasDetails := attrs.Get(verifyDetailsKey)
	assert.False(t, hasDetails)
}

func TestVerifyIgnoresPreStampedOutcomeAttributes(t *testing.T) {
	t.Parallel()
	logs := buildSignedHMACRecord(t, "rec-prestamped")
	rl := logs.ResourceLogs().At(0)
	lr := rl.ScopeLogs().At(0).LogRecords().At(0)
	attrs := lr.Attributes()
	attrs.PutStr(verifyStatusKey, statusPassed)
	attrs.PutStr(verifyReasonKey, reasonOK)
	attrs.PutStr(verifiedAtKey, "2020-01-01T00:00:00Z")
	attrs.PutStr(verificationProfileKey, "stale-profile")
	attrs.PutStr(tier2StatusKey, tier2VerifiedQueued)
	attrs.PutStr(exportStatusKey, tier2VerifiedQueued)
	attrs.PutStr(lastStateChangeAtKey, "2020-01-01T00:00:00Z")

	p := newTestProcessor(t, &Config{
		Mode:        ModeSync,
		HmacKeyFile: filepath.Join("testdata", "dev_hmac_key.txt"),
	})
	reason, err := p.verifyAuditLogRecord(rl.Resource(), lr)
	require.NoError(t, err, "reason=%s", reason)
	assert.Equal(t, reasonOK, reason)
}

func TestMarkFailedSetsOutcomeAttributes(t *testing.T) {
	t.Parallel()
	logs := buildSignedHMACRecord(t, "rec-outcome-fail")
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	lr.Attributes().PutStr(auditAttrIntegrityVal, "deadbeef")

	sink := &consumertest.LogsSink{}
	p := newTestProcessor(t, &Config{
		Mode:                ModeSync,
		HmacKeyFile:         filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode:         FailureModeMark,
		VerificationProfile: "tier2-prod",
	})
	p.nextLogs = sink

	require.NoError(t, p.ConsumeLogs(context.Background(), logs))
	require.Len(t, sink.AllLogs(), 1)

	out := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := out.Attributes()
	status, _ := attrs.Get(verifyStatusKey)
	assert.Equal(t, status.Str(), statusFailed)
	reason, _ := attrs.Get(verifyReasonKey)
	assert.Equal(t, reason.Str(), "integrity_mismatch")
	details, ok := attrs.Get(verifyDetailsKey)
	require.True(t, ok)
	assert.NotEmpty(t, details.Str())
	tier2, _ := attrs.Get(tier2StatusKey)
	assert.Equal(t, tier2.Str(), tier2RejectedVerify)
	export, _ := attrs.Get(exportStatusKey)
	assert.Equal(t, export.Str(), tier2RejectedVerify)
}
