// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestCanonicalAttrStringPrimitives(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  func() pcommon.Value
		want string
	}{
		{name: "empty", set: func() pcommon.Value { return pcommon.NewValueEmpty() }, want: ""},
		{name: "string", set: func() pcommon.Value { v := pcommon.NewValueStr("hello"); return v }, want: "hello"},
		{name: "int", set: func() pcommon.Value { v := pcommon.NewValueInt(42); return v }, want: "42"},
		{name: "bool_true", set: func() pcommon.Value { v := pcommon.NewValueBool(true); return v }, want: "true"},
		{name: "bool_false", set: func() pcommon.Value { v := pcommon.NewValueBool(false); return v }, want: "false"},
		{name: "double", set: func() pcommon.Value { v := pcommon.NewValueDouble(1.5); return v }, want: "1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, canonicalAttrString(tt.set()))
		})
	}
}

func TestAttrStringCoercesNonStringAuditFields(t *testing.T) {
	t.Parallel()
	lr := plog.NewLogRecord()
	lr.Attributes().PutInt(auditAttrActorID, 4242)

	assert.Equal(t, "4242", attrString(lr, auditAttrActorID))
}

func TestJcsCanonicalAuditRecordTypedCustomAttributes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-typed")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutInt("custom.count", 7)
	attrs.PutBool("custom.ok", true)
	attrs.PutDouble("custom.ratio", 0.25)

	collected := collectNonIntegrityAttributes(lr)
	byKey := make(map[string]string, len(collected))
	for _, entry := range collected {
		byKey[entry.Key] = entry.Value
	}
	assert.Equal(t, "7", byKey["custom.count"])
	assert.Equal(t, "true", byKey["custom.ok"])
	assert.Equal(t, "0.25", byKey["custom.ratio"])
}

func TestCollectNonIntegrityAttributesExcludesOutcomeAttributes(t *testing.T) {
	t.Parallel()
	lr := plog.NewLogRecord()
	attrs := lr.Attributes()
	attrs.PutStr("custom.note", "keep-me")
	attrs.PutStr(verifyStatusKey, statusPassed)
	attrs.PutStr(tier2StatusKey, tier2VerifiedQueued)
	attrs.PutStr(auditAttrIntegrityVal, "ignored-anyway")

	collected := collectNonIntegrityAttributes(lr)
	require.Len(t, collected, 1)
	assert.Equal(t, "custom.note", collected[0].Key)
	assert.Equal(t, "keep-me", collected[0].Value)
}

func TestJcsCanonicalAuditRecordStableForStringAttributes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-stable")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutStr("custom.note", "tier2")

	first, err := jcsCanonicalAuditRecord(lr)
	require.NoError(t, err)
	second, err := jcsCanonicalAuditRecord(lr)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}
