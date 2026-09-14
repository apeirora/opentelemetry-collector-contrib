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

func TestValueToInterfacePrimitives(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  func() pcommon.Value
		want any
	}{
		{name: "empty", set: func() pcommon.Value { return pcommon.NewValueEmpty() }, want: nil},
		{name: "string", set: func() pcommon.Value { v := pcommon.NewValueStr("hello"); return v }, want: map[string]any{"stringValue": "hello"}},
		{name: "int", set: func() pcommon.Value { v := pcommon.NewValueInt(42); return v }, want: map[string]any{"intValue": "42"}},
		{name: "bool_true", set: func() pcommon.Value { v := pcommon.NewValueBool(true); return v }, want: map[string]any{"boolValue": true}},
		{name: "bool_false", set: func() pcommon.Value { v := pcommon.NewValueBool(false); return v }, want: map[string]any{"boolValue": false}},
		{name: "double", set: func() pcommon.Value { v := pcommon.NewValueDouble(1.5); return v }, want: map[string]any{"doubleValue": 1.5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := valueToInterface(tt.set(), 0)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSerializeLogRecordMatchesSigningShape(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.SetSeverityNumber(plog.SeverityNumberInfo)
	lr.SetSeverityText("INFO")
	lr.Body().SetStr(`{"event":"user.login"}`)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-typed")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutInt("custom.count", 7)
	attrs.PutBool("custom.ok", true)
	attrs.PutDouble("custom.ratio", 0.25)
	attrs.PutStr(auditAttrIntegrityVal, "ignored")
	attrs.PutStr(verifyStatusKey, statusPassed)

	canonical, err := serializeLogRecord(lr)
	require.NoError(t, err)
	payload := string(canonical)
	assert.Contains(t, payload, `"event_name":"user.login"`)
	assert.Contains(t, payload, `"body":{"stringValue":"{\"event\":\"user.login\"}"}`)
	assert.Contains(t, payload, `"timestamp":"1779096939611093600"`)
	assert.Contains(t, payload, `"observed_timestamp":"1779096939611093600"`)
	assert.Contains(t, payload, `"custom.count":{"intValue":"7"}`)
	assert.Contains(t, payload, `"custom.ok":{"boolValue":true}`)
	assert.Contains(t, payload, `"custom.ratio":{"doubleValue":0.25}`)
	assert.NotContains(t, payload, `"severity_number"`)
	assert.NotContains(t, payload, `"severity_text"`)
	assert.NotContains(t, payload, auditAttrIntegrityVal)
	assert.NotContains(t, payload, verifyStatusKey)
	assert.NotContains(t, payload, `"attributes":[`)
}

func TestSerializeLogRecordExcludesOutcomeAttributes(t *testing.T) {
	t.Parallel()
	lr := plog.NewLogRecord()
	lr.SetEventName("user.login")
	attrs := lr.Attributes()
	attrs.PutStr("custom.note", "keep-me")
	attrs.PutStr(verifyStatusKey, statusPassed)
	attrs.PutStr(tier2StatusKey, tier2VerifiedQueued)
	attrs.PutStr(auditAttrIntegrityVal, "ignored-anyway")

	canonical, err := serializeLogRecord(lr)
	require.NoError(t, err)
	assert.Contains(t, string(canonical), `"custom.note":{"stringValue":"keep-me"}`)
	assert.NotContains(t, string(canonical), verifyStatusKey)
	assert.NotContains(t, string(canonical), tier2StatusKey)
	assert.NotContains(t, string(canonical), auditAttrIntegrityVal)
}

func TestSerializeLogRecordStable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-stable")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr("custom.note", "tier2")

	first, err := serializeLogRecord(lr)
	require.NoError(t, err)
	second, err := serializeLogRecord(lr)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

func TestSerializeLogRecordRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	lr := plog.NewLogRecord()
	lr.Body().SetStr(string([]byte{0xff, 0xfe, 0xfd}))
	_, err := serializeLogRecord(lr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid UTF-8")
}

func TestSerializeLogRecordRejectsDeepNesting(t *testing.T) {
	t.Parallel()
	lr := plog.NewLogRecord()
	cur := lr.Attributes().PutEmptyMap("nest")
	for i := 0; i < jsonMaxDepth+2; i++ {
		cur = cur.PutEmptyMap("n")
	}
	cur.PutStr("leaf", "x")
	_, err := serializeLogRecord(lr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth")
}

func TestSerializeLogRecordMatchesSigningPRCanonicalFixture(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 1779096939611093600)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.Body().SetStr(`{"event":"user.login"}`)
	attrs := lr.Attributes()
	attrs.PutStr(auditAttrRecordID, "rec-docker-pass")
	attrs.PutStr(auditAttrActorID, "alice@example.com")
	attrs.PutStr(auditAttrActorType, "user")
	attrs.PutStr(auditAttrAction, "login")
	attrs.PutStr(auditAttrOutcome, "success")
	attrs.PutStr(auditAttrSourceID, "testapp")

	canonical, err := serializeLogRecord(lr)
	require.NoError(t, err)
	want := `{"attributes":{"audit.action":{"stringValue":"login"},"audit.actor.id":{"stringValue":"alice@example.com"},"audit.actor.type":{"stringValue":"user"},"audit.outcome":{"stringValue":"success"},"audit.record.id":{"stringValue":"rec-docker-pass"},"audit.source.id":{"stringValue":"testapp"}},"body":{"stringValue":"{\"event\":\"user.login\"}"},"event_name":"user.login","observed_timestamp":"1779096939611093600","timestamp":"1779096939611093600"}`
	assert.Equal(t, want, string(canonical))
}
