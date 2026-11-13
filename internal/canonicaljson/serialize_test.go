// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/probityai/agent-evidence-vectors/jcsvectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestSerializeLogRecord_BasicFields(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(1234567890, 123456789)))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Unix(1234567891, 987654321)))
	lr.Body().SetStr("test message")

	opts := SerializeLogRecordOptions{
		ExcludePrefixes: []string{"audit.integrity."},
	}

	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	// Parse back to verify structure
	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	assert.Equal(t, "1234567890123456789", data["timestamp"])
	assert.Equal(t, "1234567891987654321", data["observed_timestamp"])
	assert.Equal(t, map[string]any{"stringValue": "test message"}, data["body"])
}

func TestSerializeLogRecord_EventName(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.SetEventName("user.login")
	lr.Body().SetStr("User logged in")

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	assert.Equal(t, "user.login", data["event_name"])
}

func TestSerializeLogRecord_TraceContext(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")

	traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	spanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	lr.SetTraceID(traceID)
	lr.SetSpanID(spanID)

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", data["trace_id"])
	assert.Equal(t, "0102030405060708", data["span_id"])
}

func TestSerializeLogRecord_Attributes(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")
	lr.Attributes().PutStr("http.method", "GET")
	lr.Attributes().PutInt("http.status_code", 200)
	lr.Attributes().PutBool("success", true)

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	attrs := data["attributes"].(map[string]any)
	assert.Equal(t, map[string]any{"stringValue": "GET"}, attrs["http.method"])
	assert.Equal(t, map[string]any{"intValue": "200"}, attrs["http.status_code"])
	assert.Equal(t, map[string]any{"boolValue": true}, attrs["success"])
}

func TestSerializeLogRecord_ExcludePrefixes(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")
	lr.Attributes().PutStr("normal.attr", "value1")
	lr.Attributes().PutStr("audit.integrity.value", "signature")
	lr.Attributes().PutStr("audit.integrity.algorithm", "RS256")
	lr.Attributes().PutStr("audit.verification.status", "verified")
	lr.Attributes().PutStr("other.attr", "value2")

	opts := SerializeLogRecordOptions{
		ExcludePrefixes: []string{"audit.integrity.", "audit.verification."},
	}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	attrs := data["attributes"].(map[string]any)
	assert.Contains(t, attrs, "normal.attr")
	assert.Contains(t, attrs, "other.attr")
	assert.NotContains(t, attrs, "audit.integrity.value")
	assert.NotContains(t, attrs, "audit.integrity.algorithm")
	assert.NotContains(t, attrs, "audit.verification.status")
}

func TestSerializeLogRecord_EmptyBody(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Attributes().PutStr("key", "value")

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	assert.NotContains(t, data, "body")
	assert.Contains(t, data, "attributes")
}

func TestSerializeLogRecord_NoAttributes(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test message")

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	assert.Contains(t, data, "body")
	assert.NotContains(t, data, "attributes")
}

func TestSerializeLogRecord_ComplexBody(t *testing.T) {
	lr := plog.NewLogRecord()

	bodyMap := lr.Body().SetEmptyMap()
	bodyMap.PutStr("message", "error occurred")
	bodyMap.PutInt("code", 500)
	details := bodyMap.PutEmptyMap("details")
	details.PutStr("component", "database")

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	body := data["body"].(map[string]any)
	assert.Equal(t, map[string]any{"stringValue": "error occurred"}, body["message"])
	assert.Equal(t, map[string]any{"intValue": "500"}, body["code"])

	detailsData := body["details"].(map[string]any)
	assert.Equal(t, map[string]any{"stringValue": "database"}, detailsData["component"])
}

func TestSerializeLogRecord_Defaults(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")
	lr.SetTimestamp(pcommon.Timestamp(1234567890000000000))

	// Create nested structure close to default limit (128) to verify defaults are actually applied
	attrs := lr.Attributes()
	current := attrs.PutEmptyMap("nested")
	for i := 0; i < 100; i++ { // Well under default MaxDepth of 128
		current = current.PutEmptyMap("level")
	}
	current.PutStr("deep", "value")

	// Test with empty options - should use defaults (MaxDepth: 128, MaxInputBytes: 2 MiB)
	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify it's actually using defaults
	assert.Less(t, len(result), DefaultMaxInputBytes, "result should be well under 2 MiB default")
	assert.Greater(t, len(result), 100, "result should contain the nested structure")

	// Verify the deeply nested structure was serialized
	assert.Contains(t, string(result), "deep")
	assert.Contains(t, string(result), "value")
}

func TestSerializeLogRecord_ExceedsDepthLimit(t *testing.T) {
	lr := plog.NewLogRecord()

	// Create deeply nested structure
	bodyMap := lr.Body().SetEmptyMap()
	current := bodyMap
	for i := 0; i < 5; i++ {
		current = current.PutEmptyMap("level")
	}
	current.PutStr("deep", "value")

	opts := SerializeLogRecordOptions{
		MaxDepth: 3,
	}
	_, err := SerializeLogRecord(lr, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "depth limit")
}

func TestSerializeLogRecord_ExceedsSizeLimit(t *testing.T) {
	lr := plog.NewLogRecord()

	// Create a large body
	largeString := strings.Repeat("a", 1000)
	lr.Body().SetStr(largeString)

	opts := SerializeLogRecordOptions{
		MaxInputBytes: 100, // Very small limit
	}
	_, err := SerializeLogRecord(lr, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds size limit")
}

func TestSerializeLogRecord_InvalidUTF8InEventName(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.SetEventName("invalid\xffutf8")
	lr.Body().SetStr("test")

	opts := SerializeLogRecordOptions{}
	_, err := SerializeLogRecord(lr, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid UTF-8")
}

func TestSerializeLogRecord_CanonicalJSON(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")

	// Add attributes in non-alphabetical order
	lr.Attributes().PutStr("zebra", "z")
	lr.Attributes().PutStr("alpha", "a")
	lr.Attributes().PutStr("beta", "b")

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	// Canonical JSON should have keys in lexicographic order
	// The result should be deterministic
	result2, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	assert.Equal(t, result, result2, "Serialization should be deterministic")

	// Check that keys are in order in the JSON
	jsonStr := string(result)
	alphaPos := strings.Index(jsonStr, `"alpha"`)
	betaPos := strings.Index(jsonStr, `"beta"`)
	zebraPos := strings.Index(jsonStr, `"zebra"`)

	assert.True(t, alphaPos < betaPos && betaPos < zebraPos,
		"Attributes should be in alphabetical order in canonical JSON")
}

// TestSerializeLogRecord_AttributeInsertionOrderDeterministic verifies that two records
// with the same data but attributes inserted in different order produce identical
// canonical bytes. This tests the JCS key sorting requirement.
func TestSerializeLogRecord_AttributeInsertionOrderDeterministic(t *testing.T) {
	makeRecord := func(order []string) plog.LogRecord {
		lr := plog.NewLogRecord()
		lr.SetTimestamp(pcommon.Timestamp(1000000000))
		for _, k := range order {
			lr.Attributes().PutStr(k, "v")
		}
		return lr
	}

	r1 := makeRecord([]string{"z.attr", "a.attr", "m.attr"})
	r2 := makeRecord([]string{"a.attr", "m.attr", "z.attr"})

	opts := SerializeLogRecordOptions{}
	b1, err := SerializeLogRecord(r1, opts)
	require.NoError(t, err)
	b2, err := SerializeLogRecord(r2, opts)
	require.NoError(t, err)

	require.Equal(t, b1, b2, "attribute insertion order must not affect serialization (JCS key sorting)")
}

func TestMarshalJCS_Empty(t *testing.T) {
	result, err := marshalJCS(map[string]any{}, DefaultMaxInputBytes)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(result))
}

func TestMarshalJCS_ExceedsSize(t *testing.T) {
	data := map[string]any{
		"key": strings.Repeat("a", 1000),
	}
	_, err := marshalJCS(data, 100)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds size limit")
}

func TestSerializeLogRecord_Int64Timestamps(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")

	// Use specific timestamp values that fit in int64
	lr.SetTimestamp(pcommon.Timestamp(1234567890123456789))
	lr.SetObservedTimestamp(pcommon.Timestamp(1234567891987654321))

	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)

	var data map[string]any
	err = json.Unmarshal(result, &data)
	require.NoError(t, err)

	// Timestamps should be encoded as decimal strings
	assert.Equal(t, "1234567890123456789", data["timestamp"])
	assert.Equal(t, "1234567891987654321", data["observed_timestamp"])
}

// TestSerializeLogRecord_BodyTypes verifies that the log body is serialized
// correctly for every pcommon.Value type. This ensures that records with
// different body types produce distinct canonical bytes.
func TestSerializeLogRecord_BodyTypes(t *testing.T) {
	// Serialize record with no body for comparison
	emptyLR := plog.NewLogRecord()
	emptyLR.SetEventName("e")
	emptyResult, err := SerializeLogRecord(emptyLR, SerializeLogRecordOptions{})
	require.NoError(t, err)

	tests := []struct {
		name        string
		setBody     func(plog.LogRecord)
		wantContain string
	}{
		{
			name:        "string body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetStr("hello") },
			wantContain: `"body":{"stringValue":"hello"}`,
		},
		{
			name:        "int body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetInt(42) },
			wantContain: `"body":{"intValue":"42"}`,
		},
		{
			name:        "double body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetDouble(1.5) },
			wantContain: `"body":{"doubleValue":1.5}`,
		},
		{
			name:        "bool body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetBool(true) },
			wantContain: `"body":{"boolValue":true}`,
		},
		{
			name:        "bytes body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetEmptyBytes().Append(0xDE, 0xAD) },
			wantContain: `"body":{"bytesValue":"3q0="}`,
		},
		{
			name:        "slice body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetEmptySlice().AppendEmpty().SetStr("x") },
			wantContain: `"body":[{"stringValue":"x"}]`,
		},
		{
			name:        "map body",
			setBody:     func(lr plog.LogRecord) { lr.Body().SetEmptyMap().PutStr("action", "delete-all") },
			wantContain: `"body":{"action":{"stringValue":"delete-all"}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lr := plog.NewLogRecord()
			lr.SetEventName("e")
			tc.setBody(lr)

			result, err := SerializeLogRecord(lr, SerializeLogRecordOptions{})
			require.NoError(t, err)

			// Must differ from empty body
			assert.NotEqual(t, string(emptyResult), string(result),
				"body should be present in canonical payload")

			// Must contain expected body representation
			assert.Contains(t, string(result), tc.wantContain,
				"payload does not carry the expected body representation")
		})
	}
}

// TestSerializeLogRecord_BodyDistinguishesRecords verifies that two records
// differing only in their body produce distinct canonical bytes.
func TestSerializeLogRecord_BodyDistinguishesRecords(t *testing.T) {
	lr1 := plog.NewLogRecord()
	lr1.SetEventName("e")
	lr1.Body().SetEmptyMap().PutStr("action", "read")

	lr2 := plog.NewLogRecord()
	lr2.SetEventName("e")
	lr2.Body().SetEmptyMap().PutStr("action", "delete-all")

	result1, err := SerializeLogRecord(lr1, SerializeLogRecordOptions{})
	require.NoError(t, err)

	result2, err := SerializeLogRecord(lr2, SerializeLogRecordOptions{})
	require.NoError(t, err)

	assert.NotEqual(t, result1, result2,
		"records with different map bodies must produce distinct canonical bytes")
}

// TestSerializeLogRecord_EmptyBodyOmitted confirms that an unset body is
// omitted from the payload rather than being encoded as null.
func TestSerializeLogRecord_EmptyBodyOmitted(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.SetEventName("e")

	// Verify body is actually empty
	require.Equal(t, pcommon.ValueTypeEmpty, lr.Body().Type(),
		"expected unset body to be ValueTypeEmpty")

	result, err := SerializeLogRecord(lr, SerializeLogRecordOptions{})
	require.NoError(t, err)

	// Body key should not appear in output
	assert.NotContains(t, string(result), `"body"`,
		"unset body should be omitted from canonical payload")
}

// TestSerializeLogRecord_BodyInvalidUTF8Rejected verifies that invalid UTF-8
// in the body is rejected during serialization.
func TestSerializeLogRecord_BodyInvalidUTF8Rejected(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr(string([]byte{0xff, 0xfe}))

	_, err := SerializeLogRecord(lr, SerializeLogRecordOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UTF-8",
		"expected UTF-8 validation error for invalid body")
}

// TestSerializeLogRecord_BodyNestingDepthCapped verifies that deeply nested
// body structures respect the MaxDepth limit and don't overflow the stack.
func TestSerializeLogRecord_BodyNestingDepthCapped(t *testing.T) {
	lr := plog.NewLogRecord()

	// Create body nested beyond default limit
	m := lr.Body().SetEmptyMap()
	for i := 0; i < DefaultMaxDepth+1; i++ {
		m = m.PutEmptyMap("n")
	}

	_, err := SerializeLogRecord(lr, SerializeLogRecordOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth limit",
		"expected depth limit error for deeply nested body")
}

// TestSerializeLogRecord_TimestampPrecision verifies that timestamps differing
// by 1 nanosecond produce distinct canonical bytes. This ensures int64 timestamps
// are serialized as strings, not as float64 (which would lose precision for
// values in the ~1.7e18 range).
func TestSerializeLogRecord_TimestampPrecision(t *testing.T) {
	base := pcommon.Timestamp(1714041600000000000)

	lr1 := plog.NewLogRecord()
	lr1.SetTimestamp(base)
	lr1.Body().SetStr("test")

	lr2 := plog.NewLogRecord()
	lr2.SetTimestamp(base + 1) // 1 nanosecond later
	lr2.Body().SetStr("test")

	result1, err := SerializeLogRecord(lr1, SerializeLogRecordOptions{})
	require.NoError(t, err)

	result2, err := SerializeLogRecord(lr2, SerializeLogRecordOptions{})
	require.NoError(t, err)

	assert.NotEqual(t, result1, result2,
		"timestamps differing by 1ns must produce distinct canonical bytes")

	// Verify timestamp appears as quoted string
	assert.Contains(t, string(result1), `"timestamp":"1714041600000000000"`)
	assert.Contains(t, string(result2), `"timestamp":"1714041600000000001"`)
}

// TestSerializeLogRecord_ObservedTimestampPrecision is the same check for ObservedTimestamp.
func TestSerializeLogRecord_ObservedTimestampPrecision(t *testing.T) {
	base := pcommon.Timestamp(1714041600000000000)

	lr1 := plog.NewLogRecord()
	lr1.SetObservedTimestamp(base)
	lr1.Body().SetStr("test")

	lr2 := plog.NewLogRecord()
	lr2.SetObservedTimestamp(base + 1)
	lr2.Body().SetStr("test")

	result1, err := SerializeLogRecord(lr1, SerializeLogRecordOptions{})
	require.NoError(t, err)

	result2, err := SerializeLogRecord(lr2, SerializeLogRecordOptions{})
	require.NoError(t, err)

	assert.NotEqual(t, result1, result2,
		"observed_timestamps differing by 1ns must produce distinct canonical bytes")

	// Verify observed_timestamp appears as quoted string
	assert.Contains(t, string(result1), `"observed_timestamp":"1714041600000000000"`)
	assert.Contains(t, string(result2), `"observed_timestamp":"1714041600000000001"`)
}

// minVectors stops a bump that drops vectors from passing on fewer of them.
const minVectors = 50

var canonicalLeaf = regexp.MustCompile(`"(?:[^"\\]|\\.)*":?|true|false|-?\d[-+.0-9e]*`)

// TestRFC8785Vectors runs published RFC 8785 vectors through
// SerializeLogRecord, so a jcs or Go bump that moves the signed bytes fails
// here. The vectors come from a module pinned in go.mod and go.sum.
//
// Only the accept cases are run. The reject cases are lone surrogates,
// non-finite numbers and duplicate members, which never reach jcs.Transform
// on this path: TestSerializeLogRecord_BodyInvalidUTF8Rejected and float64
// special values tests cover the first two, and a pcommon.Map cannot hold a
// duplicate member.
func TestRFC8785Vectors(t *testing.T) {
	vectors, err := jcsvectors.Canonical()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(vectors), minVectors)

	for _, vector := range vectors {
		t.Run(vector.Corpus+"/"+vector.ID, func(t *testing.T) {
			var decoded any
			require.NoError(t, json.Unmarshal(vector.Input, &decoded))
			value := pcommon.NewValueEmpty()
			require.NoError(t, value.FromRaw(decoded))
			lr := plog.NewLogRecord()
			value.CopyTo(lr.Attributes().PutEmpty("v"))

			opts := SerializeLogRecordOptions{
				ExcludePrefixes: []string{"audit.integrity."},
			}
			got, err := SerializeLogRecord(lr, opts)
			require.NoError(t, err)
			require.Equal(t, `{"attributes":{"v":`+wrapLeaves(string(vector.Canonical))+`}}`, string(got))
		})
	}
}

// wrapLeaves gives canonical JSON the shape valueToInterface gives the same
// value: each scalar becomes a one-member object, and member order is unchanged.
func wrapLeaves(canonical string) string {
	return canonicalLeaf.ReplaceAllStringFunc(canonical, func(leaf string) string {
		switch {
		case strings.HasSuffix(leaf, `":`):
			return leaf // a member name
		case leaf[0] == '"':
			return `{"stringValue":` + leaf + `}`
		case leaf == "true" || leaf == "false":
			return `{"boolValue":` + leaf + `}`
		default:
			return `{"doubleValue":` + leaf + `}`
		}
	})
}
