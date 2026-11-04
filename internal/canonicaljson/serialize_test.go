// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

	// Test with empty options - should use defaults
	opts := SerializeLogRecordOptions{}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestSerializeLogRecord_CustomLimits(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Body().SetStr("test")

	opts := SerializeLogRecordOptions{
		MaxDepth:      10,
		MaxInputBytes: 1024,
	}
	result, err := SerializeLogRecord(lr, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
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
