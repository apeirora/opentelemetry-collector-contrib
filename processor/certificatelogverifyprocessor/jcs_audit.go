// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	auditAttrRecordID      = "audit.record.id"
	auditAttrActorID       = "audit.actor.id"
	auditAttrActorType     = "audit.actor.type"
	auditAttrAction        = "audit.action"
	auditAttrOutcome       = "audit.outcome"
	auditAttrTargetID      = "audit.target.id"
	auditAttrTargetType    = "audit.target.type"
	auditAttrSourceID      = "audit.source.id"
	auditAttrSourceType    = "audit.source.type"
	auditAttrSchemaVersion = "audit.schema.version"
	auditAttrSequenceNo    = "audit.sequence.number"
	auditAttrPrevHash      = "audit.prev.hash"
	auditAttrIntegrityVal  = "audit.integrity.value"

	jsonMaxDepth      = 128
	jsonMaxInputBytes = 1 << 21
)

func isIntegrityAttributeKey(key string) bool {
	return key == auditAttrIntegrityVal || strings.HasPrefix(key, "audit.integrity.")
}

func isProcessorOutcomeAttribute(key string) bool {
	switch key {
	case verifyStatusKey, verifyReasonKey, verifyDetailsKey,
		verifiedAtKey, verificationProfileKey,
		tier2StatusKey, exportStatusKey, lastStateChangeAtKey:
		return true
	default:
		return false
	}
}

func isExcludedFromJCS(key string) bool {
	return isIntegrityAttributeKey(key) || isProcessorOutcomeAttribute(key)
}

func serializeLogRecord(lr plog.LogRecord) ([]byte, error) {
	data := make(map[string]any)

	if lr.EventName() != "" {
		data["event_name"] = lr.EventName()
	}

	if lr.Body().Type() != pcommon.ValueTypeEmpty {
		body, err := valueToInterface(lr.Body(), 0)
		if err != nil {
			return nil, fmt.Errorf("log record body: %w", err)
		}
		data["body"] = body
	}

	if lr.Timestamp() != 0 {
		data["timestamp"] = strconv.FormatInt(lr.Timestamp().AsTime().UnixNano(), 10)
	}

	if lr.ObservedTimestamp() != 0 {
		data["observed_timestamp"] = strconv.FormatInt(lr.ObservedTimestamp().AsTime().UnixNano(), 10)
	}

	if !lr.TraceID().IsEmpty() {
		data["trace_id"] = lr.TraceID().String()
	}

	if !lr.SpanID().IsEmpty() {
		data["span_id"] = lr.SpanID().String()
	}

	attrs := make(map[string]any)
	var attrErr error
	lr.Attributes().Range(func(k string, v pcommon.Value) bool {
		if isExcludedFromJCS(k) {
			return true
		}
		val, err := valueToInterface(v, 0)
		if err != nil {
			attrErr = err
			return false
		}
		attrs[k] = val
		return true
	})
	if attrErr != nil {
		return nil, attrErr
	}
	if len(attrs) > 0 {
		data["attributes"] = attrs
	}

	return marshalJCS(data)
}

func marshalJCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw) > jsonMaxInputBytes {
		return nil, fmt.Errorf("serialized log record exceeds size limit (%d > %d bytes)", len(raw), jsonMaxInputBytes)
	}
	return jcs.Transform(raw)
}

func valueToInterface(v pcommon.Value, depth int) (any, error) {
	if depth > jsonMaxDepth {
		return nil, fmt.Errorf("value exceeds nesting depth limit (%d)", jsonMaxDepth)
	}
	switch v.Type() {
	case pcommon.ValueTypeStr:
		s := v.Str()
		if !utf8.ValidString(s) {
			return nil, errors.New("string value contains invalid UTF-8")
		}
		return map[string]any{"stringValue": s}, nil
	case pcommon.ValueTypeInt:
		return map[string]any{"intValue": strconv.FormatInt(v.Int(), 10)}, nil
	case pcommon.ValueTypeDouble:
		return map[string]any{"doubleValue": v.Double()}, nil
	case pcommon.ValueTypeBool:
		return map[string]any{"boolValue": v.Bool()}, nil
	case pcommon.ValueTypeBytes:
		return map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(v.Bytes().AsRaw())}, nil
	case pcommon.ValueTypeSlice:
		slice := make([]any, v.Slice().Len())
		for i := 0; i < v.Slice().Len(); i++ {
			val, err := valueToInterface(v.Slice().At(i), depth+1)
			if err != nil {
				return nil, err
			}
			slice[i] = val
		}
		return slice, nil
	case pcommon.ValueTypeMap:
		m := make(map[string]any)
		var mapErr error
		v.Map().Range(func(k string, val pcommon.Value) bool {
			converted, err := valueToInterface(val, depth+1)
			if err != nil {
				mapErr = err
				return false
			}
			m[k] = converted
			return true
		})
		if mapErr != nil {
			return nil, mapErr
		}
		return m, nil
	default:
		return nil, nil
	}
}

func integrityHashHex(lr plog.LogRecord) (string, error) {
	canonical, err := serializeLogRecord(lr)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func attrString(lr plog.LogRecord, key string) string {
	v, ok := lr.Attributes().Get(key)
	if !ok {
		return ""
	}
	if v.Type() == pcommon.ValueTypeStr {
		return v.Str()
	}
	return v.AsString()
}

func attrInt(lr plog.LogRecord, key string) (int64, bool) {
	v, ok := lr.Attributes().Get(key)
	if !ok || v.Type() != pcommon.ValueTypeInt {
		return 0, false
	}
	return v.Int(), true
}

func resourceAttrString(resource pcommon.Resource, key string) string {
	v, ok := resource.Attributes().Get(key)
	if !ok {
		return ""
	}
	if v.Type() == pcommon.ValueTypeStr {
		return v.Str()
	}
	return v.AsString()
}

func streamIDFromRecord(resource pcommon.Resource, lr plog.LogRecord) string {
	if id := attrString(lr, auditAttrSourceID); id != "" {
		return id
	}
	return resourceAttrString(resource, auditAttrSourceID)
}
