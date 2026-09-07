// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deszhou/jcs"
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
)

type jcsAttr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

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

func jcsCanonicalAuditRecord(lr plog.LogRecord) ([]byte, error) {
	attrs := collectNonIntegrityAttributes(lr)
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].Key == attrs[j].Key {
			return attrs[i].Value < attrs[j].Value
		}
		return attrs[i].Key < attrs[j].Key
	})

	timestamp := lr.Timestamp().AsTime().UTC()
	observed := lr.ObservedTimestamp().AsTime().UTC()
	if observed.IsZero() {
		observed = timestamp
	}

	payload := map[string]any{
		"timestamp":          formatAuditTimestamp(timestamp),
		"observed_timestamp": formatAuditTimestamp(observed),
		"event_name":         lr.EventName(),
		"audit.record.id":    attrString(lr, auditAttrRecordID),
		"audit.actor.id":     attrString(lr, auditAttrActorID),
		"audit.actor.type":   attrString(lr, auditAttrActorType),
		"audit.action":       attrString(lr, auditAttrAction),
		"audit.outcome":      attrString(lr, auditAttrOutcome),
		"attributes":         attrs,
	}
	if targetID := attrString(lr, auditAttrTargetID); targetID != "" {
		payload["audit.target.id"] = targetID
	}
	if targetType := attrString(lr, auditAttrTargetType); targetType != "" {
		payload["audit.target.type"] = targetType
	}
	if sourceID := attrString(lr, auditAttrSourceID); sourceID != "" {
		payload["audit.source.id"] = sourceID
	}
	if sourceType := attrString(lr, auditAttrSourceType); sourceType != "" {
		payload["audit.source.type"] = sourceType
	}
	if body := lr.Body().AsString(); body != "" {
		payload["body"] = body
	}
	if schema := attrString(lr, auditAttrSchemaVersion); schema != "" {
		payload["audit.schema.version"] = schema
	}
	if seq, ok := attrInt(lr, auditAttrSequenceNo); ok && seq > 0 {
		payload["audit.sequence.number"] = seq
	}
	if prev := attrString(lr, auditAttrPrevHash); prev != "" {
		payload["audit.prev.hash"] = prev
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit record: %w", err)
	}
	return jcs.Transform(data)
}

func integrityHashHex(lr plog.LogRecord) (string, error) {
	canonical, err := jcsCanonicalAuditRecord(lr)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func collectNonIntegrityAttributes(lr plog.LogRecord) []jcsAttr {
	attrs := make([]jcsAttr, 0)
	lr.Attributes().Range(func(k string, v pcommon.Value) bool {
		if isExcludedFromJCS(k) {
			return true
		}
		attrs = append(attrs, jcsAttr{Key: k, Value: canonicalAttrString(v)})
		return true
	})
	return attrs
}

func canonicalAttrString(v pcommon.Value) string {
	switch v.Type() {
	case pcommon.ValueTypeEmpty:
		return ""
	case pcommon.ValueTypeStr:
		return v.Str()
	case pcommon.ValueTypeInt:
		return strconv.FormatInt(v.Int(), 10)
	case pcommon.ValueTypeBool:
		return strconv.FormatBool(v.Bool())
	case pcommon.ValueTypeDouble:
		return strconv.FormatFloat(v.Double(), 'g', -1, 64)
	default:
		return v.AsString()
	}
}

func attrString(lr plog.LogRecord, key string) string {
	v, ok := lr.Attributes().Get(key)
	if !ok {
		return ""
	}
	return canonicalAttrString(v)
}

func attrInt(lr plog.LogRecord, key string) (int64, bool) {
	v, ok := lr.Attributes().Get(key)
	if !ok {
		return 0, false
	}
	return v.Int(), true
}

func resourceAttrString(resource pcommon.Resource, key string) string {
	v, ok := resource.Attributes().Get(key)
	if !ok {
		return ""
	}
	return canonicalAttrString(v)
}

func formatAuditTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

func streamIDFromRecord(resource pcommon.Resource, lr plog.LogRecord) string {
	if id := attrString(lr, auditAttrSourceID); id != "" {
		return id
	}
	return resourceAttrString(resource, auditAttrSourceID)
}
