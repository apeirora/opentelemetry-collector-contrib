// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	auditAttrRecordID       = "audit.record.id"
	auditAttrRecordIDLegacy = "audit.record_id"
)

type failedAuditRecord struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type syncDeliveryResult struct {
	accepted      int
	failedRecords []failedAuditRecord
}

func (r *syncDeliveryResult) hasFailures() bool {
	return len(r.failedRecords) > 0
}

func (r *syncDeliveryResult) rejectedCount() int {
	return len(r.failedRecords)
}

func (r *syncDeliveryResult) partialSuccessMessage() string {
	payload := struct {
		RejectedRecordIDs []string            `json:"rejected_record_ids"`
		RejectedRecords   []failedAuditRecord `json:"rejected_records,omitempty"`
	}{
		RejectedRecordIDs: make([]string, 0, len(r.failedRecords)),
		RejectedRecords:   r.failedRecords,
	}
	for _, record := range r.failedRecords {
		payload.RejectedRecordIDs = append(payload.RejectedRecordIDs, record.ID)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("rejected %d log record(s)", len(r.failedRecords))
	}
	return string(data)
}

func splitLogsByRecord(logs plog.Logs) []plog.Logs {
	batches := make([]plog.Logs, 0, logs.LogRecordCount())
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rl := logs.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				single := plog.NewLogs()
				newRL := single.ResourceLogs().AppendEmpty()
				rl.Resource().CopyTo(newRL.Resource())
				newSL := newRL.ScopeLogs().AppendEmpty()
				sl.Scope().CopyTo(newSL.Scope())
				sl.LogRecords().At(k).CopyTo(newSL.LogRecords().AppendEmpty())
				batches = append(batches, single)
			}
		}
	}
	return batches
}

func auditRecordID(lr plog.LogRecord) string {
	if v, ok := lr.Attributes().Get(auditAttrRecordID); ok {
		return v.Str()
	}
	if v, ok := lr.Attributes().Get(auditAttrRecordIDLegacy); ok {
		return v.Str()
	}
	traceID := lr.TraceID()
	spanID := lr.SpanID()
	if !traceID.IsEmpty() || !spanID.IsEmpty() {
		return traceID.String() + "/" + spanID.String()
	}
	return ""
}

func auditRecordIDFromLogs(logs plog.Logs, fallback string) string {
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rl := logs.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				if id := auditRecordID(sl.LogRecords().At(k)); id != "" {
					return id
				}
			}
		}
	}
	return fallback
}
