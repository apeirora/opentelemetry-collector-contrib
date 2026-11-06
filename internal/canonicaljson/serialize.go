// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package canonicaljson // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/canonicaljson"

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/gowebpki/jcs"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Default values
const (
	DefaultMaxDepth      = 128
	DefaultMaxInputBytes = 1 << 21 // 2 MiB
)

// SerializeLogRecordOptions controls serialization behavior
type SerializeLogRecordOptions struct {
	// ExcludePrefixes lists attribute prefixes to exclude from serialization
	// e.g., ["audit.integrity.", "audit.verification."]
	ExcludePrefixes []string

	// MaxDepth caps recursion depth for nested Slice/Map values
	// Default: 128
	MaxDepth int

	// MaxInputBytes caps the serialized JSON size before JCS canonicalization
	// Default: 2 MiB (1 << 21)
	MaxInputBytes int
}

// SerializeLogRecord produces RFC 8785 (JCS) canonical JSON of a log record.
//
// Fields included in serialization (per OTLP LogRecord):
//   - event_name (EventName)
//   - body (Body)
//   - timestamp (Timestamp as Unix nanoseconds string)
//   - observed_timestamp (ObservedTimestamp as Unix nanoseconds string)
//   - trace_id (TraceID as hex string)
//   - span_id (SpanID as hex string)
//   - attributes (Attributes, filtered by ExcludePrefixes)
//
// Fields intentionally excluded from serialization:
//   - Attributes matching any prefix in opts.ExcludePrefixes
//   - SeverityNumber / SeverityText (audit metadata, not signed content)
//   - Flags (W3C trace-context sampling bit, transport-level metadata)
//   - DroppedAttributesCount (pipeline metadata, not original content)
//
// Note: This field list is intentionally hard-coded rather than using reflection
// to ensure cryptographic stability. Any new OTLP LogRecord fields require explicit
// review to determine if they should be part of the signed payload.
//
// Returns canonical JSON bytes or an error if:
//   - Nesting depth exceeds MaxDepth
//   - Serialized size exceeds MaxInputBytes
//   - Invalid UTF-8 is encountered
//   - JCS transformation fails
func SerializeLogRecord(lr plog.LogRecord, opts SerializeLogRecordOptions) ([]byte, error) {
	// Apply defaults
	if opts.MaxDepth == 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	if opts.MaxInputBytes == 0 {
		opts.MaxInputBytes = DefaultMaxInputBytes
	}

	data := make(map[string]any)

	if lr.EventName() != "" {
		if err := checkUTF8(lr.EventName(), "event name"); err != nil {
			return nil, err
		}
		data["event_name"] = lr.EventName()
	}

	if lr.Body().Type() != pcommon.ValueTypeEmpty {
		body, err := valueToInterface(lr.Body(), 0, opts.MaxDepth)
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
		// Check if key matches any exclude prefix
		for _, prefix := range opts.ExcludePrefixes {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}

		if err := checkUTF8(k, "attribute key"); err != nil {
			attrErr = err
			return false
		}
		val, err := valueToInterface(v, 0, opts.MaxDepth)
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

	return marshalJCS(data, opts.MaxInputBytes)
}

// marshalJCS produces RFC 8785 (JCS) canonical JSON bytes.
// json.Marshal sorts map keys (Go ≥ 1.12), then jcs.Transform normalizes
// number representation and validates the result per the JCS spec.
func marshalJCS(v any, maxInputBytes int) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInputBytes {
		return nil, fmt.Errorf("serialized log record exceeds size limit (%d > %d bytes)", len(raw), maxInputBytes)
	}
	return jcs.Transform(raw)
}
