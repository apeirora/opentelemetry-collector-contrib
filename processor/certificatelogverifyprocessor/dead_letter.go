// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

const deadLetterIndexKey = "__dead_letter_index__"

type deadLetterEntry struct {
	ID                   string          `json:"id"`
	StoredAt             time.Time       `json:"stored_at"`
	VerifyReason         string          `json:"verify_reason"`
	VerifyDetails        string          `json:"verify_details"`
	VerificationProfile  string          `json:"verification_profile"`
	ProcessorFailureMode string          `json:"processor_failure_mode"`
	AuditRecordID        string          `json:"audit_record_id,omitempty"`
	StreamID             string          `json:"stream_id,omitempty"`
	TTL                  string          `json:"ttl,omitempty"`
	Record               json.RawMessage `json:"record,omitempty"`
	Resource             json.RawMessage `json:"resource,omitempty"`
}

type deadLetterStore struct {
	cfg    DeadLetterConfig
	client storage.Client
	logger *zap.Logger
}

func newDeadLetterStore(cfg DeadLetterConfig, client storage.Client, logger *zap.Logger) *deadLetterStore {
	return &deadLetterStore{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

func (s *deadLetterStore) shouldStore(reason string, processorFailureMode string) bool {
	if !s.cfg.Enabled {
		return false
	}
	if len(s.cfg.Reasons) > 0 && !containsString(s.cfg.Reasons, reason) {
		return false
	}
	modes := s.cfg.effectiveFailureModes()
	if len(modes) > 0 && !containsString(modes, processorFailureMode) {
		return false
	}
	return true
}

func (s *deadLetterStore) store(ctx context.Context, resource pcommon.Resource, lr plog.LogRecord, reason string, verifyErr error, processorFailureMode, verificationProfile string) error {
	if !s.shouldStore(reason, processorFailureMode) {
		return nil
	}

	recordID := attrString(lr, auditAttrRecordID)
	streamID := streamIDFromRecord(resource, lr)

	entry := deadLetterEntry{
		ID:                   uuid.New().String(),
		StoredAt:             time.Now().UTC(),
		VerifyReason:         reason,
		VerifyDetails:        verifyErr.Error(),
		VerificationProfile:  verificationProfile,
		ProcessorFailureMode: processorFailureMode,
		AuditRecordID:        recordID,
		StreamID:             streamID,
	}
	if s.cfg.TTL > 0 {
		entry.TTL = time.Now().UTC().Add(s.cfg.TTL).Format(time.RFC3339Nano)
	}

	if s.cfg.ShouldIncludeRecord() {
		recordPayload, err := marshalLogRecord(lr)
		if err != nil {
			return fmt.Errorf("dead letter record marshal: %w", err)
		}
		entry.Record = recordPayload
	}
	if s.cfg.ShouldIncludeResource() {
		resourcePayload, err := marshalResource(resource)
		if err != nil {
			return fmt.Errorf("dead letter resource marshal: %w", err)
		}
		entry.Resource = resourcePayload
	}

	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("dead letter entry marshal: %w", err)
	}
	if s.cfg.MaxEntrySizeBytes > 0 && len(payload) > s.cfg.MaxEntrySizeBytes {
		return fmt.Errorf("dead letter entry size %d exceeds max_entry_size_bytes %d", len(payload), s.cfg.MaxEntrySizeBytes)
	}

	key, err := s.entryKey(entry.ID, recordID, streamID)
	if err != nil {
		return err
	}

	if err := s.client.Set(ctx, key, payload); err != nil {
		return fmt.Errorf("dead letter storage set: %w", err)
	}

	if s.cfg.MaintainIndex {
		if err := s.appendIndex(ctx, key); err != nil {
			return fmt.Errorf("dead letter index update: %w", err)
		}
	}

	s.logger.Info("Stored verification failure in dead letter queue",
		zap.String("key", key),
		zap.String("verify_reason", reason),
		zap.String("audit_record_id", recordID),
		zap.String("stream_id", streamID),
	)
	return nil
}

func (s *deadLetterStore) entryKey(entryID, recordID, streamID string) (string, error) {
	prefix := s.cfg.effectiveKeyPrefix()
	if s.cfg.DeduplicateByRecordID {
		if recordID == "" {
			return "", fmt.Errorf("deduplicate_by_record_id requires audit.record.id on failed record")
		}
		entryID = sanitizeKeySegment(recordID)
	}
	if s.cfg.PartitionByStream {
		if streamID == "" {
			return "", fmt.Errorf("partition_by_stream requires audit.source.id on failed record")
		}
		return prefix + sanitizeKeySegment(streamID) + "/" + entryID, nil
	}
	return prefix + entryID, nil
}

func (s *deadLetterStore) appendIndex(ctx context.Context, key string) error {
	data, err := s.client.Get(ctx, deadLetterIndexKey)
	if err != nil {
		return err
	}
	keys := make([]string, 0)
	if data != nil {
		if err := json.Unmarshal(data, &keys); err != nil {
			return err
		}
	}
	for _, existing := range keys {
		if existing == key {
			return nil
		}
	}
	keys = append(keys, key)
	indexData, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, deadLetterIndexKey, indexData)
}

func marshalLogRecord(lr plog.LogRecord) (json.RawMessage, error) {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr.CopyTo(sl.LogRecords().AppendEmpty())
	data, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func marshalResource(resource pcommon.Resource) (json.RawMessage, error) {
	logs := plog.NewLogs()
	resource.CopyTo(logs.ResourceLogs().AppendEmpty().Resource())
	data, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func sanitizeKeySegment(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_")
	return replacer.Replace(value)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
