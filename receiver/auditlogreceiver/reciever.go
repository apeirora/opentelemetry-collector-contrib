// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/errorutil"
)

// TODO: Fix logging of processed logs (count only valid ones).
// TODO: Investigate how persistence queue in exporters affects delivery guarantees.

const (
	// pendingKeysListKey indexes all keys under pendingKeyPrefix in storage.
	pendingKeysListKey = "__pending_keys__"
	// pendingKeyPrefix is the storage namespace for async entries awaiting delivery.
	pendingKeyPrefix = "pending/"
	// deadLetterKeyPrefix is the storage namespace for permanently failed pending entries.
	deadLetterKeyPrefix = "dead_letter/"

	defaultTickerTime    = 30 * time.Second
	rejectedVerifyFailed = "rejected_verify_failed"
)

// pendingAuditEntry is a durably stored OTLP payload waiting for async delivery.
type pendingAuditEntry struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Body        []byte    `json:"body"`
	ContentType string    `json:"content_type"`
	RetryCount  int       `json:"retry_count"`
	NextRetryAt time.Time `json:"next_retry_at"`
}

type auditLogReceiver struct {
	logger   *zap.Logger
	consumer consumer.Logs
	server   *http.Server
	storage  storage.Client
	cfg      *Config
	settings receiver.Settings
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	shutdownWG sync.WaitGroup

	circuitBreaker *circuitBreaker
	obsrecv        *receiverhelper.ObsReport

	keysListMutex sync.Mutex
	inflightWg    sync.WaitGroup
}

type AuditLogReceiver = auditLogReceiver

func NewReceiver(cfg *Config, set receiver.Settings, consumer consumer.Logs) (*AuditLogReceiver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	transport := "http"
	if cfg.TLS.HasValue() {
		transport = "https"
	}

	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             set.ID,
		Transport:              transport,
		ReceiverCreateSettings: set,
	})
	if err != nil {
		cancel()
		return nil, err
	}

	logger := componentLogger(set.Logger)

	r := &auditLogReceiver{
		logger:   logger,
		consumer: consumer,
		cfg:      cfg,
		settings: set,
		ctx:      ctx,
		cancel:   cancel,
		obsrecv:  obsrecv,
	}

	r.circuitBreaker = newCircuitBreaker(cfg.CircuitBreaker, logger)

	return r, nil
}

func (r *auditLogReceiver) Start(ctx context.Context, host component.Host) error {
	if r.server != nil {
		return nil
	}

	extensions := host.GetExtensions()
	storageExtension, exists := extensions[r.cfg.StorageID]
	if !exists {
		return fmt.Errorf("storage extension %s not found", r.cfg.StorageID)
	}

	storageExt, ok := storageExtension.(storage.Extension)
	if !ok {
		return fmt.Errorf("storage extension %s does not implement storage.Extension", r.cfg.StorageID)
	}

	var err error
	r.storage, err = storageExt.GetClient(ctx, component.KindReceiver, r.cfg.StorageID, "auditlogreceiver")
	if err != nil {
		return fmt.Errorf("failed to get storage client: %w", err)
	}

	if r.cfg.IsAsync() {
		r.wg.Add(1)
		go r.processPendingLogsLoop()
	} else {
		r.recoverSyncPending()
	}

	path := r.cfg.Path
	if path == "" {
		path = defaultPath
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, r.handleAuditLogs)

	ln, err := r.cfg.ToListener(ctx)
	if err != nil {
		return fmt.Errorf("failed to bind to address %s: %w", r.cfg.Endpoint, err)
	}

	r.server, err = r.cfg.ToServer(ctx, host, r.settings.TelemetrySettings, mux)
	if err != nil {
		return err
	}

	if r.cfg.ReadHeaderTimeout == 0 {
		r.server.ReadHeaderTimeout = 20 * time.Second
	}

	r.shutdownWG.Add(1)
	go func() {
		defer r.shutdownWG.Done()
		if errHTTP := r.server.Serve(ln); !errors.Is(errHTTP, http.ErrServerClosed) && errHTTP != nil {
			componentstatus.ReportStatus(host, componentstatus.NewFatalErrorEvent(errHTTP))
		}
	}()

	return nil
}

func (r *auditLogReceiver) Shutdown(ctx context.Context) error {
	if r.server != nil {
		if err := r.server.Shutdown(ctx); err != nil {
			r.logger.Error("HTTP server shutdown error", errString(err))
		}
		r.shutdownWG.Wait()
	}

	r.inflightWg.Wait()

	if !r.cfg.IsAsync() {
		r.recoverSyncPending()
	}

	r.cancel()
	r.wg.Wait()

	if r.storage != nil {
		if err := r.storage.Close(ctx); err != nil {
			r.logger.Error("Failed to close storage client", errString(err))
		}
	}

	return nil
}

// processPendingLogsLoop runs the async delivery worker until shutdown.
func (r *auditLogReceiver) processPendingLogsLoop() {
	defer r.wg.Done()

	interval := r.cfg.ProcessInterval
	if interval == 0 {
		interval = defaultTickerTime
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			r.logger.Info("Stopping pending audit log worker")
			return
		case <-ticker.C:
			r.processPendingLogs()
		}
	}
}

// processPendingLogs delivers pending entries that are due for retry.
func (r *auditLogReceiver) processPendingLogs() {
	if r.storage == nil {
		return
	}

	keys, err := r.getPendingKeys()
	if err != nil {
		r.logger.Error("Failed to get pending keys", errString(err))
		return
	}

	now := time.Now()
	ageThreshold := r.cfg.ProcessAgeThreshold

	for _, key := range keys {
		data, err := r.storage.Get(context.Background(), key)
		if err != nil {
			r.logger.Debug("Failed to get pending entry", zap.String("key", key), errString(err))
			continue
		}
		if data == nil {
			r.removeFromPendingKeysList(key)
			continue
		}

		var entry pendingAuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			r.logger.Warn("Discarding corrupt pending entry", zap.String("key", key), errString(err))
			_ = r.deletePendingEntry(key)
			continue
		}

		if ageThreshold > 0 && entry.Timestamp.After(now.Add(-ageThreshold)) {
			continue
		}
		if !entry.NextRetryAt.IsZero() && now.Before(entry.NextRetryAt) {
			continue
		}

		if r.cfg.CircuitBreaker.IsEnabled() {
			shouldProcess, _ := r.circuitBreaker.checkCircuitBreakerState(key)
			if !shouldProcess {
				continue
			}
		}

		if err := r.deliverPendingEntry(key, &entry); err != nil {
			if isDiscardableProcessingError(err) {
				r.logger.Warn("Moving pending entry to dead letter after permanent failure",
					zap.String("key", key),
					errString(err),
				)
				_ = r.moveToDeadLetter(key, &entry, err)
				continue
			}
			r.logger.Error("Pending delivery failed, will retry", zap.String("key", key), errString(err))
		}
	}
}

// deliverPendingEntry runs the pipeline for one pending entry and removes it on success.
func (r *auditLogReceiver) deliverPendingEntry(key string, entry *pendingAuditEntry) error {
	logs, err := unmarshalPendingLogs(entry)
	if err != nil {
		return consumererror.NewPermanent(err)
	}

	if err := r.deliverLogs(context.Background(), logs); err != nil {
		if isDiscardableProcessingError(err) {
			return err
		}
		return r.schedulePendingRetry(key, entry, err)
	}

	if err := r.deletePendingEntry(key); err != nil {
		r.logger.Error("Delivered but failed to delete pending entry", zap.String("key", key), errString(err))
	}
	r.logger.Info("Successfully delivered pending audit log", zap.String("key", key))
	return nil
}

func (r *auditLogReceiver) schedulePendingRetry(key string, entry *pendingAuditEntry, deliveryErr error) error {
	entry.RetryCount++
	if r.cfg.Delivery.MaxRetries > 0 && entry.RetryCount > r.cfg.Delivery.MaxRetries {
		_ = r.moveToDeadLetter(key, entry, deliveryErr)
		return deliveryErr
	}
	entry.NextRetryAt = time.Now().Add(r.calculateRetryDelay(entry.RetryCount))
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := r.storage.Set(context.Background(), key, data); err != nil {
		return err
	}
	if !isDiscardableProcessingError(deliveryErr) && r.cfg.CircuitBreaker.IsEnabled() {
		r.circuitBreaker.RecordFailure()
	}
	return deliveryErr
}

func (r *auditLogReceiver) moveToDeadLetter(key string, entry *pendingAuditEntry, cause error) error {
	payload, err := json.Marshal(struct {
		Entry pendingAuditEntry `json:"entry"`
		Error string            `json:"error"`
	}{*entry, cause.Error()})
	if err != nil {
		return err
	}
	if err := r.storage.Set(context.Background(), deadLetterKeyPrefix+entry.ID, payload); err != nil {
		return err
	}
	return r.deletePendingEntry(key)
}

func (r *auditLogReceiver) calculateRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := float64(r.cfg.Delivery.InitialInterval) * math.Pow(2, float64(attempt-1))
	maxDelay := float64(r.cfg.Delivery.MaxInterval)
	if delay > maxDelay {
		delay = maxDelay
	}
	return time.Duration(delay)
}

func unmarshalPendingLogs(entry *pendingAuditEntry) (plog.Logs, error) {
	otlpReq := plogotlp.NewExportRequest()
	switch entry.ContentType {
	case "application/x-protobuf", "application/vnd.google.protobuf":
		if err := otlpReq.UnmarshalProto(entry.Body); err != nil {
			return plog.Logs{}, fmt.Errorf("failed to unmarshal pending protobuf: %w", err)
		}
	case "application/json":
		if err := otlpReq.UnmarshalJSON(entry.Body); err != nil {
			return plog.Logs{}, fmt.Errorf("failed to unmarshal pending json: %w", err)
		}
	default:
		return plog.Logs{}, fmt.Errorf("unsupported pending content type %q", entry.ContentType)
	}
	return otlpReq.Logs(), nil
}

func (r *auditLogReceiver) deliverLogs(ctx context.Context, logs plog.Logs) error {
	if logs.LogRecordCount() == 0 {
		return nil
	}

	if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
		if !isDiscardableProcessingError(err) && r.cfg.CircuitBreaker.IsEnabled() {
			r.circuitBreaker.RecordFailure()
		}
		return mapPipelineError(err)
	}

	if r.cfg.CircuitBreaker.IsEnabled() {
		r.circuitBreaker.RecordSuccess()
	}
	return nil
}

func (r *auditLogReceiver) checkCircuitForRequest() error {
	if !r.cfg.CircuitBreaker.IsEnabled() {
		return nil
	}
	ok, _ := r.circuitBreaker.checkCircuitBreakerState("sync")
	if !ok {
		return newUnavailableError(errCircuitOpen.Error())
	}
	return nil
}

func (r *auditLogReceiver) persistPendingLogs(logs plog.Logs) (string, error) {
	protoBody, err := plogotlp.NewExportRequestFromLogs(logs).MarshalProto()
	if err != nil {
		return "", fmt.Errorf("failed to marshal logs for pending storage: %w", err)
	}

	pendingID := uuid.New().String()
	key := pendingKeyPrefix + pendingID
	entry := pendingAuditEntry{
		ID:          pendingID,
		Timestamp:   time.Now().UTC(),
		Body:        protoBody,
		ContentType: "application/x-protobuf",
	}
	entryData, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	if err := r.storePendingEntry(key, entryData); err != nil {
		return "", err
	}
	return key, nil
}

func (r *auditLogReceiver) syncDeliver(ctx context.Context, logs plog.Logs) (*syncDeliveryResult, error) {
	pendingKey, err := r.persistPendingLogs(logs)
	if err != nil {
		return nil, err
	}

	if err := r.checkCircuitForRequest(); err != nil {
		return nil, err
	}

	result, err := r.deliverLogsByRecord(ctx, logs)
	if err != nil {
		return nil, err
	}

	if err := r.deletePendingEntry(pendingKey); err != nil {
		r.logger.Error("Delivered but failed to delete pending entry", zap.String("key", pendingKey), errString(err))
	}
	return result, nil
}

func (r *auditLogReceiver) deliverLogsByRecord(ctx context.Context, logs plog.Logs) (*syncDeliveryResult, error) {
	result := &syncDeliveryResult{}
	batches := splitLogsByRecord(logs)

	for i, batch := range batches {
		fallbackID := fmt.Sprintf("record-%d", i)
		recordID := auditRecordIDFromLogs(batch, fallbackID)

		if err := r.deliverLogs(ctx, batch); err != nil {
			if isDiscardableProcessingError(err) {
				result.failedRecords = append(result.failedRecords, failedAuditRecord{
					ID:     recordID,
					Reason: err.Error(),
				})
				continue
			}
			return nil, err
		}
		result.accepted++
	}

	return result, nil
}

func (r *auditLogReceiver) recoverSyncPending() {
	if r.storage == nil {
		return
	}

	keys, err := r.getPendingKeys()
	if err != nil {
		r.logger.Error("Failed to list pending entries for recovery", errString(err))
		return
	}
	if len(keys) == 0 {
		return
	}

	r.logger.Info("Recovering pending sync audit logs", zap.Int("count", len(keys)))
	for _, key := range keys {
		data, err := r.storage.Get(context.Background(), key)
		if err != nil || data == nil {
			continue
		}

		var entry pendingAuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			r.logger.Warn("Discarding corrupt pending entry", zap.String("key", key), errString(err))
			_ = r.deletePendingEntry(key)
			continue
		}

		logs, err := unmarshalPendingLogs(&entry)
		if err != nil {
			_ = r.moveToDeadLetter(key, &entry, err)
			continue
		}

		if err := r.deliverLogs(context.Background(), logs); err != nil {
			if isDiscardableProcessingError(err) {
				_ = r.moveToDeadLetter(key, &entry, err)
			}
			continue
		}

		if err := r.deletePendingEntry(key); err != nil {
			r.logger.Error("Recovered but failed to delete pending entry", zap.String("key", key), errString(err))
		}
	}
}

func (r *auditLogReceiver) getPendingKeys() ([]string, error) {
	data, err := r.storage.Get(context.Background(), pendingKeysListKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending keys list: %w", err)
	}
	if data == nil {
		return []string{}, nil
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending keys list: %w", err)
	}
	return keys, nil
}

func (r *auditLogReceiver) removeFromPendingKeysList(key string) {
	r.keysListMutex.Lock()
	defer r.keysListMutex.Unlock()

	keys, err := r.getPendingKeys()
	if err != nil {
		r.logger.Error("Failed to get pending keys list for removal", errString(err))
		return
	}

	newKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			newKeys = append(newKeys, k)
		}
	}

	if len(newKeys) == 0 {
		if err := r.storage.Delete(context.Background(), pendingKeysListKey); err != nil {
			r.logger.Error("Failed to delete empty pending keys list", errString(err))
		}
		return
	}

	data, err := json.Marshal(newKeys)
	if err != nil {
		r.logger.Error("Failed to marshal pending keys list", errString(err))
		return
	}
	if err := r.storage.Set(context.Background(), pendingKeysListKey, data); err != nil {
		r.logger.Error("Failed to update pending keys list", errString(err))
	}
}

// storePendingEntry atomically writes a pending entry and updates the pending key index.
func (r *auditLogReceiver) storePendingEntry(key string, entryData []byte) error {
	r.keysListMutex.Lock()
	defer r.keysListMutex.Unlock()

	keys, err := r.getPendingKeys()
	if err != nil {
		return fmt.Errorf("failed to get pending keys list: %w", err)
	}

	keyExists := false
	for _, k := range keys {
		if k == key {
			keyExists = true
			break
		}
	}

	var ops []*storage.Operation
	ops = append(ops, storage.SetOperation(key, entryData))

	if !keyExists {
		keys = append(keys, key)
		keysListData, err := json.Marshal(keys)
		if err != nil {
			return fmt.Errorf("failed to marshal pending keys list: %w", err)
		}
		ops = append(ops, storage.SetOperation(pendingKeysListKey, keysListData))
	}

	if err := r.storage.Batch(context.Background(), ops...); err != nil {
		return fmt.Errorf("failed to store pending entry: %w", err)
	}
	return nil
}

func (r *auditLogReceiver) deletePendingEntry(key string) error {
	r.keysListMutex.Lock()
	defer r.keysListMutex.Unlock()

	keys, err := r.getPendingKeys()
	if err != nil {
		return fmt.Errorf("failed to get pending keys list: %w", err)
	}

	newKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			newKeys = append(newKeys, k)
		}
	}

	var ops []*storage.Operation
	ops = append(ops, storage.DeleteOperation(key))

	if len(newKeys) == 0 {
		ops = append(ops, storage.DeleteOperation(pendingKeysListKey))
	} else {
		data, err := json.Marshal(newKeys)
		if err != nil {
			return fmt.Errorf("failed to marshal pending keys list: %w", err)
		}
		ops = append(ops, storage.SetOperation(pendingKeysListKey, data))
	}

	if err := r.storage.Batch(context.Background(), ops...); err != nil {
		return fmt.Errorf("failed to delete pending entry: %w", err)
	}
	return nil
}

func (r *auditLogReceiver) handleAuditLogs(w http.ResponseWriter, req *http.Request) {
	r.inflightWg.Add(1)
	defer r.inflightWg.Done()

	if req.Method != http.MethodPost {
		writeAuditHTTPError(w, consumererror.NewPermanent(errors.New("only POST method allowed")))
		return
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "application/x-protobuf" && contentType != "application/json" && contentType != "application/vnd.google.protobuf" {
		writeAuditHTTPError(w, consumererror.NewPermanent(fmt.Errorf("unsupported content type %q, expected application/x-protobuf, application/vnd.google.protobuf, or application/json", contentType)))
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeAuditHTTPError(w, consumererror.NewPermanent(fmt.Errorf("failed to read request body: %w", err)))
		return
	}
	defer req.Body.Close()

	switch {
	case contentType == "application/x-protobuf", contentType == "application/vnd.google.protobuf":
		r.handleOTLP(w, req, body, contentType, true)
	case contentType == "application/json":
		r.handleOTLP(w, req, body, contentType, false)
	}
}

// handleOTLP is the shared entry point for protobuf and JSON OTLP audit requests.
// Flow: parse → sync delivery (200) or async durable accept (202).
func (r *auditLogReceiver) handleOTLP(w http.ResponseWriter, req *http.Request, body []byte, contentType string, isProto bool) {
	format := "json"
	if isProto {
		format = "protobuf"
	}
	ctx := r.obsrecv.StartLogsOp(req.Context())

	otlpReq := plogotlp.NewExportRequest()
	var err error
	if isProto {
		err = otlpReq.UnmarshalProto(body)
	} else {
		err = otlpReq.UnmarshalJSON(body)
	}
	if err != nil {
		r.logger.Error("Failed to unmarshal OTLP request", errString(err))
		writeAuditHTTPError(w, consumererror.NewPermanent(err))
		r.obsrecv.EndLogsOp(ctx, format, 0, err)
		return
	}

	logs := otlpReq.Logs()
	numRecords := logs.LogRecordCount()

	if numRecords == 0 {
		r.writeOTLPResponse(w, isProto, http.StatusOK)
		r.obsrecv.EndLogsOp(ctx, format, 0, nil)
		return
	}

	if r.cfg.IsAsync() {
		if err := r.acceptAsync(w, logs, body, contentType, isProto); err != nil {
			writeAuditHTTPError(w, err)
			r.obsrecv.EndLogsOp(ctx, format, numRecords, err)
			return
		}
		r.obsrecv.EndLogsOp(ctx, format, numRecords, nil)
		return
	}

	result, err := r.syncDeliver(req.Context(), logs)
	if err != nil {
		r.logger.Error("Sync delivery failed", errString(err))
		writeAuditHTTPError(w, err)
		r.obsrecv.EndLogsOp(ctx, format, numRecords, err)
		return
	}

	if result.hasFailures() {
		if result.accepted == 0 {
			writeAuditHTTPError(w, consumererror.NewPermanent(
				fmt.Errorf("%s: all %d log record(s) rejected", rejectedVerifyFailed, result.rejectedCount()),
			))
			r.obsrecv.EndLogsOp(ctx, format, numRecords, fmt.Errorf("all records rejected"))
			return
		}
		r.writeOTLPPartialSuccessResponse(w, isProto, result)
		r.obsrecv.EndLogsOp(ctx, format, result.accepted, nil)
		return
	}

	r.writeOTLPResponse(w, isProto, http.StatusOK)
	r.obsrecv.EndLogsOp(ctx, format, numRecords, nil)
}

// acceptAsync persists the request before returning 202, guaranteeing at-least-once delivery.
func (r *auditLogReceiver) acceptAsync(w http.ResponseWriter, logs plog.Logs, body []byte, contentType string, isProto bool) error {
	storeBody := body
	storeContentType := contentType
	protoBody, err := plogotlp.NewExportRequestFromLogs(logs).MarshalProto()
	if err != nil {
		return fmt.Errorf("failed to marshal logs for pending storage: %w", err)
	}
	storeBody = protoBody
	storeContentType = "application/x-protobuf"
	if isProto {
		storeBody = body
		storeContentType = contentType
	}

	pendingID := uuid.New().String()
	key := pendingKeyPrefix + pendingID
	entry := pendingAuditEntry{
		ID:          pendingID,
		Timestamp:   time.Now().UTC(),
		Body:        storeBody,
		ContentType: storeContentType,
	}
	entryData, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if err := r.storePendingEntry(key, entryData); err != nil {
		return err
	}

	r.logger.Info("Accepted audit log for async delivery",
		zap.String("pending_id", pendingID),
		zap.Int("log_records", logs.LogRecordCount()))

	r.writeOTLPResponse(w, isProto, http.StatusAccepted)
	return nil
}

func (r *auditLogReceiver) writeOTLPResponse(w http.ResponseWriter, isProto bool, status int) {
	r.writeOTLPExportResponse(w, isProto, status, plogotlp.NewExportResponse())
}

func (r *auditLogReceiver) writeOTLPPartialSuccessResponse(w http.ResponseWriter, isProto bool, result *syncDeliveryResult) {
	response := plogotlp.NewExportResponse()
	partial := response.PartialSuccess()
	partial.SetRejectedLogRecords(int64(result.rejectedCount()))
	partial.SetErrorMessage(result.partialSuccessMessage())
	r.writeOTLPExportResponse(w, isProto, http.StatusOK, response)
}

func (r *auditLogReceiver) writeOTLPExportResponse(w http.ResponseWriter, isProto bool, status int, response plogotlp.ExportResponse) {
	var responseData []byte
	var err error
	if isProto {
		responseData, err = response.MarshalProto()
		if err == nil {
			w.Header().Set("Content-Type", "application/x-protobuf")
		}
	} else {
		responseData, err = response.MarshalJSON()
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		errorutil.HTTPError(w, err)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(responseData)
}

// isDiscardableProcessingError reports errors that must not be retried (verify failure, permanent exporter errors).
func isDiscardableProcessingError(err error) bool {
	if err == nil {
		return false
	}
	if consumererror.IsPermanent(err) {
		return true
	}
	return strings.Contains(err.Error(), rejectedVerifyFailed)
}
