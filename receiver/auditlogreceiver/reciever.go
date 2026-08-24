// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

const (
	pendingKeysListKey  = "__pending_keys__"
	pendingKeyPrefix    = "pending/"
	deadLetterKeyPrefix = "dead_letter/"

	rejectedVerifyFailed = "rejected_verify_failed"
)

type pendingAuditEntry struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Body        []byte    `json:"body"`
	ContentType string    `json:"content_type"`
}

type auditLogReceiver struct {
	logger     *zap.Logger
	consumer   consumer.Logs
	server     *http.Server
	storage    storage.Client
	cfg        *Config
	settings   receiver.Settings
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shutdownWG sync.WaitGroup

	circuitBreaker *circuitBreaker
	obsrecv        *receiverhelper.ObsReport

	keysListMutex sync.Mutex
	recoverMutex  sync.Mutex
	inflightWg    sync.WaitGroup
}

type AuditLogReceiver = auditLogReceiver

func NewReceiver(cfg *Config, set receiver.Settings, consumer consumer.Logs) (*AuditLogReceiver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

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
		return nil, err
	}

	logger := componentLogger(set.Logger)

	r := &auditLogReceiver{
		logger:   logger,
		consumer: consumer,
		cfg:      cfg,
		settings: set,
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

	r.recoverSyncPending()

	loopCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go r.recoverPendingLoop(loopCtx)

	path := r.cfg.Path
	if path == "" {
		path = defaultPath
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, r.handleAuditLogs)

	ln, err := r.cfg.ToListener(ctx)
	if err != nil {
		cancel()
		r.wg.Wait()
		return fmt.Errorf("failed to bind to address %s: %w", r.cfg.NetAddr.Endpoint, err)
	}

	r.server, err = r.cfg.ToServer(ctx, host.GetExtensions(), r.settings.TelemetrySettings, mux)
	if err != nil {
		cancel()
		r.wg.Wait()
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
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()

	if r.server != nil {
		if err := r.server.Shutdown(ctx); err != nil {
			r.logger.Error("HTTP server shutdown error", errString(err))
		}
		r.shutdownWG.Wait()
	}

	r.inflightWg.Wait()
	r.recoverSyncPending()

	if r.storage != nil {
		if err := r.storage.Close(ctx); err != nil {
			r.logger.Error("Failed to close storage client", errString(err))
		}
	}

	return nil
}

func (r *auditLogReceiver) recoverPendingLoop(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(defaultRecoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.recoverSyncPending()
		}
	}
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

func corruptDeadLetterID(pendingKey string) string {
	id := strings.TrimPrefix(pendingKey, pendingKeyPrefix)
	if id == "" {
		id = uuid.New().String()
	}
	return "corrupt_" + id
}

func (r *auditLogReceiver) moveCorruptPendingToDeadLetter(key string, rawData []byte, cause error) error {
	dlID := corruptDeadLetterID(key)
	payload, err := json.Marshal(struct {
		PendingKey string `json:"pending_key"`
		RawData    []byte `json:"raw_data"`
		Error      string `json:"error"`
	}{key, rawData, cause.Error()})
	if err != nil {
		return err
	}
	if err := r.storage.Set(context.Background(), deadLetterKeyPrefix+dlID, payload); err != nil {
		return err
	}
	return r.deletePendingEntry(key)
}

func (r *auditLogReceiver) handleCorruptPendingEntry(key string, rawData []byte, cause error) {
	dlKey := deadLetterKeyPrefix + corruptDeadLetterID(key)
	if err := r.moveCorruptPendingToDeadLetter(key, rawData, cause); err != nil {
		r.logger.Error("Failed to move corrupt WAL entry to dead letter",
			zap.String("pending_key", key),
			zap.String("dead_letter_key", dlKey),
			errString(cause),
			errString(err),
		)
		return
	}
	r.logger.Error("Corrupt WAL entry moved to dead letter",
		zap.String("pending_key", key),
		zap.String("dead_letter_key", dlKey),
		errString(cause),
	)
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
	r.logger.Info("Stored sync WAL entry",
		zap.String("pending_key", key),
		zap.Int("log_records", logs.LogRecordCount()),
	)
	return key, nil
}

func (r *auditLogReceiver) syncDeliver(ctx context.Context, logs plog.Logs) (*syncDeliveryResult, error) {
	if err := r.checkCircuitForRequest(); err != nil {
		if r.cfg.CircuitBreaker.OpenBehaviorMode() == CircuitOpenAccept {
			pendingKey, perr := r.persistPendingLogs(logs)
			if perr != nil {
				return nil, perr
			}
			r.logger.Info("Circuit open; stored WAL entry and deferred delivery",
				zap.String("pending_key", pendingKey),
				zap.Int("log_records", logs.LogRecordCount()),
			)
			return &syncDeliveryResult{circuitDeferred: true}, nil
		}
		return nil, err
	}

	pendingKey, err := r.persistPendingLogs(logs)
	if err != nil {
		return nil, err
	}

	result, err := r.deliverLogsByRecord(ctx, logs)
	if err != nil {
		r.logger.Warn("Sync delivery failed, WAL entry retained for recovery",
			zap.String("pending_key", pendingKey),
			errString(err),
		)
		return nil, err
	}

	if err := r.deletePendingEntry(pendingKey); err != nil {
		r.logger.Error("Delivered but failed to delete pending entry; downstream sinks must dedupe on audit.record.id",
			zap.String("pending_key", pendingKey),
			errString(err),
		)
		return result, nil
	}
	r.logger.Info("Cleared sync WAL entry after successful delivery",
		zap.String("pending_key", pendingKey),
		zap.Int("accepted_records", result.accepted),
	)
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

	if !r.recoverMutex.TryLock() {
		return
	}
	defer r.recoverMutex.Unlock()

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
		if r.cfg.CircuitBreaker.IsEnabled() {
			ok, _ := r.circuitBreaker.checkCircuitBreakerState(key)
			if !ok {
				continue
			}
		}

		data, err := r.storage.Get(context.Background(), key)
		if err != nil || data == nil {
			continue
		}

		var entry pendingAuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			r.handleCorruptPendingEntry(key, data, err)
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
				continue
			}
			r.logger.Warn("Recovery delivery failed, WAL entry retained",
				zap.String("pending_key", key),
				errString(err),
			)
			continue
		}

		if err := r.deletePendingEntry(key); err != nil {
			r.logger.Error("Recovered but failed to delete pending entry; downstream sinks must dedupe on audit.record.id",
				zap.String("pending_key", key),
				errString(err),
			)
			continue
		}
		r.logger.Info("Recovered and cleared sync WAL entry", zap.String("pending_key", key))
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

func parseAuditContentType(header string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return "", fmt.Errorf("unsupported content type %q, expected application/x-protobuf, application/vnd.google.protobuf, or application/json", header)
	}
	switch mediaType {
	case "application/x-protobuf", "application/vnd.google.protobuf", "application/json":
		return mediaType, nil
	default:
		return "", fmt.Errorf("unsupported content type %q, expected application/x-protobuf, application/vnd.google.protobuf, or application/json", header)
	}
}

func (r *auditLogReceiver) handleAuditLogs(w http.ResponseWriter, req *http.Request) {
	r.inflightWg.Add(1)
	defer r.inflightWg.Done()

	if req.Method != http.MethodPost {
		writeAuditHTTPError(w, consumererror.NewPermanent(errors.New("only POST method allowed")))
		return
	}

	contentType, err := parseAuditContentType(req.Header.Get("Content-Type"))
	if err != nil {
		writeAuditHTTPError(w, consumererror.NewPermanent(err))
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeAuditHTTPError(w, consumererror.NewPermanent(fmt.Errorf("failed to read request body: %w", err)))
		return
	}
	defer req.Body.Close()

	switch contentType {
	case "application/x-protobuf", "application/vnd.google.protobuf":
		r.handleOTLP(w, req, body, true)
	case "application/json":
		r.handleOTLP(w, req, body, false)
	}
}

func (r *auditLogReceiver) handleOTLP(w http.ResponseWriter, req *http.Request, body []byte, isProto bool) {
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

	result, err := r.syncDeliver(req.Context(), logs)
	if err != nil {
		r.logger.Error("Sync delivery failed", errString(err))
		writeAuditHTTPError(w, err)
		r.obsrecv.EndLogsOp(ctx, format, numRecords, err)
		return
	}

	if result.isCircuitDeferred() {
		r.writeOTLPResponse(w, isProto, http.StatusAccepted)
		r.obsrecv.EndLogsOp(ctx, format, numRecords, nil)
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

func isDiscardableProcessingError(err error) bool {
	if err == nil {
		return false
	}
	if consumererror.IsPermanent(err) {
		return true
	}
	return strings.Contains(err.Error(), rejectedVerifyFailed)
}
