package auditlogreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/errorutil"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"
)

// TODO
//Fix loging of processed log(count only vaild one)

// what will happen if we implement persistance que in exporter?
// entry point, should it be same as for logs, should we check for audit logs?
// filtering for attribute or sth else
const (
	keysListKey            = "__keys_list__"
	defaultTickerTime      = 30 * time.Second
	defaultProcessInterval = 30 * time.Second
)

type AuditLogEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Body      []byte    `json:"body"`
}

type auditLogReceiver struct {
	logger   *zap.Logger
	consumer consumer.Logs
	server   *http.Server
	storage  storage.Client
	cfg      *Config
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	circuitBreaker *CircuitBreaker
	obsrecv        *receiverhelper.ObsReport
}

func NewReceiver(cfg *Config, set receiver.Settings, consumer consumer.Logs) (*auditLogReceiver, error) {
	ctx, cancel := context.WithCancel(context.Background())

	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             set.ID,
		Transport:              "http",
		ReceiverCreateSettings: set,
	})
	if err != nil {
		return nil, err
	}

	r := &auditLogReceiver{
		logger:   set.Logger,
		consumer: consumer,
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
		obsrecv:  obsrecv,
	}

	r.circuitBreaker = NewCircuitBreaker(cfg.CircuitBreaker, set.Logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", r.handleAuditLogs)
	mux.HandleFunc("/v1/logs/", r.handleAuditLogs)       // Support OTLP standard endpoint
	mux.HandleFunc("/v1/logs/export", r.handleAuditLogs) // OTLP standard export endpoint

	r.server = &http.Server{
		Addr:    cfg.Endpoint,
		Handler: mux,
	}

	return r, nil
}

func (r *auditLogReceiver) Start(ctx context.Context, host component.Host) error {
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

	go func() {
		if err := r.server.ListenAndServe(); err != http.ErrServerClosed {
			r.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	r.wg.Add(1)
	go r.processStoredLogsLoop()

	return nil
}

func (r *auditLogReceiver) Shutdown(ctx context.Context) error {
	r.cancel()

	r.wg.Wait()

	if r.storage != nil {
		if err := r.storage.Close(ctx); err != nil {
			r.logger.Error("Failed to close storage client", zap.Error(err))
		}
	}

	return r.server.Shutdown(ctx)
}

func (r *auditLogReceiver) processAuditLog(entry *AuditLogEntry) error {
	shouldProcess, err := r.circuitBreaker.CheckCircuitBreakerState(entry.ID)
	if !shouldProcess {
		return err
	}

	r.logger.Info("Processing audit log",
		zap.String("id", entry.ID),
		zap.Time("timestamp", entry.Timestamp))

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord.SetSeverityText("INFO")

	logRecord.Body().SetStr(string(entry.Body))

	attrs := logRecord.Attributes()
	attrs.PutStr("receiver", "auditlogreceiver")

	ctx := context.Background()

	consumeErr := r.consumer.ConsumeLogs(ctx, logs)
	if consumeErr != nil {
		r.circuitBreaker.RecordFailure()
		return consumeErr
	}

	r.circuitBreaker.RecordSuccess()
	return nil
}

func (r *auditLogReceiver) processStoredLogsLoop() {
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
			r.logger.Info("Stopping audit log processing goroutine")
			return
		case <-ticker.C:
			r.processStoredLogs()
		}
	}
}

// processStoredLogs processes audit logs that are older than the configured threshold
func (r *auditLogReceiver) processStoredLogs() {
	if r.storage == nil {
		return
	}

	keys, err := r.getAllKeys()
	if err != nil {
		r.logger.Error("Failed to get all keys from storage", zap.Error(err))
		return
	}

	r.logger.Debug("Processing stored logs", zap.Int("count", len(keys)))

	ageThreshold := r.cfg.ProcessAgeThreshold
	if ageThreshold == 0 {
		ageThreshold = defaultProcessInterval
	}

	cutoffTime := time.Now().Add(-ageThreshold)

	for _, key := range keys {
		data, err := r.storage.Get(context.Background(), key)
		if err != nil {
			r.logger.Debug("Failed to get audit log entry", zap.String("key", key), zap.Error(err))
			continue
		}

		if data == nil {
			continue
		}

		var entry AuditLogEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			r.logger.Error("Failed to unmarshal audit log entry", zap.String("key", key), zap.Error(err))
			continue
		}

		if entry.Timestamp.After(cutoffTime) {
			continue
		}

		// Check circuit breaker state
		shouldProcess, err := r.circuitBreaker.CheckCircuitBreakerState(key)
		if !shouldProcess {
			r.logger.Debug("Circuit breaker is open, skipping processing", zap.String("key", key))
			continue
		}

		if err := r.processAuditLog(&entry); err != nil {
			r.logger.Error("Failed to process audit log", zap.String("key", key), zap.Error(err))

			continue
		}

		// Success - remove the entry
		if err := r.storage.Delete(context.Background(), key); err != nil {
			r.logger.Error("Failed to delete processed entry", zap.String("key", key), zap.Error(err))
		} else {
			r.logger.Info("Successfully processed and removed audit log", zap.String("key", key))
		}

		r.removeFromKeysList(key)
	}
}

// getAllKeys retrieves all keys from storage
// Since storage interface doesn't provide a direct way to list all keys through the storage interface,
// we'll use a simple approach: maintain a list of keys in storage.
func (r *auditLogReceiver) getAllKeys() ([]string, error) {

	data, err := r.storage.Get(context.Background(), keysListKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys list: %w", err)
	}

	if data == nil {
		return []string{}, nil
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys list: %w", err)
	}

	return keys, nil
}

func (r *auditLogReceiver) addToKeysList(key string) error {

	keys, err := r.getAllKeys()
	if err != nil {
		return fmt.Errorf("failed to get keys list: %w", err)
	}

	for _, k := range keys {
		if k == key {
			return nil
		}
	}

	keys = append(keys, key)

	data, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to marshal keys list: %w", err)
	}

	if err := r.storage.Set(context.Background(), keysListKey, data); err != nil {
		return fmt.Errorf("failed to update keys list: %w", err)
	}

	return nil
}

func (r *auditLogReceiver) removeFromKeysList(key string) {

	keys, err := r.getAllKeys()
	if err != nil {
		r.logger.Error("Failed to get keys list for removal", zap.Error(err))
		return
	}

	newKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			newKeys = append(newKeys, k)
		}
	}

	if len(newKeys) == 0 {
		if err := r.storage.Delete(context.Background(), keysListKey); err != nil {
			r.logger.Error("Failed to delete empty keys list", zap.Error(err))
		}
	} else {
		data, err := json.Marshal(newKeys)
		if err != nil {
			r.logger.Error("Failed to marshal updated keys list", zap.Error(err))
			return
		}

		if err := r.storage.Set(context.Background(), keysListKey, data); err != nil {
			r.logger.Error("Failed to update keys list", zap.Error(err))
		}
	}
}

func (r *auditLogReceiver) handleAuditLogs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		errorutil.HTTPError(w, consumererror.NewPermanent(fmt.Errorf("only POST method allowed")))
		return
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "application/x-protobuf" && contentType != "application/json" && contentType != "application/vnd.google.protobuf" {
		errorutil.HTTPError(w, consumererror.NewPermanent(fmt.Errorf("unsupported content type %q, expected application/x-protobuf, application/vnd.google.protobuf, or application/json", contentType)))
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		errorutil.HTTPError(w, consumererror.NewPermanent(fmt.Errorf("failed to read request body: %w", err)))
		return
	}
	defer req.Body.Close()

	entryID := uuid.New().String()
	key := entryID

	if contentType == "application/x-protobuf" || contentType == "application/vnd.google.protobuf" {
		err = r.handleOTLPProtobuf(w, req, body, entryID, key)
		if err != nil {
			r.logger.Error("Failed to handle OTLP protobuf request", zap.Error(err))
			return
		}
		return
	}

	ctx := r.obsrecv.StartLogsOp(req.Context())

	entry := AuditLogEntry{
		ID:        entryID,
		Timestamp: time.Now(),
		Body:      body,
	}

	entryData, err := json.Marshal(entry)
	if err != nil {
		r.logger.Error("Failed to marshal audit log entry", zap.Error(err))
		errorutil.HTTPError(w, err)
		r.obsrecv.EndLogsOp(ctx, "json", 0, err)
		return
	}

	if r.storage != nil {
		if err := r.storage.Set(context.Background(), key, entryData); err != nil {
			r.logger.Error("Failed to store audit log entry", zap.String("key", key), zap.Error(err))
			errorutil.HTTPError(w, err)
			r.obsrecv.EndLogsOp(ctx, "json", 0, err)
			return
		}

		if err := r.addToKeysList(key); err != nil {
			r.logger.Error("Failed to add key to keys list", zap.String("key", key), zap.Error(err))
		}

		r.logger.Info("Stored audit log entry", zap.String("id", entryID), zap.String("content_type", contentType))
	} else {
		r.logger.Error("Storage client not initialized")
		errorutil.HTTPError(w, fmt.Errorf("storage client not initialized"))
		r.obsrecv.EndLogsOp(ctx, "json", 0, fmt.Errorf("storage client not initialized"))
		return
	}

	w.WriteHeader(http.StatusAccepted)

	err = r.processAuditLog(&entry)
	if err != nil {
		r.logger.Error("Failed to process audit log entry", zap.Error(err))
		r.obsrecv.EndLogsOp(ctx, "json", 1, err)
	} else {
		err = r.storage.Delete(context.Background(), key)
		if err != nil {
			r.logger.Error("Failed to delete audit log entry", zap.Error(err))
		}
		r.removeFromKeysList(key)
		r.obsrecv.EndLogsOp(ctx, "json", 1, nil)
	}
}

// handleOTLPProtobuf handles OTLP protobuf format requests following standard OTLP patterns
func (r *auditLogReceiver) handleOTLPProtobuf(w http.ResponseWriter, req *http.Request, body []byte, entryID, key string) error {
	ctx := r.obsrecv.StartLogsOp(req.Context())

	otlpReq := plogotlp.NewExportRequest()
	if err := otlpReq.UnmarshalProto(body); err != nil {
		r.logger.Error("Failed to unmarshal OTLP protobuf request", zap.Error(err))
		errorutil.HTTPError(w, consumererror.NewPermanent(err))
		r.obsrecv.EndLogsOp(ctx, "protobuf", 0, err)
		return err
	}

	logs := otlpReq.Logs()
	numRecords := logs.LogRecordCount()

	if numRecords == 0 {
		response := plogotlp.NewExportResponse()
		responseData, err := response.MarshalProto()
		if err != nil {
			r.logger.Error("Failed to marshal OTLP response", zap.Error(err))
			errorutil.HTTPError(w, err)
			r.obsrecv.EndLogsOp(ctx, "protobuf", 0, err)
			return err
		}

		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(responseData)
		r.obsrecv.EndLogsOp(ctx, "protobuf", 0, err)
		return err
	}

	if r.storage != nil {
		entry := AuditLogEntry{
			ID:        entryID,
			Timestamp: time.Now(),
			Body:      body,
		}

		entryData, err := json.Marshal(entry)
		if err != nil {
			r.logger.Error("Failed to marshal audit log entry", zap.Error(err))
			errorutil.HTTPError(w, err)
			r.obsrecv.EndLogsOp(ctx, "protobuf", numRecords, err)
			return err
		}

		if err := r.storage.Set(context.Background(), key, entryData); err != nil {
			r.logger.Error("Failed to store audit log entry", zap.String("key", key), zap.Error(err))
			errorutil.HTTPError(w, err)
			r.obsrecv.EndLogsOp(ctx, "protobuf", numRecords, err)
			return err
		}

		if err := r.addToKeysList(key); err != nil {
			r.logger.Error("Failed to add key to keys list", zap.String("key", key), zap.Error(err))
		}

		r.logger.Info("Stored OTLP audit log entry", zap.String("id", entryID), zap.Int("log_records", numRecords))
	}

	err := r.consumer.ConsumeLogs(ctx, logs)

	response := plogotlp.NewExportResponse()
	if err != nil {
		r.logger.Error("Failed to consume OTLP logs", zap.Error(err))
	}

	responseData, marshalErr := response.MarshalProto()
	if marshalErr != nil {
		r.logger.Error("Failed to marshal OTLP response", zap.Error(marshalErr))
		errorutil.HTTPError(w, marshalErr)
		r.obsrecv.EndLogsOp(ctx, "protobuf", numRecords, marshalErr)
		return marshalErr
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, writeErr := w.Write(responseData)

	if err == nil && r.storage != nil {
		if deleteErr := r.storage.Delete(context.Background(), key); deleteErr != nil {
			r.logger.Error("Failed to delete processed OTLP entry", zap.Error(deleteErr))
		} else {
			r.removeFromKeysList(key)
		}
	}

	r.obsrecv.EndLogsOp(ctx, "protobuf", numRecords, err)

	return writeErr
}
