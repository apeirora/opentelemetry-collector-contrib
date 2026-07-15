# Audit Log Pipeline Pitfalls

This document catalogs known pitfalls, failure modes, and misconfiguration risks for the Tier-2 audit log pipeline built from:

- **Go SDK** — `go.opentelemetry.io/otel/sdk/auditlog` (`AuditLogProcessor`, `AuditLogger`, OTLP HTTP export)
- `auditlogreceiver` — HTTP OTLP ingest with sync delivery and WAL (crash recovery)
- `certificatelogverify` — JCS integrity verification, optional hash chain, optional dead letter queue

It is intended for operators and integrators wiring SDK → collector → backend.

SDK reference: `opentelemetry-go/sdk/auditlog/AUDIT_LOG_README.md` and `PITFALLS_BACKLOG.md`.

**Scope:** This document covers the **sync pipeline only** — SDK synchronous export (`WaitOnExport: true`), collector `response_mode: sync`, processor `mode: sync`. Receiver `response_mode: async`, processor `mode: deferred`, and SDK `WaitOnExport: false` are **out of scope** and not recommended for Tier-2 audit.

---

## Pitfall summary (A–Z)

**Resolved** — pitfalls reviewed and addressed in sync-pipeline design / this doc (kept for traceability):

**End-to-end (resolved)**

a. **[RESOLVED] Competing durability** — SDK store, receiver WAL, and exporter `sending_queue` could all retry the same record → duplicates or stuck queues.  
→ **Resolution:** Audit exporters **must not** enable `sending_queue` (`sending_queue.enabled: false` required). Durable retry is SDK store (transport failure only) + receiver sync WAL (crash recovery) only. See §1.1, `example-config.yaml`.

b. **[RESOLVED] SDK backlog + collector WAL overlap** — After offline recovery, SDK store replay and collector WAL recovery could both deliver the same `audit.record.id`.  
→ **Resolution:** Accepted at-least-once design for distinct failure classes; not a duplicate auto-retry on reachable-collector HTTP errors. Sink dedupes on `audit.record.id`. SDK store applies only when collector is unreachable. See §1.1.

c. **[RESOLVED] Exporter `sending_queue`** — Persistent exporter queue adds a third retry layer on top of SDK and collector WAL.  
→ **Resolution:** Same as (a) — **do not enable** `sending_queue` on audit pipeline exporters; use inline `retry_on_failure` during sync request instead. See §1.1.

d. **[RESOLVED] Multiple exporters (fan-out)** — One failing sink returns collector 503 even if another exporter succeeded; concern that SDK would store and retry.  
→ **Resolution:** **Expected SDK behavior** — on reachable collector HTTP 503 (including fan-out), SDK returns `collector_rejected` and **does not** store. Store-and-retry is **only** when the collector is unreachable. Collector-side: prefer single sink or idempotent backend on `audit.record.id`. See §1.2.

e. **[RESOLVED] HTTP 503 misread** — Application code must not treat every `503` from `EmitWithResult` as “stored for retry”.  
→ **Resolution:** SDK `EmitWithResult` exposes both code and status string: `503 rejected` (collector reachable, HTTP error, **not stored**) vs `503 stored` (collector unreachable, `collector_unreachable_stored`). Verified in `testapp` (`emit result: status=%d %s`) and E2E scenarios 05/08/09 (`503 rejected`, reason includes “not stored”). See `testlogs/README.md` SDK durability summary, §1.3.

f. **[RESOLVED] OTLP partial success / per-record batch failures** — Concern that mixed pass/fail batches would not be reported.  
→ **Resolution:** Collector sync mode **notifies per-record outcomes**: mixed verify results → **HTTP 200** + OTLP `partialSuccess` (`rejected_log_records`, `error_message` with `rejected_record_ids` JSON); all records fail → **HTTP 400**. `testapp` emits one record per `Export()` so each emit gets `200 delivered` or `400 rejected` (scenarios 02, 07). SDK OTLP exporter rejects `partial_success` only if a multi-record `Export()` receives it — not the default one-record path. See §1.3, §2.6, `partial_batch_test.go`.

g. **[RESOLVED] Processor order / mutating processors** — Mutating processors before verify cause `integrity_mismatch` or silent tampering.  
→ **Resolution:** Audit `logs` pipeline allows **`certificatelogverify` only** — **no other processors** (no `batch`, `queuebatch`, `attributes`, `transform`, `filter`, or any mutating processor). See `example-config.yaml`, `testlogs/README.md` rule 2, §1.4.

h. **[RESOLVED] Shared storage keys** — WAL (`pending/`), hash chain (`hash_chain/`), DLQ (`dead_letter/`) may share one backend; collisions and ops confusion if namespaces are not explicit.  
→ **Resolution:** `example-config.yaml` splits `redis_storage/wal` (db 0, receiver only) and `redis_storage/audit_meta` (db 1, processor DLQ/hash chain) with `dead_letter.key_prefix: audit_verify_dlq/`. Exporters `sending_queue: false`. SDK store remains app-side. See §1.5.

**End-to-end (open)**

_None — all end-to-end items a–h resolved._

**auditlogreceiver**

i. **[RESOLVED] Storage required** — Receiver will not start without a configured, connected storage extension.  
→ **By design:** Sync mode needs a WAL (`redis_storage/wal` or `file_storage`). No storage → fail at startup (do not run without it). See §2.1.

j. **[RESOLVED] WAL orphan after success** — Pipeline succeeds but `deletePendingEntry` fails → duplicate delivery on restart.  
→ **Resolution:** At-least-once is intentional; **sinks must deduplicate on `audit.record.id`**. Receiver emits monitoring logs for WAL write/clear/retain/orphan paths (see `receiver/auditlogreceiver/README.md`); alert on *"Delivered but failed to delete pending entry"* / *"Recovered but failed to delete pending entry"* and WAL `pending/` growth. See §2.2.

k. **[RESOLVED] WAL kept on 503** — Transient pipeline failure retains WAL entry until delivery succeeds or recovery replays.  
→ **Resolution:** Same as **j** — correct at-least-once behavior; **sinks must deduplicate on `audit.record.id`**. Client may retry on 503; monitor `Sync delivery failed, WAL entry retained for recovery`. See §2.3.

l. **[RESOLVED] Circuit breaker blocks ingest** — When open, sync mode must choose how to handle new requests during backend outages.  
→ **Resolution:** `circuit_breaker.open_behavior` (default `reject`): **`reject`** returns **503** without WAL (SDK retries when collector is reachable); **`accept`** persists to WAL and returns **202** (defer delivery until circuit recovers via `recoverSyncPending`). Sync pipeline and `WaitOnExport` unchanged for the happy path. See §2.4.

m. **[RESOLVED] Partial batch HTTP 200** — (Same as **f**.) Collector returns OTLP `partialSuccess` body with rejected IDs; parse response body, not HTTP status alone. One-record-per-emit testapp path uses `400 rejected` / `200 delivered` per record instead.

n. **[RESOLVED] All records fail → 400** — Entire request rejected when every record fails verify.  
→ **Resolution:** By design — HTTP **400** to the client. Failed records are **stored in processor DLQ** (`certificatelogverify.dead_letter`, e.g. `redis_storage/audit_meta` with `audit_verify_dlq/` prefix) before the permanent verify error is returned. Requires `dead_letter.enabled: true`. See §2.6.

o. **[RESOLVED] Corrupt WAL** — Bad JSON in receiver WAL must not be silently dropped.  
→ **Resolution:** Logged at **Error** and moved to receiver dead letter (`dead_letter/corrupt_{id}` in WAL storage) with raw bytes + error; pending key removed. Monitor `Corrupt WAL entry moved to dead letter`. See §2.7.

p. **[RESOLVED] Protocol constraints** — POST only; strict OTLP `Content-Type`; not arbitrary JSON audit blobs.  
→ **By design:** Tier-2 ingest accepts only **POST** with `application/x-protobuf`, `application/vnd.google.protobuf`, or `application/json` OTLP logs export. Other methods or content types are rejected permanently. See §2.8.

q. **[RESOLVED] Transport security** — Ingest must not be plain HTTP in production.  
→ **Resolution:** Receiver supports **TLS and mTLS** via standard `confighttp` `tls` block (`cert_file`, `key_file`, `client_ca_file`). `example-config.yaml` configures mTLS; `tls_test.go` covers TLS and mTLS (client cert required when `client_ca_file` is set). SDK must use matching client TLS. Default factory config has no TLS — enable in deployment. See §2.9.

r. **[RESOLVED] Multi-instance storage races** — Replicas sharing one Redis DB can race on `__pending_keys__` and hash-chain state.  
→ **Resolution:** **One dedicated storage partition per collector instance** is sufficient: assign each replica its own Redis **db** pair (e.g. collector A: db 0+1, collector B: db 2+3) or separate file-storage directories. Within one instance, still split WAL (db 0) vs audit_meta (db 1) per pitfall **h**. See §2.10.

s. **Open TODOs** — Telemetry counts may include invalid records; exporter queue interaction with WAL not fully analyzed.

**certificatelogverify**

t. **[RESOLVED] JCS mismatch** — Signer and collector canonical bytes differ → `integrity_mismatch`.  
→ **Not a collector bug** — integration/contract alignment: SDK sign mode, keys, and OTLP field placement must match processor rules. Misconfiguration or hand-built OTLP. See §3.1.

u. **[RESOLVED] `audit.integrity.algorithm` on resource** — Algorithm on log record → `missing_integrity_algorithm`.  
→ **Skip for Go SDK pipeline** — SDK places `audit.integrity.algorithm` on the resource at export (`spec_alignment_test.go`). Not an action item when using `go.opentelemetry.io/otel/sdk/auditlog`. See §3.2.

v. **[RESOLVED] Algorithm vs key mismatch** — HMAC algorithms need HMAC key; signature algorithms need cert.  
→ **Resolution:** Processor loads each configured key source at startup and logs `Audit integrity verification ready` with `hmac_key_loaded`, `certificate_loaded`, and `supported_algorithms`. Warns if only one key type is configured. Configure both (as in `example-config.yaml`) or match SDK signing mode to loaded keys. See §3.3.

w. **[DEFERRED] Hash chain + multi-record `Export()`** — Only applies if `hash_chain.enabled: true`. **Hash chain is experimental — do not enable yet.** See §3.4.

x. **[DEFERRED] Hash chain commit after export** — Only applies if hash chain enabled. **Experimental — do not use yet.** See §3.5.

y. **[DEFERRED] Hash chain concurrency** — Only if hash chain enabled. Per-instance storage partition (pitfall **r**) applies when enabled. **Experimental — do not use yet.** See §2.10, §3.5.

z. **[DEFERRED] Hash chain field rules** — Only if hash chain enabled. **Experimental — do not use yet.** See §3.6.

aa. **`failure_mode: mark`** — Failed records pass downstream unless sinks filter on `verify_status` / `tier2_status`.

ab. **[RESOLVED] Keys/certs at startup only** — No hot reload; rotation needs collector restart.  
→ **Accepted ops model:** rolling collector restart after secret rotation (coordinate with SDK key update). Periodic in-process reload deferred — not required for Tier-2 today. See §3.8.

ac. **[RESOLVED] Certificate scope** — No expiry, revocation, or CA pinning; verifies signature against configured public key only.  
→ **Accepted for Tier-2** — HMAC deployments unaffected. For asymmetric signing, optional startup expiry check is future work; full PKI not required. See §3.9.

ad. **[RESOLVED] Non-string attributes** — Int/bool/double in OTLP must canonicalize the same as the signer.  
→ **Resolution:** Unified `canonicalAttrString` in `jcs_audit.go` (matches SDK `log.Value.String()` for primitives). **Contract:** prefer string custom attributes with Go SDK; typed primitives supported when signer/OTLP types align. See §3.10.

ae. **[RESOLVED] Integrity value encoding** — `audit.integrity.value` must decode to the same bytes the signer produced.  
→ **Resolution:** Processor accepts **hex or base64** (`decodeHexOrBase64` in `audit_verify.go`, hex first). **Contract:** Go SDK emits **base64** by default; use base64 in production; hex is fine for tests/custom signers. See §3.11.

af. **[RESOLVED] Post-verify mutation** — Processor stamps outcome metadata on every record after verification.  
→ **Resolution:** By design (`markPassed` / `markFailed` / `markDeferred` in `processor.go`). Outcome keys excluded from JCS in `jcs_audit.go` so re-processing stamped records does not break verify. **Contract:** sinks must expect processor attrs; filter on `verify_status` / `tier2_status` when using `failure_mode: mark`. See §3.12.

ag. **[RESOLVED] DLQ `fail_on_storage_error: false`** — Default is best-effort DLQ; storage errors are logged only.  
→ **Resolution:** Accepted behavior. Set `dead_letter.fail_on_storage_error: true` in production when forensic capture must not be lost. See §3.13.

ah. **[RESOLVED] DLQ `deduplicate_by_record_id`** — Requires `audit.record.id`; overwrites prior entry for the same ID.  
→ **Resolution:** Accepted behavior. Keep `false` unless last-failure-wins per record ID is intended. See §3.13.

ai. **[RESOLVED] DLQ `partition_by_stream`** — Requires `audit.source.id` on failed records.  
→ **Resolution:** Accepted behavior. Enable only when every audit record has `audit.source.id`. See §3.13.

aj. **[RESOLVED] DLQ `maintain_index`** — Index updates are not atomic across replicas.  
→ **Resolution:** Accepted behavior. Keep `maintain_index: false` in multi-replica deployments; enumerate via storage `SCAN` on `key_prefix`. See §3.13.

ak. **[RESOLVED] DLQ `ttl`** — Expiry hint in JSON only; no automatic deletion.  
→ **Resolution:** Accepted behavior. Run an external sweeper that reads `ttl` from entries or keys by age. See §3.13.

al. **[RESOLVED] DLQ `max_entry_size_bytes`** — Oversized entries fail DLQ write; may fail the pipeline when `fail_on_storage_error: true`.  
→ **Resolution:** Accepted behavior. Set a sane cap and pair with `include_record` / `include_resource` sizing. See §3.13.

am. **[RESOLVED] DLQ `reasons` filter** — Non-empty `dead_letter.reasons` is an allowlist; filtered failures are not stored (silent skip).  
→ **Resolution:** Accepted behavior. Omit `reasons` for full capture; set explicitly only to reduce DLQ volume. See §3.14.

**Go SDK**

_SDK implementation status: `opentelemetry-go/sdk/auditlog/PITFALLS_BACKLOG.md` (resolved delivery/circuit/dedup items; P1/P2 performance limits accepted)._

an. **[RESOLVED] In-memory store** — Default store lost on restart.  
→ **Resolution:** Accepted — use `-filestore`, Redis, SQL, or another durable `AuditLogStore` when the collector can be offline. See §4.1.

ao. **[RESOLVED] `sign_content` not `meta`** — `body` or `attr` signing fails at collector.  
→ **Resolution:** Contract — use `AuditSignContentMeta` (default). Processor always verifies full meta JCS. See §4.2.

ap. **[RESOLVED] JCS / OTLP alignment** — Field placement and encoding must match processor.  
→ **Resolution:** Go SDK enforces resource `audit.integrity.algorithm`, base64 integrity value, `SourceIP` → `audit.source.id` (`spec_alignment_test.go`). Collector aligned via §3.10–3.11. Golden-vector tests recommended. See §4.3.

aq. **[RESOLVED] OTLP inline HTTP retry** — Default ~750ms retry per `Export()` stacks with collector retry.  
→ **Resolution:** Implemented in SDK (`PITFALLS_BACKLOG.md`). Disable with `otlpexport.WithHTTPRetry(false)` if double-retry is confusing; collector WAL is separate. See §4.4.

ar. **[RESOLVED] Startup TLS / strict verify** — Bad TLS blocks startup; strict mode requires collector at boot.  
→ **Resolution:** Implemented in SDK (`WithStrictStartupVerify`, TLS verify at `Build()`). Contract: use non-strict for K8s rollouts if needed; strict for hard startup gates. See §4.5.

as. **[RESOLVED] Export circuit** — `MaxAttempts` exhausted opens circuit; backlog stalls until cooldown/resync.  
→ **Resolution:** Implemented in SDK — circuit opens, resyncs store to queue after cooldown, probes without restart. Monitor `export_circuit_open`. See §4.6.

at. **[RESOLVED] `store_remove_failed`** — Export OK but `RemoveAll` fails → same ID re-exported after restart.  
→ **Resolution:** Documented at-least-once contract; sink dedupes on `audit.record.id`. Monitor `store_remove_failed`. See §4.7, SDK backlog duplicate-delivery item.

au. **[RESOLVED] Per-record export throughput** — One HTTP round-trip per emit on happy path.  
→ **Resolution:** Accepted P2 limit (`PITFALLS_BACKLOG.md`) — capacity-plan collector ingest; no emit-side batching today. See §4.8.

av. **[RESOLVED] Offline queue memory** — Pending records in store **and** in-memory queue (~2×); global backoff blocks head-of-line batches.  
→ **Resolution:** Accepted P2 limit during outages. Future: per-batch retry, queue-only path. See §4.9.

aw. **[RESOLVED] Custom exporter errors** — Non-OTLP-shaped errors misclassified → wrong store/reject.  
→ **Resolution:** Accepted — custom exporters must return OTLP-shaped HTTP errors or `net.OpError`/timeout (`export_errors.go`). See §4.10.

ax. **[RESOLVED] Exception handler only logs** — Apps must use `EmitWithResult` / `AuditException.Status`.  
→ **Resolution:** Contract — `DefaultAuditExceptionHandler` logs only; branch on `EmitWithResult` status (`collector_rejected`, `collector_unreachable_stored`, etc.). See §4.11.

ay. **[RESOLVED] `SinkTimestamp` fallback** — May be `time.Now()` without real sink receipt.  
→ **Resolution:** Accepted P1 — not legal-grade proof of backend persistence. See §4.12.

az. **[RESOLVED] SDK validation / policy** — Required fields and policy limits reject before collector.  
→ **Resolution:** By design — validate at SDK before export; align app data with `AuditLogger` rules. See §4.13.

ba. **[RESOLVED] Path mismatch** — SDK default `/v1/audit` must match `auditlogreceiver.path`.  
→ **Resolution:** Contract — align URL path; 404 is HTTP error (`503 rejected`), not stored on emit. See §4.14.

bb. **[RESOLVED] Local verify ≠ Tier-2** — SDK pre-export check does not replace `certificatelogverify`.  
→ **Resolution:** By design — keys must match; collector verify is still required. See §4.15.

**Go SDK (open)**

_None — all SDK items **an–bb** resolved (implemented behavior, operator contract, or accepted P1/P2 limit per `PITFALLS_BACKLOG.md`)._

**Security**

bc. **Verify ≠ encrypt** — TLS for transit; integrity for tampering; payloads still readable in collector and at exporters.

bd. **Compromised collector host** — Attacker can read keys, WAL, hash chain, and DLQ from disk/memory.

be. **Replay** — Without hash chain, valid signed records can be replayed unless sink dedupes on `audit.record.id`.

bf. **Bypass ingest** — Direct access to exporters/backends skips receiver and verify processor.

---

## Quick reference: recommended safe defaults

| Layer | Setting | Why |
|-------|---------|-----|
| SDK | `WaitOnExport: true` (default); durable store (`-filestore` / Redis / SQL) for offline only | Sync emit when collector reachable; store-and-retry only on transport failure |
| SDK | `WithAuditRecordSigning(..., AuditSignContentMeta)` | Must match collector JCS canonicalization (not `body` or `attr` alone) |
| SDK OTLP | Default path `/v1/audit`; align with `auditlogreceiver.path` | Mismatched path → 404 / connection errors |
| Receiver | `response_mode: sync` | End-to-end delivery semantics; HTTP 200/400/503 map to outcomes |
| Processor | `mode: sync`, `failure_mode: strict` | Verify before export; reject tampered records; **only processor** in audit pipeline |
| Exporters | **`sending_queue.enabled: false` (required — do not enable)** | Must not add a competing persistent queue; use inline `retry_on_failure` during the sync request instead |
| Hash chain | Rely on sync per-record delivery + sequential emits per stream | See §3.4 |
| Sink | Dedupe on `audit.record.id` | SDK + collector are at-least-once; exactly-once is a sink responsibility |

See `receiver/auditlogreceiver/example-config.yaml` for a reference layout.

---

## 1. End-to-end pipeline pitfalls

### 1.1 Competing durability layers (SDK store + receiver WAL + exporter queue)

**Status: [RESOLVED]** — see summary items **a** and **c**.

**Risk:** Duplicate delivery, ambiguous HTTP semantics, or records stuck in multiple queues if an exporter `sending_queue` is enabled or the SDK store is used for the wrong failure type.

The SDK and collector each have durability for **different failure classes**:

| Situation | SDK behavior |
|-----------|--------------|
| Collector **reachable**, export succeeds | Record delivered; **not** stored |
| Collector **reachable**, HTTP error on emit (400/503/429, verify reject, fan-out failure, etc.) | Logged; **not** stored; `EmitWithResult` → `503` / `rejected` |
| Collector **unreachable** (DNS, TCP, timeout) on emit | Saved to `AuditLogStore`, queued, background retry; `503` / `stored` |
| Background export of **stored** record gets HTTP 503/429 | Store entry **retained**; batch re-queued with `RetryPolicy` backoff |
| Export succeeds but `RemoveAll` fails | Record may be re-exported after restart (`store_remove_failed`) |

**Collector sync mode:** WAL written before pipeline delivery, deleted on success; retained on transient collector 503.

**Pitfall (a, c):** Enabling exporter `sending_queue` adds a competing retry layer on top of SDK background retry and collector WAL.

**Required — do not enable exporter `sending_queue`:** Audit pipeline exporters **must not** use `sending_queue.enabled: true`. Persistent exporter queues compete with the SDK offline store and the receiver WAL and hide failures from the synchronous HTTP response. Use `sending_queue.enabled: false` and inline `retry_on_failure` (bounded by `max_elapsed_time`) so backend retry runs inside the sync request window. See `receiver/auditlogreceiver/example-config.yaml`.

**Pitfall (b):** After an offline period, the SDK backlog replays stored records while the collector may still hold WAL entries from partial failures — both paths can deliver the same `audit.record.id` if the sink is not idempotent.

**Resolution (b):** Accepted at-least-once contract. SDK store is populated **only** on transport failure, not on HTTP 503 from a reachable collector. Overlap is limited to crash/offline recovery paths; sinks must dedupe on `audit.record.id` (documented in SDK `AUDIT_LOG_README.md`).

**Mitigation:**
- SDK: store-and-retry **only** for transport failures; do not custom-wrap emit to retry HTTP 400/503 from a reachable collector.
- Receiver: `response_mode: sync` (WAL is crash recovery only).
- Exporters: **`sending_queue.enabled: false`** — do not enable for audit logs.
- Sink: treat `audit.record.id` as an idempotency key where at-least-once delivery is possible (`store_remove_failed`, WAL replay).

### 1.2 Multiple exporters (fan-out)

**Status: [RESOLVED]** — see summary item **d**.

**Risk:** With multiple exporters on the same pipeline, the collector fans out to all sinks. If one exporter fails transiently, the receiver returns **503** even if another exporter already accepted the data.

Documented in `sync_scenarios_test.go` (`TestSyncFanOutRetryDuplicatesSuccessfulSink`).

**Resolution (d):** This is **expected** for the sync SDK contract. When the collector is reachable and returns HTTP 503 (including fan-out failure), the SDK returns `collector_rejected` and **does not** persist the record to `AuditLogStore`. The SDK **only** stores when the collector is **unreachable** (DNS/TCP/timeout). The SDK will not automatically store-and-retry on fan-out 503.

The collector may retain a sync WAL entry on transient 503 for its own crash recovery; that is separate from SDK storage.

**Collector mitigation (still applies):** Prefer a single authoritative sink for audit records, or idempotent sinks on `audit.record.id` — not SDK store-and-retry on HTTP 503.

### 1.3 HTTP status semantics vs SDK expectations

**Status: [RESOLVED]** — see summary items **e** and **f**.

| Status | Meaning in collector sync mode | SDK behavior (`OnEmit`) |
|--------|-------------------------------|-------------------------|
| 200 | Verified and exported (or OTLP `partialSuccess` when batch has mixed results) | Success; `200 delivered`; record not stored |
| 400 | Permanent rejection (e.g. all records failed verification, or single-record verify fail) | HTTP error → **not stored**; `400 rejected` |
| 503 | Transient pipeline/backend failure; collector WAL retained | HTTP error on emit → **not stored**; `503 rejected` |
| 503 | Transport failure (unreachable host) | **Stored** for background retry; `503 stored` (`collector_unreachable_stored`) |

**Resolution (e):** `EmitWithResult` returns **both** `StatusCode` and `Status` string (`status.Map` in `sdk/auditlog/status/status.go`). Same HTTP code, different meaning:

| `StatusCode` | `Status` | Meaning |
|--------------|----------|---------|
| 503 | `rejected` | Collector reachable; HTTP error; **not** stored |
| 503 | `stored` | Collector unreachable; saved to `AuditLogStore` |

`testapp` logs `emit result: status=%d %s` — E2E scenarios 05/08/09 show `503 rejected` with reason *"audit records are logged and not stored"*. Documented in `opentelemetry-go/testlogs/README.md` (SDK durability summary).

**Resolution (f) — per-record and partial-batch notification:**

| Case | Collector HTTP | OTLP response |
|------|----------------|---------------|
| All records fail verify | **400** | Error body |
| Some pass, some fail (multi-record request) | **200** | `partialSuccess`: `rejected_log_records` + `error_message` JSON with `rejected_record_ids` |
| Single record fail (`testapp` default: one record per `Export()`) | **400** | Per-record `400 rejected` in `EmitWithResult` (scenarios 02, 07) |

Collector implementation: `splitLogsByRecord`, `writeOTLPPartialSuccessResponse` (`reciever.go`, `partial_batch_test.go`).

**Remaining edge case:** If the SDK sends **multiple records in one** `Export()`, `otlpexport/http.go` treats OTLP `partial_success` as a hard export failure (`partial_success not allowed`). Default `testapp` / `OnEmit` path is one record per export — not affected.

**Pitfall (e, historical):** Application code that treats all `503` from `EmitWithResult` as “stored for retry” without checking `Status == "stored"`.

### 1.4 Processor policy — no mutating processors

**Status: [RESOLVED]** — see summary item **g**.

**Policy:** The audit `logs` pipeline must contain **`certificatelogverify` only**. Do **not** add any other processors — especially mutating ones (`batch`, `queuebatch`, `attributes`, `transform`, `filter`, `resource`, custom mutators). Any mutation before or after verify breaks the signed JCS payload or allows tampering after verification.

**Required pipeline:**

```yaml
pipelines:
  logs/audit:
    receivers: [auditlogreceiver]
    processors: [certificatelogverify]
    exporters: [...]
```

#### Do not use `queuebatchprocessor` (core collector PR [#15500](https://github.com/open-telemetry/opentelemetry-collector/pull/15500))

`queuebatchprocessor` is the planned replacement for `batchprocessor`. It is **not** suitable for the sync audit pipeline even if configured with `wait_for_result: true`.

| Concern | `queuebatchprocessor` behavior | Audit pipeline requirement |
| ------- | ------------------------------ | -------------------------- |
| Async handoff | Default `wait_for_result: false` — returns before export completes | Sync end-to-end; HTTP 200/400/503 only after full delivery |
| Batching | Merges records (`min_size: 8192`, `flush_timeout: 200ms`) | One record per request; per-record verify and export outcomes |
| Extra queue | In-memory queue between verify and export | Single durability path: receiver WAL + SDK store only |
| Processor policy | Adds a second processor | `certificatelogverify` only |
| Integrity | Changes batch boundaries and timing after verify | JCS-signed payload must not be re-batched or delayed opaquely |
| HTTP semantics | Caller may succeed while export is still pending | 200 = verified **and** exported; 503 = real failure |
| Competing retry | Queue retries overlap WAL and inline exporter retry | `sending_queue.enabled: false`; bounded inline retry only |
| `MutatesData` | With `batch.enabled: false`, may pass read-only pdata to a mutating downstream processor | Direct sync chain into `certificatelogverify` |

Reference: `receiver/auditlogreceiver/example-config.yaml`, `opentelemetry-go/testlogs/README.md` rule 2.

### 1.5 Shared storage extension across components

**Status: [RESOLVED]** — see summary item **h**.

**Built-in key namespaces (today):**

| Consumer | Keys | Notes |
|----------|------|--------|
| `auditlogreceiver` (sync WAL) | `pending/`, `__pending_keys__` | Crash recovery only |
| `certificatelogverify` hash chain | `hash_chain/{stream_id}` | When `hash_chain.enabled: true` |
| `certificatelogverify` dead letter | `dead_letter/` (default) | Override with `dead_letter.key_prefix` |
| Exporter `sending_queue` | (varies) | **Must not be enabled** on audit pipeline |

**Implemented in `example-config.yaml`:** split extensions below (Redis db 0 = WAL, db 1 = processor metadata). **Multi-instance:** assign a unique db pair per collector replica (see §2.10).

**Resolution (h)**

```yaml
extensions:
  redis_storage/wal:
    endpoint: redis:6379
    db: 0
  redis_storage/audit_meta:
    endpoint: redis:6379
    db: 1

receivers:
  auditlogreceiver:
    storage: redis_storage/wal

processors:
  certificatelogverify:
    hash_chain:
      storage: redis_storage/audit_meta
    dead_letter:
      storage: redis_storage/audit_meta
      key_prefix: audit_verify_dlq/
```

Also required:
- `sending_queue.enabled: false` on all audit exporters.
- SDK `AuditLogStore` separate from collector Redis (app-side file/Redis/SQL with its own prefix).

**Do not**
   - Point exporter `sending_queue.storage` at the same extension as the receiver WAL.
   - Share collector Redis with SDK offline store using the same key prefix.
   - Run multiple collector replicas on one WAL backend without ingest partitioning (see pitfall **r**).

**Ops**
   - Document which extension ID backs WAL vs DLQ vs hash chain in runbooks.
   - Monitor key growth: `KEYS pending/*`, `hash_chain/*`, `{dead_letter.prefix}*` (or use Redis `SCAN` in production).

**When this pitfall is fully resolved:** `receiver/auditlogreceiver/example-config.yaml` implements the split: `redis_storage/wal` + `redis_storage/audit_meta`, explicit `dead_letter.key_prefix`, and `sending_queue.enabled: false` on audit exporters.

---

## 2. auditlogreceiver pitfalls

### 2.1 Storage extension is mandatory

**Status: [RESOLVED] — by design** — see summary item **i**.

Sync `auditlogreceiver` **requires** a storage extension. If `storage` is missing, the extension is not registered in `service.extensions`, or the backend is unreachable at startup, the receiver **must not** start — there is no ingest without a WAL.

This is intentional: sync mode always uses storage as a write-ahead log (persist → deliver → delete on success). Running without storage would remove crash recovery and violate the sync durability contract.

**Config:** `storage: redis_storage/wal` (or `file_storage`) in `example-config.yaml`. Do not disable or omit storage for production audit ingest.

### 2.2 WAL orphan entries after successful delivery

**Status: [RESOLVED] — mitigated by sink contract + monitoring logs** — see summary item **j**.

**Risk:** Duplicate delivery after restart if WAL delete fails after a successful pipeline run.

Flow: `persistPendingLogs` → pipeline succeeds (record at sink) → `deletePendingEntry` fails (storage error) → entry stays in WAL → `recoverSyncPending` redelivers on restart/shutdown.

**Resolution:**

1. **Idempotent sinks (required)** — Backends must **deduplicate on `audit.record.id`**: reject duplicates, upsert, or accept silently without a second durable write. Same contract as SDK `store_remove_failed` and pitfall **b**. Documented in `receiver/auditlogreceiver/README.md`.
2. **Monitor WAL logs and storage** — Alert on Redis/file storage errors, WAL pending key count (`pending/`, `__pending_keys__`), and collector logs:

| Log message | Level | Action |
|-------------|-------|--------|
| `Stored sync WAL entry` | Info | Normal — WAL write before delivery |
| `Cleared sync WAL entry after successful delivery` | Info | Normal — happy path |
| `Sync delivery failed, WAL entry retained for recovery` | Warn | Transient failure; expect client retry / recovery |
| `Delivered but failed to delete pending entry; downstream sinks must dedupe on audit.record.id` | Error | **Orphan risk** — sink may already have record; fix storage |
| `Recovered and cleared sync WAL entry` | Info | Recovery replay succeeded |
| `Recovery delivery failed, WAL entry retained` | Warn | Recovery blocked transiently |
| `Recovered but failed to delete pending entry; downstream sinks must dedupe on audit.record.id` | Error | **Orphan risk** after recovery replay |

3. **Ops** — Fix storage availability before restart when possible; after recovery replay, dedupe at sink prevents duplicate audit rows.

This is rare (storage glitch between deliver and delete) but possible; at-least-once delivery is by design, not exactly-once.

### 2.3 WAL retained on transient pipeline failure (by design)

**Status: [RESOLVED]** — see summary item **k** (same contract as **j**).

On **503** from a transient pipeline/backend failure, the sync WAL entry is **not** deleted. The client may retry; `recoverSyncPending` also replays on restart. This is correct at-least-once delivery; **sinks must deduplicate on `audit.record.id`**.

Monitor: `Sync delivery failed, WAL entry retained for recovery` (Warn) with `pending_key`.

### 2.4 Circuit breaker and sync ingest during outages

**Status: [RESOLVED]** — see summary item **l**.

When `circuit_breaker.enabled` is true (default), consecutive pipeline failures open the circuit. In **sync** mode, `circuit_breaker.open_behavior` controls new requests while the circuit is open:

| `open_behavior` | HTTP response | WAL | Client / SDK implication |
|-----------------|---------------|-----|---------------------------|
| **`reject`** (default) | **503** | Not written | Collector reachable → SDK returns `503 rejected` (not stored). App retries when backend recovers. No duplicate WAL from circuit-open rejects. |
| **`accept`** | **202** | Written | Collector accepted for deferred delivery. Delivery runs when circuit closes (`recoverSyncPending` / next successful path). App/SDK must treat **202** as accepted — do not auto-retry the same record unless you accept at-least-once overlap with recovery. **Sinks still dedupe on `audit.record.id`**. |

Verification failures (`rejected_verify_failed`) are permanent and do **not** trip the breaker for that record; backend outages do.

**Config example:**

```yaml
circuit_breaker:
  enabled: true
  circuit_open_threshold: 5
  circuit_open_duration: 1m
  open_behavior: reject   # or accept
```

**Monitoring:** `Circuit open; stored WAL entry and deferred delivery` (Info) when `open_behavior: accept`.

**Mitigation:** Tune `circuit_open_threshold` / `circuit_open_duration`; use `accept` during sustained backend outages when apps cannot tolerate 503 on valid records; use `reject` with SDK `WaitOnExport` when the app should retry explicitly.

### 2.5 Per-record delivery

The receiver splits each OTLP request into single-record batches (`splitLogsByRecord`) so partial success and per-record verification errors map to OTLP `partialSuccess`. This also allows hash-chain state to commit between records in the same HTTP request (see §3.4).

### 2.6 Partial batch success and verify failures

**Status: [RESOLVED]** — see summary items **f**, **m**, and **n**.

When some records fail verification and others pass in **one OTLP request**, sync mode returns **HTTP 200** with OTLP partial success:

- `rejected_log_records` — count of failed records
- `error_message` — JSON with `rejected_record_ids` and `rejected_records` (`batch.go`, `partial_batch_test.go`)

When **all** records fail verification, HTTP **400** is returned.

**Verify failures and DLQ (n):** Before returning the permanent `rejected_verify_failed` error, `certificatelogverify` writes each failed record to **processor DLQ** when `dead_letter.enabled: true` (see `example-config.yaml` — `redis_storage/audit_meta`, `key_prefix: audit_verify_dlq/`). The client gets **400**; ops inspect DLQ for forensic review. Enable `dead_letter.fail_on_storage_error: true` if DLQ write failure must fail the request instead of logging only.

**`testapp` / default SDK path:** one record per `Export()` — each failed record gets `400 rejected`, each success gets `200 delivered` (E2E scenarios 02, 07), not an OTLP partial-success response.

**Pitfall (historical):** Clients that only check HTTP status (not OTLP body) on multi-record requests treat failed records as accepted.

### 2.7 Corrupt WAL entries

**Status: [RESOLVED]** — see summary item **o**.

JSON unmarshal failures on WAL storage (corrupt `pending/` entry) are **not** silently deleted. The receiver:

1. Logs **Error**: `Corrupt WAL entry moved to dead letter` (`pending_key`, `dead_letter_key`, parse error).
2. Stores raw WAL bytes under `dead_letter/corrupt_{id}` in **receiver WAL storage** (same extension as `pending/`).
3. Removes the corrupt `pending/` key.

If DLQ write fails, logs `Failed to move corrupt WAL entry to dead letter` and retains the pending key for retry.

**Note:** Processor DLQ holds verify failures for parseable OTLP records; receiver `dead_letter/corrupt_*` holds unparseable WAL envelopes only.

### 2.8 Content-Type and protocol constraints

**Status: [RESOLVED] — by design** — see summary item **p**.

Tier-2 audit ingest is **OTLP logs export only**. The receiver enforces:

- **POST** only — other HTTP methods return a permanent error (`only POST method allowed`).
- **Content-Type** must be exactly one of:
  - `application/x-protobuf`
  - `application/vnd.google.protobuf`
  - `application/json`
- Body must be a valid OTLP `ExportLogsServiceRequest` (protobuf or JSON).

Arbitrary JSON audit blobs, custom schemas, or loose `Content-Type` matching are **intentionally rejected**. This is not a gap — it keeps the wire format aligned with the SDK OTLP exporter and `certificatelogverify` JCS pipeline.

### 2.9 TLS and mTLS on the ingest endpoint

**Status: [RESOLVED]** — see summary item **q**.

The receiver uses the collector `confighttp.ServerConfig` TLS stack. When `tls` is configured on `auditlogreceiver`, the server listens over **HTTPS** (`reciever.go` sets transport to `https`).

**Reference deployment (`example-config.yaml`):**

```yaml
receivers:
  auditlogreceiver:
    tls:
      cert_file: .../server.crt
      key_file: .../server.key
      client_ca_file: .../ca.crt   # mTLS — clients must present a cert signed by this CA
      min_version: "1.2"
```

**Verified in tests (`tls_test.go`):**

- `TestReceiverTLS` — HTTPS with server cert, client trusts CA
- `TestReceiverMTLSRejectsClientWithoutCert` — handshake fails without client cert when `client_ca_file` is set
- `TestReceiverMTLSAcceptsClientWithCert` — valid client cert accepted

**Note:** Factory defaults do **not** enable TLS. Production must set `tls` (and typically `client_ca_file` for mTLS). Complement with network policy or ingress restrictions as needed. SDK `AuditLogProcessor` must use matching client TLS (`WithTLS`, client cert) to reach the collector.

### 2.10 Multi-instance deployment

**Status: [RESOLVED]** — see summary item **r**.

**Risk (when sharing one DB):** Pending key index (`__pending_keys__`) and hash-chain commits are not coordinated across collector replicas. Two instances writing the same Redis **db** can race on WAL index updates and `hash_chain/{stream_id}` state (related pitfall **y**).

**Resolution:** Give **each collector instance its own storage partition**. For Redis, a dedicated **db** (or db pair) per instance is sufficient:

| Instance | `redis_storage/wal` | `redis_storage/audit_meta` |
|----------|---------------------|----------------------------|
| Collector A | `db: 0` | `db: 1` |
| Collector B | `db: 2` | `db: 3` |
| Collector C | `db: 4` | `db: 5` |

For file storage, use a **separate directory per instance** (no shared `pending/` or `hash_chain/` paths).

Within a **single** instance, continue to split WAL vs processor metadata (pitfall **h** — db 0 vs db 1 in `example-config.yaml`). Load-balancer affinity is optional when storage is already isolated per replica.

**Not required:** Single active ingest leader — per-instance DB isolation avoids cross-replica WAL/hash-chain races as long as each replica only uses its own db pair.

**Where to set per-instance “collections” (config, not receiver code):**

Redis does not use named collections like MongoDB — isolation is by **logical `db` number** and/or **key prefix**. You configure this in **collector YAML** and extension config structs; the audit receiver does not expose its own `pending/` namespace name.

| What | Where | Config field / code |
|------|--------|---------------------|
| Redis logical database per instance | `extensions.redis_storage/*` | `db` in `extension/storage/redisstorageextension/config.go` |
| Extra Redis key prefix per extension | same block | `prefix` → appended in `extension.go` `getPrefix()` |
| Which storage extension the WAL uses | `receivers.auditlogreceiver` | `storage:` → `StorageID` in `receiver/auditlogreceiver/config.go`; resolved in `reciever.go` `Start()` via `GetClient(..., r.cfg.StorageID, "auditlogreceiver")` |
| Processor DLQ / hash-chain backend | `processors.certificatelogverify` | `dead_letter.storage`, `hash_chain.storage` → `StorageID` in `processor/certificatelogverifyprocessor/config.go`; clients in `processor.go` `getStorageClient()` |
| DLQ key namespace (within one Redis db) | `dead_letter` block | `key_prefix` (e.g. `audit_verify_dlq/`) — `DeadLetterConfig.KeyPrefix` |
| File backend per instance | `extensions.file_storage/*` | `directory` in `extension/storage/filestorage/config.go` |

**Hardcoded key suffixes (not YAML-tunable today):**

| Keys | File | Constant |
|------|------|----------|
| WAL `pending/`, `__pending_keys__` | `receiver/auditlogreceiver/reciever.go` | `pendingKeyPrefix`, `pendingKeysListKey` |
| Receiver corrupt/permanent DLQ | same | `deadLetterKeyPrefix` (`dead_letter/`, `dead_letter/corrupt_*`) |
| Hash chain state | `processor/certificatelogverifyprocessor/hash_chain.go` | `hashChainKeyPrefix` (`hash_chain/`) |

Redis storage prepends an auto-generated prefix to every key: `{kind}_{componentType}_{componentName}_{clientName}` (see `redisstorageextension/extension.go`). Example full key shape: `receiver_redis_storage_wal_auditlogreceiver` + `pending/{uuid}`.

**Per-collector example (instance B uses db 2+3):**

```yaml
extensions:
  redis_storage/wal:
    endpoint: redis:6379
    db: 2
    prefix: collector_b          # optional extra isolation
  redis_storage/audit_meta:
    endpoint: redis:6379
    db: 3
    prefix: collector_b

receivers:
  auditlogreceiver:
    storage: redis_storage/wal

processors:
  certificatelogverify:
    hash_chain:
      storage: redis_storage/audit_meta
    dead_letter:
      storage: redis_storage/audit_meta
      key_prefix: audit_verify_dlq/
```

Each collector deployment uses its own config file (or env-specific overlay) with a unique `db` pair; no code change required unless you need configurable `pending/` prefixes on the receiver.

- Processed log counts in telemetry may not reflect only valid records.
- Interaction between receiver durability and exporter `sending_queue` is not fully analyzed (`reciever.go` TODOs).

---

## 3. certificatelogverify processor pitfalls

### 3.1 JCS canonicalization must match the signer exactly

**Status: [RESOLVED] — integration / configuration alignment, not a pipeline defect.**

This pitfall appears when the **SDK (or custom signer) and collector are not configured to the same contract**. The processor is doing the right thing: recompute canonical bytes and verify. `integrity_mismatch` means “signer and verifier disagreed on what was signed,” not “verification is broken.”

**Typical misconfiguration (fix in SDK/app config, not collector YAML alone):**

| Misconfiguration | Symptom |
|------------------|---------|
| SDK `AuditSignContentBody` or `Attr` but collector expects **meta** (default) | `integrity_mismatch` |
| SDK HMAC key ≠ collector `hmac_key_file` | `integrity_mismatch` |
| Custom OTLP / post-sign edits to timestamps or attributes | `integrity_mismatch` |
| Third-party signer with different canonical rules | `integrity_mismatch` |

**Correct setup:** SDK `WithAuditRecordSigning(..., AuditSignContentMeta)`, same key/cert as `certificatelogverify`, don’t mutate records after sign. Collector config is mostly `hmac_key_file` / `cert_file` + `mode: sync` — the JCS rules themselves are fixed in code on both sides.

**What this means in practice**

Verification is not “compare the log body” or “check a few fields”. The processor:

1. Rebuilds a **fixed JSON object** from the OTLP log record (`jcs_audit.go` → `jcsCanonicalAuditRecord`).
2. Runs **JCS** (JSON Canonicalization Scheme) on that JSON to get a **deterministic byte sequence**.
3. Computes HMAC or verifies a signature over those bytes.
4. Compares the result to `audit.integrity.value` on the log record.

The SDK signer does the same steps (`opentelemetry-go/sdk/auditlog/jcs_integrity.go`). If the canonical bytes differ by even one character, you get `integrity_mismatch` even when the record looks correct in a UI.

**Canonical payload shape (meta / default sign mode)**

Both SDK and processor include the same top-level keys when present (optional keys are **omitted when empty**):

| Field | Source on OTLP log record |
|-------|---------------------------|
| `timestamp` | `LogRecord.timestamp` (nanosecond UTC) |
| `observed_timestamp` | `LogRecord.observed_timestamp` (or `timestamp` if zero) |
| `event_name` | `LogRecord.event_name` |
| `audit.record.id` | log attribute |
| `audit.actor.id` / `.type` | log attributes |
| `audit.action` / `audit.outcome` | log attributes |
| `audit.target.id` / `.type` | log attributes (only if non-empty) |
| `audit.source.id` / `.type` | log attributes (SDK maps `SourceIP` → `audit.source.id` at sign time) |
| `body` | log body string (only if non-empty) |
| `audit.schema.version` | log attribute (only if non-empty) |
| `audit.sequence.number` | log attribute (only if > 0) |
| `audit.prev.hash` | log attribute (only if non-empty) |
| `attributes` | **all other** log attributes except `audit.integrity.*`, sorted by key then value |

Then `jcs.Transform(...)` produces the signed bytes. Attribute order in OTLP does **not** matter; sort order in the `attributes` array does.

**Excluded from canonical payload (never signed)**

- `audit.integrity.value`
- `audit.integrity.algorithm`
- Any other `audit.integrity.*` key

**Typical causes of `integrity_mismatch`**

| Cause | Example | Fix |
|-------|---------|-----|
| Wrong sign mode | SDK `WithAuditSignContent(body)` but collector verifies **meta** | Use `AuditSignContentMeta` (default in `testapp`) |
| Extra/missing optional field | Signer includes empty `audit.target.id`; collector omits empty keys | Match “omit when empty” rules on both sides |
| Duplicate semantics | `audit.record.id` only in struct field vs also in `attributes` | Let SDK export; don’t hand-edit OTLP |
| Timestamp drift | Re-sign after changing `timestamp` / `observed_timestamp` | Sign immediately before export; don’t mutate after sign |
| Non-string attribute encoding | Int/bool attr serialized differently SDK vs `AsString()` in collector | Use string attributes for signed fields |
| Integrity encoding | Hex vs base64 in `audit.integrity.value` | SDK defaults to base64; processor accepts both |
| Custom signer | Third-party signer with different JSON field names | Port signer to same `jcs_integrity.go` rules or add golden-vector tests |

**Concrete flow**

```
SDK Emit → sign(jcsCanonicalAuditRecord(record)) → OTLP HTTP → collector
         → jcsCanonicalAuditRecord(logRecord)     → same bytes? → pass/fail
```

**Mitigation**

- **SDK:** `WithAuditRecordSigning(..., AuditSignContentMeta)` and `WithAuditHMACVerificationKey` / cert signing aligned with collector `hmac_key_file` / `cert_file`.
- **Tests:** Golden-vector test — one signed OTLP JSON file, assert processor verify passes (`pipeline_integration_test.go` pattern).
- **E2E:** `testlogs` scenarios 01/02 (pass vs tamper) validate the full path.
- **Debug:** Log or dump canonical bytes on failure (temporary) and diff against SDK `jcsSigningPayload` output for the same record.

Reference implementations must stay in sync: `processor/.../jcs_audit.go` and `opentelemetry-go/sdk/auditlog/jcs_integrity.go`.

### 3.2 `audit.integrity.algorithm` lives on the resource

**Status: [RESOLVED] — skip for Go SDK; kept for traceability only.**

**Scope:** Out of scope for the standard **Go SDK → collector** pipeline. The SDK exports `audit.integrity.algorithm` on the **resource** and `audit.integrity.value` on the **log record** (`spec_alignment_test.go`). No collector or app change needed when using `go.opentelemetry.io/otel/sdk/auditlog` with signing enabled.

**Contract (processor behavior, unchanged):** `certificatelogverify` reads algorithm from resource attributes only (`audit_verify.go`). Wrong placement → `missing_integrity_algorithm` (HTTP 400).

**Only relevant if:** you build OTLP by hand or use a non-Go signer that puts algorithm on the log record — then set algorithm on `resource.attributes`, value on `logRecords[].attributes`.

### 3.3 Algorithm vs key material mismatch

**Status: [RESOLVED] — startup check + logging**

| `audit.integrity.algorithm` (in log) | Collector must have loaded |
|--------------------------------------|----------------------------|
| `HMAC-SHA256`, `HMAC-SHA512` | HMAC key (`hmac_key_file` or k8s HMAC entry) |
| `ECDSA-P256-SHA256`, `RSA-PKCS1-SHA256` | Certificate (`cert_file` or k8s cert entry) |

At **processor creation** (sync mode), `loadSyncVerificationKeys` (`verification_startup.go`):

1. Loads each **configured** key source; **fails startup** if a configured file/secret cannot be read.
2. Logs **Info** `Audit integrity verification ready` with:
   - `hmac_key_loaded` / `certificate_loaded`
   - `supported_algorithms` — list derived from what loaded successfully
3. Logs **Warn** if only HMAC or only cert is configured, listing `unsupported_algorithms` that will be rejected at ingest.

**Recommended:** Configure **both** `hmac_key_file` and `cert_file` (as in `example-config.yaml`) when apps may use either mode, and ensure the **same** key/cert the SDK uses. For a single-algorithm deployment, configure only the matching source and heed the startup warning.

Wrong key with correct algorithm type still yields `integrity_mismatch` at runtime (pitfall **t** / SDK alignment).

### 3.4 Hash chain and multi-record batches

**Status: [DEFERRED] — hash chain is experimental; do not enable in production.**

Keep `hash_chain.enabled: false` in `certificatelogverify` (default in `example-config.yaml`). Tier-2 audit today is **JCS integrity verification only**; replay protection relies on sink dedupe on `audit.record.id` (pitfall **be**). The pitfalls below are documented for when hash chain is productized — not current operator action items.

When hash chain **is** enabled (not recommended yet), validation reads **committed storage state** per `audit.source.id` stream. Commits happen **after** successful export to the next consumer.

Sync receiver splits each OTLP request into per-record pipeline calls, so multiple records for the same stream in **one HTTP request** can work if commits complete between records.

**Known issue (if enabled):** Multiple records for the same stream in one SDK `Export()` batch still run through the processor in a single `ConsumeLogs` — hash-chain validation for record N+1 uses storage from before record N is committed (see §3.5). Default SDK path exports one record per `Export()` call, which avoids this.

### 3.5 Hash chain commit after export

**Status: [DEFERRED] — hash chain is experimental; do not enable in production.**

**Config:** `hash_chain.enabled: false` (required for current Tier-2 deployments).

When hash chain is enabled (future), order in `ConsumeLogs` is:

1. Verify all records
2. Call `nextLogs.ConsumeLogs` (export)
3. `hashChain.commit` for each verified record

**Known risks (if enabled):** Export succeeds but commit fails → record is at backend but chain state lags → next record fails `prev_hash_mismatch`. Concurrent collector instances on shared hash-chain storage without per-instance partition (pitfall **r**) → chain corruption.

### 3.6 Hash chain optional fields

**Status: [DEFERRED] — only relevant when hash chain is enabled (experimental; keep disabled).**

- `audit.source.id` required on record or resource when hash chain enabled.
- `audit.sequence.number` must strictly increase when present.
- `audit.prev.hash` must match previous record’s integrity hash when chain state exists.
- First record in a stream must not set `audit.prev.hash` (or storage must be seeded).

Resetting storage breaks the chain for all streams.

### 3.7 `failure_mode: strict` vs `mark`

| Mode | On verification failure |
|------|---------------------------|
| `strict` (default) | Record removed; pipeline returns permanent error containing `rejected_verify_failed`; receiver maps to 400/OTLP partial |
| `mark` | Record annotated with `verify_status: failed` and passed downstream |

**Pitfall:** `mark` allows unverified/tampered records to reach exporters if sinks do not filter on `verify_status` / `tier2_status`.

### 3.8 Keys and certificates loaded once at startup

**Status: [RESOLVED] — accepted; no periodic reload required for Tier-2 today.**

HMAC key and certificate are read at processor **creation** (`loadSyncVerificationKeys` in `verification_startup.go`). K8s secrets are fetched once at startup (with retry), not watched.

**Current behavior:** Rotation requires a **collector restart** (or Kubernetes **rolling restart** of collector pods). Same key must be on SDK and collector before apps emit with the new secret.

**Recommendation: leave it like that for now**

| Approach | Pros | Cons |
|----------|------|------|
| **Startup load + rolling restart** (current) | Simple, predictable, no verify races, matches most K8s secret rotation runbooks | Brief window if SDK rotates before collector restarts → `integrity_mismatch` until pods pick up new key |
| **Poll every X / file watch / K8s watch** (not implemented) | No restart for key file or mounted secret updates | Needs atomic key swap, dual-key overlap during rotation, watch failures, harder to test; audit verify path must stay consistent per record |

**Ops runbook (recommended):**

1. Update secret / key file (or mount new K8s secret version).
2. **Rolling restart** collector replicas so each loads new material at startup (startup logs show `Audit integrity verification ready`).
3. Roll SDK/apps to use the **same** new key (or overlap: keep old key on collector until all SDKs rotated, then switch — requires dual-key support, which we do **not** have today).

**Future (optional):** `key_reload_interval` or filesystem/K8s watch with explicit **dual-key** transition window — only if operators cannot tolerate rolling restart. Not needed for initial Tier-2 production if rotation is rare and coordinated.

**Do not** add silent periodic reload without dual-key support: mid-request key swap can cause intermittent `integrity_mismatch` during rotation.

### 3.9 Certificate verification scope

**Status: [RESOLVED] — accepted limitation; no fix required for current Tier-2 (HMAC-first).**

The processor uses the configured PEM **only as a public key** to verify `audit.integrity.value` over the JCS payload (`verifySignatureProof` in `audit_verify.go`). It does **not** run TLS/PKI validation:

- Certificate expiry (`NotBefore` / `NotAfter`)
- Revocation (OCSP/CRL)
- Chain of trust / CA pinning
- Compromised-key detection (except by rotating the configured cert/key and restarting)

**Do you need to fix it?**

| Deployment | Need to fix? | Why |
|------------|--------------|-----|
| **HMAC-SHA256/512** (default `testapp`, `example-config`) | **No** | No X.509 involved; trust is the shared HMAC secret (§3.8 rotation). |
| **ECDSA / RSA signing** | **Optional hardening only** | Configured cert **is** the trust anchor (“verify with this public key”). Full PKI is usually unnecessary for an app signing key. |

**Possible solutions (if you want more later)**

| Option | Effort | Value |
|--------|--------|--------|
| **A. Accept as-is** (recommended now) | None | Matches “configured key = trust anchor”; document in runbooks; rotate on compromise. |
| **B. Startup expiry check** | Low | At `loadCertificate`, warn or fail if `time.Now()` outside `NotBefore`–`NotAfter`. Catches expired signing certs before ingest. |
| **C. Optional `ca_file` + chain verify** | Medium | Verify cert chains to a configured CA at startup (not per-record). |
| **D. OCSP/CRL** | High | Per-request or periodic revocation checks — rare for long-lived internal signing certs. |
| **E. Stay on HMAC** | None | Avoids §3.9 entirely for integrity verification. |

**Recommendation:** No code change for initial production. If you adopt asymmetric signing in production, add **B** (startup expiry warn/fail) first; defer **C/D** unless compliance requires full PKI.

### 3.10 Non-string attribute canonicalization

**Status: [RESOLVED]** — see summary item **ad**.

**Problem:** Custom attributes in the JCS `attributes` array must be strings in canonical JSON. If the collector used `Str()` (string OTLP type only) for top-level fields but `AsString()` elsewhere, or if encoding differed from the SDK signer, verification failed with `integrity_mismatch`.

**Fix (processor):** `canonicalAttrString` in `jcs_audit.go` is used for all attribute reads (top-level `audit.*` fields and `attributes[]` entries):

| OTLP type | Canonical form |
|-----------|----------------|
| String | as-is |
| Int | decimal string |
| Bool | `true` / `false` |
| Double | `%g` (`strconv.FormatFloat`, aligned with Go SDK `log.Value.String()`) |

**Contract (operators / SDK):**

- **Prefer string attributes** for custom signed metadata when using `go.opentelemetry.io/otel/sdk/auditlog` (default audit fields are already strings).
- Int/bool/double are supported when the signer used the same type and encoding rules.
- Do not rely on map/slice/bytes attributes in signed payloads — use strings.

`audit.sequence.number` stays a JSON number via `attrInt`, not `canonicalAttrString`.

Tests: `jcs_audit_test.go` (`TestCanonicalAttrStringPrimitives`, `TestJcsCanonicalAuditRecordTypedCustomAttributes`).

### 3.11 `audit.integrity.value` encoding

**Status: [RESOLVED]** — see summary item **ae**.

**Problem:** `audit.integrity.value` carries the HMAC or signature as a string attribute (excluded from the JCS signed payload). If the signer encodes bytes as hex but the verifier expects base64 (or the string is corrupted), verification fails with `invalid_integrity_encoding` or `integrity_mismatch`.

**Processor behavior (`audit_verify.go`):** `decodeHexOrBase64` tries **hex** first, then **base64** (standard encoding). Whitespace around the value is trimmed before decode.

| Encoding | When to use |
|----------|-------------|
| **Base64** | **Default for Go SDK** (`encodeIntegrityValue` in `go.opentelemetry.io/otel/sdk/auditlog`) — preferred in production |
| **Hex** | Accepted for unit tests and custom signers |

**Contract:**

- Standard **Go SDK → collector** pipeline: no action required; SDK base64 matches processor decode.
- Custom signers: pick **one** encoding and keep it consistent end-to-end.
- Hex-first decode means a string that is valid hex is always interpreted as hex (ambiguous dual-encoding strings are unlikely for real MAC/signature output).

**Failure reasons:** `invalid_integrity_encoding` (neither hex nor base64 decodes), `integrity_mismatch` (decoded bytes do not match recomputed proof).

Tests: `audit_verify_test.go` (`TestDecodeHexOrBase64`, `TestVerifyIntegrityHMACSHA256_Base64`).

### 3.12 Processor mutates records after verification

**Status: [RESOLVED]** — see summary item **af**.

**Behavior:** After verification, the processor stamps outcome metadata on each log record (`MutatesData: true`). Stamping runs **after** `verifyAuditLogRecord`; it does not affect the first-pass integrity check.

| Attribute | Pass | Fail (`mark`) | Deferred |
|-----------|------|---------------|----------|
| `verify_status` | `passed` | `failed` | `deferred` |
| `verify_reason` | `ok` | e.g. `integrity_mismatch` | `deferred_by_policy` |
| `verify_details` | — | error text | — |
| `verified_at` | RFC3339Nano | RFC3339Nano | empty |
| `verification_profile` | from config | from config | from config |
| `tier2_status` | `verified_queued` | `rejected_verify_failed` | `accepted_pending_verify` |
| `export_status_overall` | mirrors `tier2_status` | mirrors `tier2_status` | mirrors `tier2_status` |
| `last_state_change_at` | RFC3339Nano | RFC3339Nano | RFC3339Nano |

**JCS exclusion (`jcs_audit.go`):** Outcome keys and `audit.integrity.*` are excluded from the canonical `attributes` array via `isExcludedFromJCS`. Re-feeding a stamped record through `certificatelogverify` (replay, DLQ re-ingest) does not change the signed payload.

**Sink / operator contract:**

- Index or route on `tier2_status` and `verify_status`.
- With `failure_mode: mark`, **filter out** `verify_status != passed` before durable storage unless you intentionally retain failed copies.
- Do not run two `certificatelogverify` processors in series on the same audit stream without understanding stamped attrs (safe with JCS exclusion, but redundant).

Tests: `processor_outcome_test.go`, `jcs_audit_test.go` (`TestCollectNonIntegrityAttributesExcludesOutcomeAttributes`).

### 3.13 Dead letter queue pitfalls

**Status: [RESOLVED]** — see summary items **ag–al**.

Processor DLQ (`dead_letter.go`) persists verification failures to a storage extension before the pipeline returns `rejected_verify_failed` (strict) or continues (mark). Each optional setting has operator-facing constraints — not bugs, but easy to misconfigure.

#### Production runbook (sync audit)

| Setting | Default | Recommendation |
|---------|---------|----------------|
| `enabled` | `false` | **`true`** when verify failures must be inspectable (pairs with receiver HTTP 400 on strict) |
| `storage` | — | Dedicated extension or Redis db (e.g. `redis_storage/audit_meta`, separate from receiver WAL — §1.5) |
| `key_prefix` | `dead_letter/` | **Unique prefix** (e.g. `audit_verify_dlq/`) when sharing a backend with WAL or hash chain |
| `fail_on_storage_error` | `false` | **`true`** in production if losing a DLQ entry is unacceptable; `false` = log and continue |
| `deduplicate_by_record_id` | `false` | Keep **`false`** unless you want last-failure-wins per `audit.record.id` (overwrites prior key) |
| `partition_by_stream` | `false` | **`true`** only when every failed record has `audit.source.id` (else store returns error) |
| `maintain_index` | `false` | Keep **`false`** with multiple collector replicas; use storage `SCAN` on `key_prefix` instead |
| `ttl` | `0` | Optional **metadata hint** in each JSON entry — **no automatic expiry**; run external cleanup |
| `max_entry_size_bytes` | `0` (unlimited) | Set a cap (e.g. 256KB–1MB); oversized marshal fails DLQ write |
| `include_record` / `include_resource` | `true` | Set `false` if payloads are large and metadata (`verify_reason`, `audit_record_id`) is enough |

Reference config: `receiver/auditlogreceiver/example-config.yaml` (`redis_storage/audit_meta`, `key_prefix: audit_verify_dlq/`).

#### Per-setting pitfalls

| Setting | Pitfall | Mitigation |
|---------|---------|------------|
| `fail_on_storage_error: false` | DLQ write failure is logged; client may still get **400** / record dropped without durable copy | `fail_on_storage_error: true` when DLQ is part of your compliance path |
| `deduplicate_by_record_id` | Requires `audit.record.id`; same ID **overwrites** prior DLQ entry | Disable unless overwrite semantics are intended |
| `partition_by_stream` | Requires `audit.source.id` (log record or resource) | Ensure SDK exports `audit.source.id`; disable partition if missing |
| `maintain_index` | `__dead_letter_index__` is read-modify-write; **not atomic** across replicas; global index key (not under `key_prefix`) | Single writer or `maintain_index: false` + prefix scan |
| `ttl` | Written as `ttl` field in JSON only — **no automatic deletion** in storage | External job: delete keys older than hint or by `stored_at` |
| `max_entry_size_bytes` | Entry marshal exceeds cap → DLQ error; fails pipeline if `fail_on_storage_error: true` | Size limit + trim `include_record` / `include_resource` |

**Storage isolation:** Use a dedicated `dead_letter.key_prefix` or storage extension/db when sharing a backend with the receiver WAL (`dead_letter/corrupt_*`) or hash chain (`hash_chain/`). See §1.5, §2.6.

Tests: `dead_letter_test.go` (`TestDeadLetterStoresFailedRecord`, `TestDeadLetterPartitionByStream`, `TestConsumeLogsWritesDeadLetterOnFailure`).

### 3.14 `dead_letter.reasons` filtering

**Status: [RESOLVED]** — see summary item **am**.

When `dead_letter.reasons` is non-empty, only listed `verify_reason` values are stored. Failures outside the list are **not** captured in DLQ (silent skip — verify behavior unchanged). Empty or omitted `reasons` stores all failure reasons.

`dead_letter.failure_modes` applies the same allowlist pattern to processor `failure_mode` (`strict` / `mark`); default is both.

**Contract:** Omit `reasons` for full forensic capture. Use an explicit list only to reduce DLQ volume. Pair with log/metrics review so filtered reasons are not mistaken for “no failures.”

Tests: `dead_letter_test.go` (`TestDeadLetterReasonFilter`).

---

## 4. Go SDK (`sdk/auditlog`) pitfalls

Cross-reference: `opentelemetry-go/sdk/auditlog/PITFALLS_BACKLOG.md`. **Resolved** in the SDK repo: connection vs HTTP 503 semantics, strict startup/TLS, inline HTTP retry, `AuditException.Status`, stored-then-HTTP-fail purge, background retry on 503/429, export circuit + resync, duplicate-delivery contract. **P1/P2** items below are accepted limits or operator contracts, not open correctness bugs.

### 4.1 In-memory store is not crash-safe

**Status: [RESOLVED] — accepted; use durable store when needed.**

Default in-memory `AuditLogStore` loses queued records on process restart (`PITFALLS_BACKLOG.md` P1).

**Mitigation:** Use `NewAuditLogFileStore`, `-filestore`, Redis, SQL, or another durable backend when the collector can be offline.

### 4.2 `sign_content` mode must be `meta` for collector verify

**Status: [RESOLVED] — contract.**

The SDK supports three signing payloads via `WithAuditRecordSigning` / `WithAuditSignContent`:

| Mode | Signed payload |
|------|----------------|
| `meta` (default) | Full JCS audit record (timestamps, event, `audit.*` fields, body, attributes) |
| `body` | JCS-wrapped body only |
| `attr` | JCS-sorted attributes only |

`certificatelogverify` always verifies the **full meta canonical form** (`jcs_audit.go`). Signing with `body` or `attr` produces `integrity_mismatch` at the collector.

**Contract:** `AuditSignContentMeta` (default in testapp).

### 4.3 JCS / encoding alignment with the processor

**Status: [RESOLVED] — Go SDK + collector contract aligned; golden vectors recommended.**

Both SDK and processor use `github.com/deszhou/jcs` and the same timestamp layout. Remaining `integrity_mismatch` causes are misconfiguration or non-Go signers:

- Different `sign_content` mode (§4.2)
- SDK signs with fields present at sign time but OTLP export omits or relocates them (e.g. `audit.integrity.algorithm` must be on the **resource**, not the log record — SDK `spec_alignment_test.go` enforces this)
- SDK default integrity encoding is **base64** (`encodeIntegrityValue`); processor accepts hex or base64 (§3.11)
- Non-string attribute values — collector uses `canonicalAttrString` aligned with SDK (§3.10)
- `audit.source.id` in canonical payload comes from `AuditRecord.SourceIP` in the SDK; must match the exported `audit.source.id` attribute

**Mitigation:** Golden-vector tests across SDK sign → OTLP export → processor verify.

### 4.4 OTLP inline HTTP retry stacks with collector retry

**Status: [RESOLVED] — implemented in SDK.**

Default audit OTLP HTTP retry: `InitialInterval` 200ms, `MaxElapsedTime` 750ms per `Export()` (`otlpexport/retry.go`). Disable with `otlpexport.WithHTTPRetry(false)` if double-retry causes confusing latency or duplicate attempts at the HTTP layer (collector WAL still applies separately).

### 4.5 Startup TLS vs offline collector

**Status: [RESOLVED] — implemented in SDK; deployment contract.**

`AuditLogProcessorBuilder.Build()` verifies TLS trust and client cert config when using HTTPS. Invalid TLS credentials prevent startup even if the collector is temporarily down.

`otlpexport.WithStrictStartupVerify(true)` requires the collector to be reachable at startup (TCP for HTTP, TLS handshake for HTTPS). Without strict mode, an offline collector is tolerated at startup.

**Contract:** Strict startup in dynamic environments (K8s rollouts) can block app start; non-strict allows start but first emits may hit store-and-retry.

### 4.6 Export circuit after `MaxAttempts`

**Status: [RESOLVED] — implemented in SDK.**

When background export exhausts `RetryPolicy.MaxAttempts` (default `0` = unlimited per cycle), the export circuit opens for `CircuitOpenDuration` (defaults to `MaxBackoff`), pauses export, then half-opens and resyncs store records into the queue.

**Symptoms:** `export_circuit_open`, `export_max_attempts_exceeded` via `AuditException.Status`; backlog stalls until cooldown.

### 4.7 `store_remove_failed` — export succeeded, store did not compact

**Status: [RESOLVED] — at-least-once contract.**

`RemoveAll` runs only after successful export. If export to the collector succeeded but store removal fails, the record remains in the store and may be **re-exported** after restart or circuit resync.

**Contract:** Sink must dedupe on `audit.record.id`; monitor `store_remove_failed` exceptions.

### 4.8 Per-record sync export limits throughput

**Status: [RESOLVED] — accepted P2 limit.**

When the collector is reachable, each `OnEmit` calls `Exporter.Export` with a **single-record** batch. Throughput is roughly one HTTP round-trip per audit event per goroutine — no emit-side batching on the happy path.

High-volume services need capacity planning for collector ingest rate and connection pooling.

### 4.9 Background queue (offline retry only): head-of-line blocking and 2× memory

**Status: [RESOLVED] — accepted P2 limit.**

During outages:

- Records exist in both `AuditLogStore` **and** the in-memory FIFO queue until export succeeds and `RemoveAll` runs (~2× memory for pending records).
- A single global retry backoff counter is shared across queued batches — a stuck head batch delays later records (`PITFALLS_BACKLOG.md` P2).
- `ForceFlush` polls every 10ms while the queue is non-empty under retry backpressure.

**Future mitigations (SDK backlog, not implemented):** emit-side micro-batching, per-batch retry state, queue-only pending path.

### 4.10 Custom exporter error classification

**Status: [RESOLVED] — accepted; exporter contract.**

`isExportConnectionFailure` treats HTTP response errors (messages containing `failed to send logs to`, `body:`, `partial success`) as **not** connection failures. Custom exporters must return OTLP-shaped HTTP errors or underlying `net.OpError`/timeout errors for correct store-vs-reject behavior.

### 4.11 Exception handler vs `EmitWithResult`

**Status: [RESOLVED] — app contract.**

`DefaultAuditExceptionHandler` only logs via `otel.Handle`. Production apps must branch on `EmitWithResult` status / `AuditReceipt` and `AuditException.Status` (`collector_rejected`, `collector_unreachable_stored`, `store_save_failed`, etc.) — not only on log lines.

### 4.12 `200 delivered` without sink receipt

**Status: [RESOLVED] — accepted P1 limitation.**

`SinkTimestamp` may fall back to `time.Now()` when the exporter returns no receipt. Do not use it as legal-grade proof of backend persistence.

### 4.13 SDK-side validation rejects before export

**Status: [RESOLVED] — by design.**

`AuditLogger` validates required fields before emit: timestamp, event name, actor/type, action, resource, outcome, body, attributes, `record_id`, hash, signature or HMAC, `schema_version`. Policy options (`WithAuditMaxBodyBytes`, `WithAuditMaxAttributeCount`, `WithAuditMaxRequestsPerSecond`, `WithAuditAuthorizer`) can reject records before they reach the collector.

### 4.14 Endpoint and path alignment

**Status: [RESOLVED] — deployment contract.**

SDK OTLP HTTP default path is `/v1/audit` (`otlpexport/http.go`). Collector default is the same, but misconfigured `path` / URL causes 404s classified as HTTP errors (not stored on emit).

### 4.15 SDK integrity verification vs Tier-2 verify

**Status: [RESOLVED] — by design.**

The SDK can verify HMAC/signature locally in `AuditLogger` before export (`WithAuditHMACVerificationKey`, etc.). Tier-2 verification still happens at `certificatelogverify`. Local and collector keys must match; local pass does not skip collector verify.

**Note:** Full mTLS chain is covered in `otlpexport/verify_test.go`; `testlogs` mock receiver is plain HTTP (`PITFALLS_BACKLOG.md` P3).

---

## 5. Security and tampering considerations

### 5.1 Verify is not encrypt

TLS protects in transit; `certificatelogverify` protects integrity of signed fields. Payloads are readable inside the collector process and at exporters.

### 5.2 Compromised collector host

An attacker with collector filesystem access can read HMAC keys, certificates, WAL, hash-chain state, and DLQ. Host hardening and secret management (K8s secrets, restricted mounts) are required.

### 5.3 Replay attacks

Hash chain mitigates reordering/replay **per stream** when enabled and correctly sequenced. Without hash chain, replay of a valid signed record may succeed unless the backend deduplicates on `audit.record.id`.

### 5.4 Bypass ingest

Applications that can reach exporters or backends directly, bypassing the audit receiver and verify processor, undermine Tier-2 guarantees. Network policy and sink authentication are out of scope for these components but required operationally.

---

## 6. Operational checklist

Before production:

- [ ] SDK: `WaitOnExport: true`, durable store for offline scenarios, `AuditSignContentMeta` signing
- [ ] SDK: `EmitWithResult` handling for `collector_rejected` vs `collector_unreachable_stored`
- [ ] SDK/collector path `/v1/audit` aligned; **receiver mTLS** configured (`tls` + `client_ca_file` on `auditlogreceiver`; SDK client cert matches CA)
- [ ] `response_mode: sync` on `auditlogreceiver`
- [ ] Audit pipeline: `certificatelogverify` **only** — no other processors
- [ ] `certificatelogverify.mode: sync`, `failure_mode: strict` (or explicit `mark` + sink filtering)
- [ ] Exporter **`sending_queue.enabled: false`** (required — do not enable) for audit pipeline
- [ ] Sink deduplicates on `audit.record.id`
- [ ] Separate storage namespaces: SDK store prefix; per-collector Redis db pair (or file dir); within each instance WAL vs audit_meta split (pitfalls **h**, **r**)
- [ ] Single collector exporter or idempotent sink
- [ ] Golden-vector tests: SDK sign → OTLP → processor verify
- [ ] Key rotation runbook: update secret → rolling restart collector → roll SDK to same key (no hot reload today; see §3.8)
- [ ] `circuit_breaker.open_behavior` chosen: `reject` (503, SDK retries) vs `accept` (WAL + 202 during outages)
- [ ] `certificatelogverify.dead_letter.enabled: true` for verify-failure forensics (pitfall **n**)
- [ ] Monitoring: SDK queue depth, `store_remove_failed`, collector 400/503/202, circuit breakers (SDK + receiver), WAL pending keys, processor DLQ + receiver `dead_letter/corrupt_*`, DLQ growth
- [ ] Runbook for storage loss (SDK store replay, WAL replay, hash chain reset)

---

## 7. Related files

| File | Purpose |
|------|---------|
| `opentelemetry-go/testlogs/README.md` | E2E test rules, SDK `503 rejected` vs `503 stored`, scenario results |
| `opentelemetry-go/sdk/auditlog/AUDIT_LOG_README.md` | SDK delivery model, store contract, config defaults |
| `opentelemetry-go/sdk/auditlog/PITFALLS_BACKLOG.md` | SDK-known pitfalls and performance limits |
| `opentelemetry-go/sdk/auditlog/jcs_integrity.go` | SDK JCS canonical payload (must match processor) |
| `opentelemetry-go/sdk/auditlog/export_errors.go` | Connection vs HTTP error classification |
| `receiver/auditlogreceiver/example-config.yaml` | Recommended sync pipeline comments and sample config |
| `receiver/auditlogreceiver/reciever.go` | Sync delivery, WAL, circuit breaker |
| `processor/certificatelogverifyprocessor/README.md` | Processor config and verify_reason reference |
| `processor/certificatelogverifyprocessor/jcs_audit.go` | Collector canonical payload definition |
| `receiver/auditlogreceiver/sync_scenarios_test.go` | Fan-out, partial batch, WAL, circuit breaker tests |
| `receiver/auditlogreceiver/tls_test.go` | TLS and mTLS ingest tests |

---

*Sync-pipeline scope. Generated from codebase analysis of `sdk/auditlog`, `auditlogreceiver` (`response_mode: sync`), and `certificatelogverifyprocessor` (`mode: sync`). Revisit when changing delivery rules, hash chain behavior, or exporter queue defaults.*
