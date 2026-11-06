# Sentinel Remediation Engine (Go)

A test-driven Go reference implementation of a security telemetry → remediation → audit/metrics pipeline.

This repository provides:

- **Domain model** for security findings (`Vulnerability`) and remediation lifecycle state (`AgentState`).
- **Neurosymbolic guardrails** to reject suspicious/unsafe patch content.
- **Remediation workflow engine** with explicit phases and rollback states.
- **Telemetry ingestion buffer** to simulate cross-account event ingestion.
- **Immutable write-ahead audit ledger** for compliance-grade traceability.
- **Prometheus-style metrics endpoint** (`/metrics`).
- **Unit + chaos + real-world scenario tests** plus an end-to-end test.
- **AWS CDK scaffolding** (demo IaC, not required to run tests).

> Note: `go.mod` targets **Go 1.22** (`go 1.22`). You can build and test with newer Go versions; CI is pinned to **Go 1.22.x**.

---

## Repository Layout

```
.
├── main.go
├── main_e2e_test.go
├── go.mod
├── go.sum
├── controller/
│   ├── controller.go
│   └── secret_broker.go
├── domain/
│   └── domain.go
├── storage/
│   ├── ledger.go
│   ├── metrics.go
│   └── telemetry.go
├── workflow/
│   ├── chaos_validation_test.go
│   ├── engine.go
│   ├── engine_test.go
│   ├── gatekeeper.go
│   └── realworld_validation_test.go
├── cdk/
│   ├── cdk.json
│   └── cdk_infrastructure.go
└── .github/
    └── workflows/
        ├── ci.yml
        └── deploy.yml
```

---

## Architecture (End-to-End)

### 1) Telemetry Ingestion

- File: `storage/telemetry.go`
- Type: `storage.TelemetryBuffer`

`TelemetryBuffer.IngestStream(...)`:

- Appends events to an in-memory queue (`EventQueue`).
- Converts a telemetry event into a `domain.Vulnerability`.
- Calls `domain.SecurityWorkflowPort.ProcessAlert(...)` asynchronously.

This simulates cross-account telemetry ingestion without requiring a real stream (Kinesis, Kafka, etc.).

### 2) Guardrails / Verification

- File: `controller/controller.go`
- Type: `controller.VerificationController`

`VerifyEpistemicGuardrails(...)` inspects the proposed patch payload and blocks common dangerous patterns (e.g. `rm -rf`, `curl | bash`). It also enforces invariants such as `PRESERVE_MEDIA_INGESTION_FLOW`.

This models the safety layer you’d want before allowing automated changes to proceed.

### 3) Remediation Workflow Engine

- File: `workflow/engine.go`
- Type: `workflow.RemediationEngine`

`ExecuteRemediationLoop(ctx, vuln, patch, forceFailure)` returns an `*domain.AgentState` and a possible error.

Lifecycle phases:

- `ANALYSIS`
- `PATCHING`
- `VERIFYING`
- `COMPLETED`
- `ROLLED_BACK`

Rollback triggers:

- Guardrail rejection (`VerifyEpistemicGuardrails` fails)
- Forced failure mode (`forceFailure=true`) to model sandbox/test failures

### 4) Audit Ledger

- File: `storage/ledger.go`
- Type: `storage.ImmutableLedger`

Every remediation attempt is committed via `CommitStateToLedger(...)`.

The ledger writes a write-ahead log line with the fields:

- Timestamp
- Task ID
- Phase
- TraceCount

Example line:

```
[2026-11-06T14:40:36-08:00] Task: TX-LOCAL-FAIL | Phase: ROLLED_BACK | TraceCount: 3
```

### 5) Prometheus Metrics

- File: `storage/metrics.go`
- Function: `storage.StartMetricsServer(address)`

Exposes `/metrics` in Prometheus text format, including:

- `sentinel_ingested_events_total`
- `sentinel_patches_applied_total`
- `sentinel_rollbacks_triggered_total`

---

## CLI Runtime (main.go)

The repo is runnable as a small demo service.

### Start metrics server

```powershell
go run . --metrics-addr :9090
```

- Metrics endpoint: `http://localhost:9090/metrics`
- Stop with `Ctrl+C`

### Simulate safe event

```powershell
go run . --metrics-addr :9090 --simulate
```

Expected:

- `sentinel_ingested_events_total 1`
- `sentinel_patches_applied_total 1`
- ledger contains `TX-LOCAL-0001 | Phase: COMPLETED`

### Simulate rollback events

Poisoned patch rollback (guardrails):

```powershell
go run . --metrics-addr :9090 --simulate-poisoned
```

Forced failure rollback (engine failure path):

```powershell
go run . --metrics-addr :9090 --simulate-force-failure
```

Both rollback modes together:

```powershell
go run . --metrics-addr :9090 --simulate-rollbacks
```

### Truncate ledger on startup

For clean demos (fresh audit log each run):

```powershell
go run . --metrics-addr :9090 --simulate-rollbacks --truncate-ledger
```

### Custom ledger path

```powershell
go run . --metrics-addr :9090 --simulate --ledger .\twitch_security_audit.log
```

---

## Testing

### Format

```powershell
go fmt ./...
```

### Run all tests (unit + chaos + realworld + E2E)

```powershell
go test -v ./...
```

### Run workflow tests only

```powershell
go test -v ./workflow
```

### Run only E2E test

```powershell
go test -v -run TestEndToEnd_HolisticSecurityPipeline .
```

---

## CI (GitHub Actions)

Workflows:

- `.github/workflows/ci.yml`
  - gofmt check
  - `go mod tidy`
  - `go test -v ./...`

- `.github/workflows/deploy.yml`
  - similar verification flow

Both are pinned to `go-version: 1.22.x` to align with the `go 1.22` directive in `go.mod`.

---

## IaC (AWS CDK scaffolding)

The `cdk/` directory contains a demo AWS CDK stack definition. It is optional for testing and does not run in unit tests.

- `cdk/cdk.json`
- `cdk/cdk_infrastructure.go`

To use CDK in practice, you’d typically also install/configure the AWS CDK CLI and credentials, and run synth/deploy flows.

---

## Notes / Next Steps

Potential next increments for a production-grade system:

- Replace in-memory telemetry queue with a real stream (Kinesis/Kafka/SQS) and add replay/idempotency.
- Expand `VerifyEpistemicGuardrails` with AST-based checks and policy bundles.
- Add structured audit records (JSON lines) in addition to human-readable logs.
- Add real remediation patch generation and sandbox verification (container/VM).
- Wire metrics increments into more points (latency histograms, phase transitions).

