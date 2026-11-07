# Sentinel Remediation Engine

A Go reference service for security-event ingestion, policy-gated dependency remediation, isolated verification, audit logging, and operational metrics.

## Capabilities

- AWS Kinesis `PutRecord` publishing and shard polling.
- At-least-once stream processing with local JSONL state for development or shared DynamoDB checkpoints, shard leases, and event-ID idempotency for coordinated consumers.
- Bounded exponential retries and durable SQS dead-letter handoff; failed records are checkpointed only after a successful remediation or confirmed DLQ send.
- Constrained remediation that upgrades an existing Go module dependency and verifies the proposed `go.mod` in an isolated Docker container.
- Policy-bundle guardrails, rollback states, human-readable and JSONL audit records, and Prometheus metrics.
- Unit, chaos, real-world scenario, and end-to-end Go tests.

The module targets Go 1.26 (`go 1.26.0`). Install Go 1.26.x. The AWS CDK scaffold is optional for building and testing the service.

## Layout

```text
controller/       policy bundle, guardrails, secret rotation
domain/           vulnerability and remediation state types
storage/          Kinesis, checkpoints, idempotency, audit, metrics
workflow/         patch generation, Docker verification, engine, tests
cdk/              optional AWS CDK scaffold
main.go           CLI service entry point
main_e2e_test.go  pipeline integration test
```

## Processing and delivery semantics

`KinesisConsumer` discovers shards, obtains iterators, and processes records in shard sequence order. For each record it:

1. Decodes `SecurityTelemetryEvent` JSON. If `event_id` is absent, it derives a stable ID from stream, shard, and sequence number.
2. Claims the ID in `IdempotencyIndex`. Completed IDs are skipped; a concurrently in-flight ID is an error and is not checkpointed.
3. Runs remediation and commits its audit state.
4. Persists the Kinesis sequence checkpoint only after event handling succeeds.

This provides **at-least-once delivery with idempotent handling**, not a distributed exactly-once transaction. In local mode, JSONL checkpoint and idempotency files are for a single consumer only and must be retained together. Do not share these files between processes. With `--dynamodb-table`, DynamoDB conditional writes coordinate per-shard leases, checkpoint ownership, and event claims across consumers. Shard and event claims are renewed during long-running sandbox verification; conditional owner/token checks fence stale consumers. A claim is considered completed only after remediation and audit commit succeed. DynamoDB TTL eventually expires completed idempotency entries after the configured retention period; a replay after expiration can be processed again.

An event should include these fields:

```json
{
  "event_id": "TX-7709",
  "aws_account_id": "112233445566",
  "microservice": "video-ingest-api",
  "payload": "dependency vulnerability detected",
  "dependency": "<existing-module-in-go.mod>",
  "fixed_version": "<higher-published-version>",
  "timestamp": "2026-11-06T21:00:00Z"
}
```

Processing failures are retried up to `--max-record-attempts` with capped exponential backoff. Malformed JSON is non-retryable and is handed off once. After attempts are exhausted, the original record bytes, source coordinates, decoded event (if valid), failure, and attempt count are written to SQS. The consumer advances its checkpoint only after SQS confirms the send; if DLQ delivery fails, it stops without checkpointing so the record can be replayed. Oversized SQS messages also fail closed. Kinesis retention limits the replay window, so monitor consumer lag and preserve shared state backups.

## Remediation safety boundary

`GoModPatchGenerator` only upgrades the requested version of a dependency already required by `go.mod`. It validates module paths and canonical Go semantic versions, rejects downgrades and `replace` directives, and does not modify the live workspace. It does not generate arbitrary source code or deploy/apply a patch.

`DockerSandboxVerifier` copies the workspace to a temporary directory, stages the generated `go.mod`, then runs `go test -mod=mod ./...` in Docker. The container has no network, a read-only input mount and Go module cache, dropped Linux capabilities, a read-only root filesystem, resource limits, and temporary writable storage. The candidate is discarded after verification. The host needs Docker and a preloaded `golang:1.26` image. Dependencies must already be in the Go module cache; verification fails closed if they are missing.

The legacy `ExecuteRemediationLoop` remains for workflow tests. The CLI uses `ExecuteGeneratedRemediation` and the generated-patch/verifier interfaces.

## Setup and tests

From the repository root in PowerShell:

```powershell
go version
go mod tidy
go fmt ./...
go test -v ./...
```

Optional race check (run on Linux/macOS or Windows with a supported C compiler; CI runs it on Ubuntu):

```powershell
go test -race ./...
```

Windows hosts without a C compiler may report `-race requires cgo`; that does not affect the normal test suite.

Download project dependencies before running the service, then prepare the sandbox image:

```powershell
docker info
docker pull golang:1.26
```

`docker info` must reach a running Docker Engine (on Windows, start Docker Desktop and use its Linux-container engine). The sandbox uses `--pull=never`, disables network access in the container, and requires the candidate dependency version to be present in the local Go module cache.

## Sandbox prewarm and diagnostics

The isolated verifier persists its Linux Go build cache in the Docker volume `sentinel-remediation-go-build-cache`. Its default timeout is 30 minutes. Prewarm the cache by testing the current workspace without attempting a dependency change:

```powershell
go run . --sandbox-prewarm --sandbox-timeout 30m
```

If the first run times out, retry with a longer limit and build tracing enabled:

```powershell
go run . --sandbox-prewarm --sandbox-timeout 45m --sandbox-debug
```

`--sandbox-debug` prints Go build commands and failed verification reports include the last captured Docker/Go output. Sandbox preparation and Docker verification durations are reported separately in logs and Prometheus metrics. The remediation histogram includes buckets through 600 seconds. Then rerun the `--simulate` command. The first cold test may be slow; later attempts reuse the cache. To intentionally clear it, run `docker volume rm sentinel-remediation-go-build-cache`.

If PowerShell says `go` is not recognized, reopen the terminal after installing Go or add it to the current session's `PATH`:

```powershell
$env:Path = 'C:\Program Files\Go\bin;' + $env:Path
```

## Local operation

Start metrics without consuming events:

```powershell
go run . --metrics-addr :9090
```

The requested dependency must already be in `go.mod`, and its target version must be newer and published. Check available versions first:

```powershell
go list -m -versions golang.org/x/mod
```

At the time this README was updated, the Go proxy lists `golang.org/x/mod` only through `v0.42.0`, which is already the version in this repository. Therefore it cannot currently be used for a successful upgrade simulation. Choose another existing `go.mod` dependency only if its version list includes a version higher than the required version, then substitute that module and version below. Download the target before sandbox verification, which runs offline:

```powershell
$dependency = '<existing-module-path>'
$fixedVersion = '<higher-published-version>'
go mod download "$dependency@$fixedVersion"
go run . --metrics-addr :9090 --simulate --dependency $dependency --fixed-version $fixedVersion
```

Inspect metrics at `http://localhost:9090/metrics`, human audit output at `twitch_security_audit.log`, and structured records at `twitch_security_audit.log.jsonl`. The simulation stays available for metrics until `Ctrl+C`. `--truncate-ledger` clears both audit files on startup. `--simulate-poisoned`, `--simulate-force-failure`, and `--simulate-rollbacks` exercise rejected metadata cases; they do not inject executable code.

## Kinesis operation

Use the AWS SDK default credential chain (AWS profile, environment credentials, or workload identity). The consumer role needs `kinesis:ListShards`, `kinesis:GetShardIterator`, and `kinesis:GetRecords` on the stream. Publishing also requires `kinesis:PutRecord`.

Consume until interrupted:

```powershell
go run . --metrics-addr :9090 `
  --kinesis-stream sentinel-security-telemetry `
  --kinesis-consume --aws-region us-west-2 `
  --kinesis-start-position TRIM_HORIZON `
  --kinesis-checkpoint .\kinesis_checkpoints.jsonl `
  --idempotency-path .\telemetry_idempotency.jsonl
```

For shards without a checkpoint the position defaults to `TRIM_HORIZON`; use `--kinesis-start-position LATEST` to start at the current tip. Existing checkpoints resume after their recorded sequence number. To publish a simulation instead of processing it locally:

```powershell
go run . --metrics-addr :9090 `
  --kinesis-stream sentinel-security-telemetry `
  --simulate --dependency $dependency --fixed-version $fixedVersion `
  --aws-region us-west-2
```

For local development, run one consumer process and keep the checkpoint and idempotency files on persistent storage. For coordinated consumers, deploy the CDK stack, then use the shared table and queue outputs:

```powershell
go run . --metrics-addr :9090 `
  --kinesis-stream sentinel-security-telemetry --kinesis-consume `
  --production-mode --dynamodb-table <ConsumerStateTableName> `
  --dlq-url <DLQUrl> --aws-region us-west-2
```

The production-mode guard requires both shared state and a DLQ. Every replica must use the same stream, table, queue, and region. DynamoDB leases fence checkpoint writes by owner. Use separate publisher and consumer roles in a hardened deployment; the CDK task role is a least-privilege consumer-role template, not attached to a running ECS task yet.

### Staging smoke test

Run this only against dedicated staging resources and non-production credentials. The CDK stack provisions an encrypted Kinesis stream, encrypted SQS DLQ, encrypted DynamoDB state table with point-in-time recovery and TTL, and a least-privilege ECS task role. It does not create an ECS service/task definition or deploy the Go process. Set `SENTINEL_STAGING_STREAM`, the table/queue outputs, and `AWS_REGION`; scope the publisher role to `PutRecord` and the consumer role to stream reads, state-table access, and DLQ sends. Pre-download the fixed dependency version on the consumer host because sandbox verification runs offline.

In PowerShell window 1, start a consumer with fresh local state paths:

```powershell
$runId = Get-Date -Format 'yyyyMMddHHmmss'
go run . --metrics-addr :9091 `
  --kinesis-stream $env:SENTINEL_STAGING_STREAM `
  --aws-region $env:AWS_REGION `
  --kinesis-consume --production-mode --kinesis-start-position LATEST `
  --dynamodb-table $env:SENTINEL_STATE_TABLE --dlq-url $env:SENTINEL_DLQ_URL
```

In PowerShell window 2, publish one simulation using a module/version already validated locally:

```powershell
go run . --metrics-addr "" `
  --kinesis-stream $env:SENTINEL_STAGING_STREAM `
  --aws-region $env:AWS_REGION `
  --simulate --dependency $dependency --fixed-version $fixedVersion
```

Once the consumer's metrics and ledger show the first event completed, publish the same simulation a second time to verify replay handling. The consumer should log `Kinesis duplicate event skipped`, increment `sentinel_duplicate_events_total`, and checkpoint the redelivery without running remediation again. Scrape `http://localhost:9091/metrics` and inspect the consumer's ledger and checkpoint JSONL. Stop the consumer with `Ctrl+C` after verification. Keep the checkpoint and idempotency files together for replay testing; use fresh paths for an isolated test run.

The opt-in AWS integration check uses `SENTINEL_TEST_KINESIS_STREAM`, `SENTINEL_TEST_DYNAMODB_TABLE`, and `SENTINEL_TEST_DLQ_URL`. It only runs when `SENTINEL_ENABLE_AWS_INTEGRATION_TESTS=1`; use dedicated staging resources because it temporarily writes and cleans up DynamoDB test items and enqueues an SQS marker (drain the test queue afterward):

```powershell
$env:SENTINEL_ENABLE_AWS_INTEGRATION_TESTS = '1'
$env:SENTINEL_TEST_KINESIS_STREAM = $env:SENTINEL_STAGING_STREAM
$env:SENTINEL_TEST_DYNAMODB_TABLE = $env:SENTINEL_STATE_TABLE
$env:SENTINEL_TEST_DLQ_URL = $env:SENTINEL_DLQ_URL
go test -v ./storage -run TestAWSIntegrationConfiguredStagingResources
```

The staging smoke test is not production-readiness sign-off. Before production, deploy a supervised ECS service/task definition, connect the CDK alarms to an SNS/on-call action, configure CloudWatch logs and retention, centralize the audit ledger, exercise failure/replay and resharding in staging, validate least-privilege OIDC deployment roles, and document human approval/rollback operations.

## CLI options

- `--metrics-addr`: Prometheus listener; set empty to disable.
- `--workspace`: Go project copied for patch generation and sandbox tests.
- `--sandbox-prewarm`, `--sandbox-timeout`, `--sandbox-debug`: run isolated tests ahead of a remediation, set the test deadline, and enable compiler tracing.
- `--dependency`, `--fixed-version`: dependency upgrade metadata for simulations (stream events carry these fields).
- `--kinesis-stream`, `--kinesis-consume`, `--aws-region`: stream configuration and consume mode.
- `--production-mode`: require Kinesis consume mode, DynamoDB shared state, and an SQS DLQ.
- `--dynamodb-table`, `--dlq-url`: shared consumer-state table and failure queue.
- `--max-record-attempts`, `--retry-backoff`, `--shard-lease-duration`: bounded processing retry and lease parameters.
- `--kinesis-checkpoint`, `--idempotency-path`: durable local delivery state for single-consumer development.
- `--kinesis-start-position`: `TRIM_HORIZON` or `LATEST` for shards without checkpoints.
- `--ledger`, `--truncate-ledger`: audit paths and retention behavior.

## Metrics and audit

`GET /metrics` exposes ingested events, successful patches, rollbacks, duplicates, DLQ handoffs, phase transitions, total processing latency, and per-stage sandbox duration histograms (`workspace_prepare` and `docker_verify`). `GET /healthz` is a liveness endpoint. Histograms have finite buckets through 600 seconds plus `+Inf`. Each remediation attempt is written to the human-readable ledger and JSONL ledger. Metrics are process-local counters; use Prometheus scraping and external time-series storage for persistence. Restrict the metrics listener to a trusted network; it is not authenticated or encrypted. The local simulation uses the stable event ID `TX-LOCAL-0001`; a repeat with the same idempotency file is reported as skipped, not processed. Use a fresh `--idempotency-path` when you intentionally want to replay that simulation.

## CI and deployment status

GitHub Actions runs formatting, dependency tidiness, `go vet`, race-enabled tests, and `govulncheck` with Go 1.26.x. AWS integration tests are opt-in and must target dedicated staging resources. The infrastructure workflow is manual, requires an explicit confirmation input and a GitHub OIDC deployment role, and deploys infrastructure only. It does not deploy the application. The CDK stack creates encrypted stream/queue/table resources, point-in-time recovery, a retained state table, and a narrowly scoped ECS task role. Configure the GitHub `staging` environment, `AWS_DEPLOY_ROLE_ARN` secret, `AWS_REGION` variable, OIDC trust conditions, and CDK bootstrap before invoking it.

Remaining production work is operational rather than hidden in the local CLI: define and deploy the ECS task/service and autoscaling policy; wire CloudWatch logs, alarms, and Kinesis lag monitoring; move the append-only audit ledger to durable centralized storage with retention controls; test lease expiry, resharding, DLQ redrive, and disaster recovery in a real staging account; and establish human approval and rollback procedures. The remediation generator intentionally remains narrow and never applies patches to the live workspace.

## Verification & Limitations

| Area | Verified so far | Limitations / remaining work |
| --- | --- | --- |
| Go validation | Formatting, unit tests, `go vet`, and dependency-tidiness checks have passed in the development workflow; CI also runs race tests and `govulncheck`. | The local Windows race test requires CGO; rely on the configured Ubuntu CI job for that check. |
| End-to-end remediation | Local simulation has completed through telemetry handling, dependency patch generation, Docker sandbox verification, audit logging, and metrics. The E2E test covers the pipeline using a mock verifier. | The E2E test is not a live AWS test; the patch generator currently handles Go module dependency upgrades, not arbitrary source-code fixes. |
| Stream and replay | Kinesis publishing/consumption, idempotency, checkpoint behavior, leases, retry handling, and DLQ paths have automated tests. | Live AWS integration tests are opt-in and require dedicated staging resources and credentials; replay, resharding, and failure recovery still need staging drills. |
| Sandbox | Docker prewarm and a local remediation simulation have been exercised; sandbox safety and workspace-copy behavior have tests. | Docker must be available to the verifier. The CDK stack does not yet deploy an ECS service/task to run the application. |
| Audit and metrics | Human-readable and JSONL audit records and Prometheus metrics are implemented. | Audit files are local and metrics are process-local; production requires centralized durable audit storage and external metrics collection/retention. |
| AWS deployment and account boundaries | CDK resources and a manually confirmed GitHub OIDC infrastructure-deployment workflow are defined. | Infrastructure has not been deployed/validated in staging. Cross-account IAM/STS producer configuration, alert routing, and operational approval/rollback procedures remain deployment work. |
