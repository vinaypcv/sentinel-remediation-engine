$ErrorActionPreference = "Stop"

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

$bt = [char]96

# Ensure dirs exist
New-Item -ItemType Directory -Force domain, controller, workflow, storage | Out-Null

# go.mod
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\go.mod") -Content @"
module twitch-security

go 1.22
"@

# domain/domain.go
$domainGo = @"
package domain

import \"time\"

type Vulnerability struct {
\tAlertID      string <BT>json:\"alert_id\"<BT>
\tAWSAccountID string <BT>json:\"aws_account_id\"<BT>
\tMicroservice string <BT>json:\"microservice\"<BT>
\tPayload      string <BT>json:\"payload\"<BT>
\tTimestamp    time.Time <BT>json:\"timestamp\"<BT>
}

type AgentState struct {
\tAlertID     string    <BT>json:\"alert_id\"<BT>
\tStatus      string    <BT>json:\"status\"<BT>
\tPatch       string    <BT>json:\"patch\"<BT>
\tVerified    bool      <BT>json:\"verified\"<BT>
\tCreatedAt   time.Time <BT>json:\"created_at\"<BT>
\tAWSAccount  string    <BT>json:\"aws_account_id\"<BT>
\tServiceName string    <BT>json:\"microservice\"<BT>
}
"@ -replace '<BT>', $bt

Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\domain\domain.go") -Content $domainGo

# domain/telemetry_time_compat.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\domain\telemetry_time_compat.go") -Content @"
package domain

import \"time\"

// TimeCompat keeps the storage package types simple while still carrying a time value.
// It intentionally mirrors time.Time to avoid leaking extra imports.
type TimeCompat struct {
\tTime time.Time
}
"@

# controller/controller.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\controller\controller.go") -Content @"
package controller

import (
\t\"context\"
\t\"errors\"
\t\"strings\"
)

type VerificationController struct{}

func NewVerificationController() *VerificationController {
\treturn &VerificationController{}
}

func (vc *VerificationController) VerifyRemediation(ctx context.Context, patch string) error {
\t_ = ctx
\tif strings.TrimSpace(patch) == \"\" {
\t\treturn errors.New(\"empty remediation patch\")
\t}
\treturn nil
}
"@

# workflow/engine.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\workflow\engine.go") -Content @"
package workflow

import (
\t\"context\"
\t\"fmt\"
\t\"time\"

\t\"twitch-security/controller\"
\t\"twitch-security/domain\"
)

type RemediationEngine struct {
\tverifier *controller.VerificationController
}

func NewRemediationEngine(verifier *controller.VerificationController) *RemediationEngine {
\treturn &RemediationEngine{verifier: verifier}
}

func (re *RemediationEngine) ExecuteRemediationLoop(
\tctx context.Context,
\tvuln domain.Vulnerability,
\tpatch string,
\tchaos bool,
) (*domain.AgentState, error) {
\tif re.verifier == nil {
\t\treturn nil, fmt.Errorf(\"missing verifier\")
\t}

\tif err := re.verifier.VerifyRemediation(ctx, patch); err != nil {
\t\treturn nil, err
\t}

\tstatus := \"remediated\"
\tif chaos {
\t\tstatus = \"remediated_with_chaos\"
\t}

\tstate := &domain.AgentState{
\t\tAlertID:     vuln.AlertID,
\t\tStatus:      status,
\t\tPatch:       patch,
\t\tVerified:    true,
\t\tCreatedAt:   time.Now(),
\t\tAWSAccount:  vuln.AWSAccountID,
\t\tServiceName: vuln.Microservice,
\t}

\treturn state, nil
}
"@

# workflow/engine_test.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\workflow\engine_test.go") -Content @"
package workflow

import (
\t\"context\"
\t\"testing\"

\t\"twitch-security/controller\"
\t\"twitch-security/domain\"
)

func TestExecuteRemediationLoop_Success(t *testing.T) {
\tctx := context.Background()
\tv := controller.NewVerificationController()
\tre := NewRemediationEngine(v)

\tstate, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: \"A-1\"}, \"package main\\n// ok\", false)
\tif err != nil {
\t\tt.Fatalf(\"expected success, got error: %v\", err)
\t}
\tif state == nil || state.AlertID != \"A-1\" {
\t\tt.Fatalf(\"unexpected state: %#v\", state)
\t}
\tif !state.Verified {
\t\tt.Fatalf(\"expected verified=true\")
\t}
}

func TestExecuteRemediationLoop_RejectsEmptyPatch(t *testing.T) {
\tctx := context.Background()
\tv := controller.NewVerificationController()
\tre := NewRemediationEngine(v)

\t_, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: \"A-1\"}, \" \" , false)
\tif err == nil {
\t\tt.Fatalf(\"expected error for empty patch\")
\t}
}
"@

# workflow/chaos_validation_test.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\workflow\chaos_validation_test.go") -Content @"
package workflow

import (
\t\"context\"
\t\"testing\"

\t\"twitch-security/controller\"
\t\"twitch-security/domain\"
)

func TestExecuteRemediationLoop_ChaosFlag(t *testing.T) {
\tctx := context.Background()
\tv := controller.NewVerificationController()
\tre := NewRemediationEngine(v)

\tstate, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: \"A-CHAOS\"}, \"package main\\n// ok\", true)
\tif err != nil {
\t\tt.Fatalf(\"expected success, got error: %v\", err)
\t}
\tif state.Status != \"remediated_with_chaos\" {
\t\tt.Fatalf(\"unexpected status: %q\", state.Status)
\t}
}
"@

# storage/ledger.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\storage\ledger.go") -Content @"
package storage

import (
\t\"context\"
\t\"encoding/json\"
\t\"os\"
\t\"sync\"

\t\"twitch-security/domain\"
)

type ImmutableLedger struct {
\tpath string
\tmu   sync.Mutex
}

func NewImmutableLedger(path string) (*ImmutableLedger, error) {
\tf, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
\tif err != nil {
\t\treturn nil, err
\t}
\t_ = f.Close()
\treturn &ImmutableLedger{path: path}, nil
}

func (l *ImmutableLedger) CommitStateToLedger(ctx context.Context, state *domain.AgentState) error {
\t_ = ctx
\tif state == nil {
\t\treturn nil
\t}

\tpayload, err := json.Marshal(state)
\tif err != nil {
\t\treturn err
\t}

\tl.mu.Lock()
\tdefer l.mu.Unlock()

\tw, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
\tif err != nil {
\t\treturn err
\t}
\tdefer w.Close()

\tif _, err := w.Write(append(payload, '\\n')); err != nil {
\t\treturn err
\t}

\treturn nil
}
"@

# storage/telemetry.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\storage\telemetry.go") -Content @"
package storage

import (
\t\"context\"

\t\"twitch-security/domain\"
)

type SecurityTelemetryEvent struct {
\tEventID      string
\tAWSAccountID string
\tMicroservice string
\tPayload      string
\tTimestamp    domain.TimeCompat
}

type SecurityWorkflowPort interface {
\tProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error)
}

type TelemetryBuffer struct {
\tport SecurityWorkflowPort
}

func NewTelemetryBuffer(port SecurityWorkflowPort) *TelemetryBuffer {
\treturn &TelemetryBuffer{port: port}
}

func (tb *TelemetryBuffer) IngestStream(ctx context.Context, event SecurityTelemetryEvent) {
\tif tb == nil || tb.port == nil {
\t\treturn
\t}

\tvuln := domain.Vulnerability{
\t\tAlertID:      event.EventID,
\t\tAWSAccountID: event.AWSAccountID,
\t\tMicroservice: event.Microservice,
\t\tPayload:      event.Payload,
\t\tTimestamp:    event.Timestamp.Time,
\t}

\tgo func() {
\t\t_, _ = tb.port.ProcessAlert(ctx, vuln)
\t}()
}
"@

# storage/metrics.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\storage\metrics.go") -Content @"
package storage

// Metrics is a placeholder for future observability.
type Metrics struct{}
"@

# main_e2e_test.go
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\main_e2e_test.go") -Content @"
package main

import (
\t\"context\"
\t\"os\"
\t\"strings\"
\t\"testing\"
\t\"time\"

\t\"twitch-security/controller\"
\t\"twitch-security/domain\"
\t\"twitch-security/storage\"
\t\"twitch-security/workflow\"
)

// MockWrapper adapts our engine to implement the driving SecurityWorkflowPort interface cleanly.
type MockWrapper struct {
\tEngine *workflow.RemediationEngine
\tLedger *storage.ImmutableLedger
}

func (mw *MockWrapper) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
\tmockPatch := \"package main\\n// Auto-remediated security configuration dependency map\"
\tstate, err := mw.Engine.ExecuteRemediationLoop(ctx, vuln, mockPatch, false)
\tif err == nil {
\t\t_ = mw.Ledger.CommitStateToLedger(ctx, state)
\t}
\treturn state, err
}

func TestEndToEnd_HolisticSecurityPipeline(t *testing.T) {
\tctx := context.Background()
\tledgerFile := \"twitch_security_audit.log\"
\tdefer os.Remove(ledgerFile)

\t// 1. Initialize core system layers
\tvController := controller.NewVerificationController()
\trEngine := workflow.NewRemediationEngine(vController)
\tledger, err := storage.NewImmutableLedger(ledgerFile)
\tif err != nil {
\t\tt.Fatalf(\"Failed to spin up audit storage ledger: %v\", err)
\t}

\twrapper := &MockWrapper{Engine: rEngine, Ledger: ledger}
\tbuffer := storage.NewTelemetryBuffer(wrapper)

\t// 2. Simulate streaming cross-account telemetry from an isolated AWS bubble
\ttelemetryAlert := storage.SecurityTelemetryEvent{
\t\tEventID:      \"TX-7709\",
\t\tAWSAccountID: \"112233445566\",
\t\tMicroservice: \"video-ingest-api\",
\t\tPayload:      \"CRITICAL_DEPENDENCY_ALERT: remote execution vulnerability detected inside vendor parsing library\",
\t\tTimestamp:    domain.TimeCompat{Time: time.Now()},
\t}

\t// 3. Stream event into buffer workspace
\tbuffer.IngestStream(ctx, telemetryAlert)

\t// Allow async execution routine to commit state logs to disk
\ttime.Sleep(50 * time.Millisecond)

\t// 4. Verify system state written to the immutable ledger
\tdata, err := os.ReadFile(ledgerFile)
\tif err != nil {
\t\tt.Fatalf(\"Failed to read persistent audit logs: %v\", err)
\t}

\tif !strings.Contains(string(data), \"TX-7709\") {
\t\tt.Errorf(\"Holistic verification failed: Log record not securely committed to the write-ahead ledger.\")
\t}
}
"@

# .gitignore
Write-Utf8NoBom -Path (Join-Path $PSScriptRoot "..\.gitignore") -Content @"
# Test audit logs generated by E2E suite
*.log
twitch_security_audit.log

# Binaries for programs and tests
*.exe
*.exe;
*.dll
*.so
*.dylib
*.test
*.out

# Go build outputs & vendor
/bin/
/dist/
/vendor/

# Environment and IDE settings
.env
.vscode/
.idea/
*.swp
*.swo

# OS metadata
.DS_Store
Thumbs.db
"@

Write-Host "Bootstrap complete."
