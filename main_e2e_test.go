package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"twitch-security/controller"
	"twitch-security/domain"
	"twitch-security/storage"
	"twitch-security/workflow"
)

type MockWrapper struct {
	Engine    *workflow.RemediationEngine
	Generator workflow.PatchGenerator
	Verifier  *testPatchVerifier
	Ledger    *storage.ImmutableLedger
}

func (mw *MockWrapper) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	state, err := mw.Engine.ExecuteGeneratedRemediation(ctx, vuln, mw.Generator, mw.Verifier)
	if state != nil {
		if ledgerErr := mw.Ledger.CommitStateToLedger(ctx, state); ledgerErr != nil {
			return state, ledgerErr
		}
	}
	return state, err
}

type testPatchVerifier struct {
	patch workflow.GeneratedPatch
}

func (v *testPatchVerifier) Verify(_ context.Context, patch workflow.GeneratedPatch) error {
	v.patch = patch
	return nil
}

func TestEndToEnd_HolisticSecurityPipeline(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	goMod := "module example.test/fixture\n\ngo 1.26.0\n\nrequire example.com/library v1.2.3\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	ledgerFile := filepath.Join(root, "audit.log")

	vController := controller.NewVerificationController()
	rEngine := workflow.NewRemediationEngine(vController)
	ledger, err := storage.NewImmutableLedger(ledgerFile)
	if err != nil {
		t.Fatalf("Failed to spin up audit storage ledger: %v", err)
	}
	defer func() {
		_ = ledger.Close()
	}()

	verifier := &testPatchVerifier{}
	wrapper := &MockWrapper{
		Engine:    rEngine,
		Generator: workflow.GoModPatchGenerator{WorkspaceRoot: root},
		Verifier:  verifier,
		Ledger:    ledger,
	}
	buffer := storage.NewTelemetryBuffer(wrapper)

	telemetryAlert := storage.SecurityTelemetryEvent{
		EventID:      "TX-7709",
		AWSAccountID: "112233445566",
		Microservice: "video-ingest-api",
		Payload:      "CRITICAL_DEPENDENCY_ALERT: remote execution vulnerability detected inside vendor parsing library",
		Dependency:   "example.com/library",
		FixedVersion: "v1.3.0",
		Timestamp:    time.Now(),
	}

	if err := buffer.ProcessEvent(ctx, telemetryAlert); err != nil {
		t.Fatalf("process telemetry event: %v", err)
	}

	data, err := os.ReadFile(ledgerFile)
	if err != nil {
		t.Fatalf("read audit ledger: %v", err)
	}
	if !strings.Contains(string(data), "TX-7709") {
		t.Fatalf("Holistic verification failed: expected TX-7709 in ledger; got: %s", data)
	}
	if verifier.patch.RelativePath != "go.mod" || !strings.Contains(string(verifier.patch.Content), "example.com/library v1.3.0") {
		t.Fatalf("expected generated dependency patch to be sandbox-verified, got: %+v", verifier.patch)
	}
}
