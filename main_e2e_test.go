package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"twitch-security/controller"
	"twitch-security/domain"
	"twitch-security/storage"
	"twitch-security/workflow"
)

type MockWrapper struct {
	Engine *workflow.RemediationEngine
	Ledger *storage.ImmutableLedger
}

func (mw *MockWrapper) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	mockPatch := "package main\n// Auto-remediated security configuration dependency map"
	state, err := mw.Engine.ExecuteRemediationLoop(ctx, vuln, mockPatch, false)
	if err == nil {
		_ = mw.Ledger.CommitStateToLedger(ctx, state)
	}
	return state, err
}

func TestEndToEnd_HolisticSecurityPipeline(t *testing.T) {
	ctx := context.Background()
	ledgerFile := "twitch_security_audit.log"

	vController := controller.NewVerificationController()
	rEngine := workflow.NewRemediationEngine(vController)
	ledger, err := storage.NewImmutableLedger(ledgerFile)
	if err != nil {
		t.Fatalf("Failed to spin up audit storage ledger: %v", err)
	}
	defer func() {
		_ = ledger.Close()
		_ = os.Remove(ledgerFile)
	}()

	wrapper := &MockWrapper{Engine: rEngine, Ledger: ledger}
	buffer := storage.NewTelemetryBuffer(wrapper)

	telemetryAlert := storage.SecurityTelemetryEvent{
		EventID:      "TX-7709",
		AWSAccountID: "112233445566",
		Microservice: "video-ingest-api",
		Payload:      "CRITICAL_DEPENDENCY_ALERT: remote execution vulnerability detected inside vendor parsing library",
		Timestamp:    time.Now(),
	}

	buffer.IngestStream(ctx, telemetryAlert)

	deadline := time.Now().Add(2 * time.Second)
	var lastData string

	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(ledgerFile)
		if readErr == nil {
			lastData = string(data)
			if strings.Contains(lastData, "TX-7709") {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	if lastData == "" {
		t.Fatalf("Holistic verification failed: no ledger data written before timeout")
	}
	if !strings.Contains(lastData, "TX-7709") {
		t.Fatalf("Holistic verification failed: expected TX-7709 in ledger; got: %s", lastData)
	}
}
