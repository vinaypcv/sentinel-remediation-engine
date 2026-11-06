package workflow

import (
	"context"
	"testing"

	"twitch-security/controller"
	"twitch-security/domain"
)

func TestExecuteRemediationLoop_Success(t *testing.T) {
	ctx := context.Background()
	v := controller.NewVerificationController()
	re := NewRemediationEngine(v)

	vuln := domain.Vulnerability{ID: "A-1"}
	state, err := re.ExecuteRemediationLoop(ctx, vuln, "package main\n// ok", false)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if state == nil || state.TaskID != "A-1" {
		t.Fatalf("unexpected state: %#v", state)
	}
	if state.CurrentPhase != "COMPLETED" {
		t.Fatalf("unexpected phase: %q", state.CurrentPhase)
	}
}

func TestExecuteRemediationLoop_GuardrailBreach(t *testing.T) {
	ctx := context.Background()
	v := controller.NewVerificationController()
	re := NewRemediationEngine(v)

	vuln := domain.Vulnerability{ID: "A-1", Invariants: []string{"PRESERVE_MEDIA_INGESTION_FLOW"}}
	_, err := re.ExecuteRemediationLoop(ctx, vuln, "rm -rf /", false)
	if err == nil {
		t.Fatalf("expected error for guardrail breach")
	}
}
