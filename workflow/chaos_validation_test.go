package workflow

import (
	"context"
	"testing"

	"twitch-security/controller"
	"twitch-security/domain"
)

func TestExecuteRemediationLoop_ForceFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	v := controller.NewVerificationController()
	re := NewRemediationEngine(v)

	vuln := domain.Vulnerability{ID: "A-CHAOS"}
	state, err := re.ExecuteRemediationLoop(ctx, vuln, "package main\n// ok", true)
	if err == nil {
		t.Fatalf("expected error")
	}
	if state == nil || state.CurrentPhase != "ROLLED_BACK" {
		t.Fatalf("unexpected state: %#v", state)
	}
}
