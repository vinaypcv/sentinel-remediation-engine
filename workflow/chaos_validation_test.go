package workflow

import (
	"context"
	"testing"

	"twitch-security/controller"
	"twitch-security/domain"
)

func TestExecuteRemediationLoop_ChaosFlag(t *testing.T) {
	ctx := context.Background()
	v := controller.NewVerificationController()
	re := NewRemediationEngine(v)

	state, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: "A-CHAOS"}, "package main\\n// ok", true)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if state.Status != "remediated_with_chaos" {
		t.Fatalf("unexpected status: %q", state.Status)
	}
}