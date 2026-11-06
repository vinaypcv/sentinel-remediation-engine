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

	state, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: "A-1"}, "package main\\n// ok", false)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if state == nil || state.AlertID != "A-1" {
		t.Fatalf("unexpected state: %#v", state)
	}
	if !state.Verified {
		t.Fatalf("expected verified=true")
	}
}

func TestExecuteRemediationLoop_RejectsEmptyPatch(t *testing.T) {
	ctx := context.Background()
	v := controller.NewVerificationController()
	re := NewRemediationEngine(v)

	_, err := re.ExecuteRemediationLoop(ctx, domain.Vulnerability{AlertID: "A-1"}, " " , false)
	if err == nil {
		t.Fatalf("expected error for empty patch")
	}
}