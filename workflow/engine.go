package workflow

import (
	"context"
	"errors"
	"fmt"

	"twitch-security/controller"
	"twitch-security/domain"
)

type RemediationEngine struct {
	Verifier *controller.VerificationController
}

func NewRemediationEngine(v *controller.VerificationController) *RemediationEngine {
	return &RemediationEngine{Verifier: v}
}

func (re *RemediationEngine) ExecuteRemediationLoop(
	ctx context.Context,
	vuln domain.Vulnerability,
	mockPatch string,
	forceFailure bool,
) (*domain.AgentState, error) {
	state := &domain.AgentState{
		TaskID:         vuln.ID,
		CurrentPhase:   "ANALYSIS",
		ExecutionTrace: []string{"Initialized ingestion pipeline analysis."},
	}

	state.CurrentPhase = "PATCHING"
	err := re.Verifier.VerifyEpistemicGuardrails(ctx, mockPatch, vuln.Invariants)
	if err != nil {
		state.CurrentPhase = "ROLLED_BACK"
		state.ExecutionTrace = append(state.ExecutionTrace, fmt.Sprintf("Aborted: %v", err))
		return state, err
	}
	state.ExecutionTrace = append(state.ExecutionTrace, "Passed epistemic guardrail evaluations.")

	state.CurrentPhase = "VERIFYING"
	if forceFailure {
		state.CurrentPhase = "ROLLED_BACK"
		state.ExecutionTrace = append(state.ExecutionTrace, "Rollback Triggered: Sandbox test suite failed.")
		return state, errors.New("remediation_failed: unit tests failed in compilation sandbox")
	}

	state.CurrentPhase = "COMPLETED"
	state.ExecutionTrace = append(state.ExecutionTrace, "Sandbox tests verified successfully. PR generated.")
	return state, nil
}
