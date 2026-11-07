package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"twitch-security/controller"
	"twitch-security/domain"
	"twitch-security/storage"
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
	start := time.Now()

	state := &domain.AgentState{
		TaskID:         vuln.ID,
		CurrentPhase:   "ANALYSIS",
		ExecutionTrace: []string{"Initialized ingestion pipeline analysis."},
	}
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)

	state.CurrentPhase = "PATCHING"
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)

	err := re.Verifier.VerifyEpistemicGuardrails(ctx, mockPatch, vuln.Invariants)
	if err != nil {
		state.CurrentPhase = "ROLLED_BACK"
		storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
		state.ExecutionTrace = append(state.ExecutionTrace, fmt.Sprintf("Aborted: %v", err))
		storage.GlobalMetrics.RecordRollback()
		storage.GlobalMetrics.RecordLatency(time.Since(start))
		return state, err
	}
	state.ExecutionTrace = append(state.ExecutionTrace, "Passed epistemic guardrail evaluations.")

	state.CurrentPhase = "VERIFYING"
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)

	if forceFailure {
		state.CurrentPhase = "ROLLED_BACK"
		storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
		state.ExecutionTrace = append(state.ExecutionTrace, "Rollback Triggered: Sandbox test suite failed.")
		storage.GlobalMetrics.RecordRollback()
		storage.GlobalMetrics.RecordLatency(time.Since(start))
		return state, errors.New("remediation_failed: unit tests failed in compilation sandbox")
	}

	state.CurrentPhase = "COMPLETED"
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
	state.ExecutionTrace = append(state.ExecutionTrace, "Sandbox tests verified successfully. PR generated.")

	storage.GlobalMetrics.RecordPatch()
	storage.GlobalMetrics.RecordLatency(time.Since(start))

	return state, nil
}

func (re *RemediationEngine) ExecuteGeneratedRemediation(
	ctx context.Context,
	vuln domain.Vulnerability,
	generator PatchGenerator,
	verifier PatchVerifier,
) (*domain.AgentState, error) {
	start := time.Now()
	state := &domain.AgentState{
		TaskID:         vuln.ID,
		CurrentPhase:   "ANALYSIS",
		ExecutionTrace: []string{"Initialized dependency remediation analysis."},
	}
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
	rollback := func(err error) (*domain.AgentState, error) {
		state.CurrentPhase = "ROLLED_BACK"
		state.ExecutionTrace = append(state.ExecutionTrace, fmt.Sprintf("Remediation rejected: %v", err))
		storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
		storage.GlobalMetrics.RecordRollback()
		storage.GlobalMetrics.RecordLatency(time.Since(start))
		return state, err
	}
	if generator == nil || verifier == nil || re.Verifier == nil {
		return rollback(errors.New("patch generator, patch verifier, and policy verifier are required"))
	}
	if err := ctx.Err(); err != nil {
		return rollback(err)
	}

	state.CurrentPhase = "PATCHING"
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
	patch, err := generator.Generate(ctx, vuln)
	if err != nil {
		return rollback(fmt.Errorf("generate remediation patch: %w", err))
	}
	if patch.RelativePath == "" || len(patch.Content) == 0 {
		return rollback(errors.New("patch generator returned an empty patch"))
	}
	state.ExecutionTrace = append(state.ExecutionTrace, patch.Summary)
	if err := re.Verifier.VerifyEpistemicGuardrails(ctx, string(patch.Content), vuln.Invariants); err != nil {
		return rollback(err)
	}
	state.ExecutionTrace = append(state.ExecutionTrace, "Generated patch passed policy guardrails.")

	state.CurrentPhase = "VERIFYING"
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
	if err := verifier.Verify(ctx, patch); err != nil {
		return rollback(fmt.Errorf("sandbox verification failed: %w", err))
	}
	state.CurrentPhase = "COMPLETED"
	state.ExecutionTrace = append(state.ExecutionTrace, "Generated patch passed isolated verification; no live files were modified.")
	storage.GlobalMetrics.RecordPhase(state.CurrentPhase)
	storage.GlobalMetrics.RecordPatch()
	storage.GlobalMetrics.RecordLatency(time.Since(start))
	return state, nil
}
