package workflow

import (
	"context"
	"fmt"
	"time"

	"twitch-security/controller"
	"twitch-security/domain"
)

type RemediationEngine struct {
	verifier *controller.VerificationController
}

func NewRemediationEngine(verifier *controller.VerificationController) *RemediationEngine {
	return &RemediationEngine{verifier: verifier}
}

func (re *RemediationEngine) ExecuteRemediationLoop(
	ctx context.Context,
	vuln domain.Vulnerability,
	patch string,
	chaos bool,
) (*domain.AgentState, error) {
	if re.verifier == nil {
		return nil, fmt.Errorf("missing verifier")
	}

	if err := re.verifier.VerifyRemediation(ctx, patch); err != nil {
		return nil, err
	}

	status := "remediated"
	if chaos {
		status = "remediated_with_chaos"
	}

	state := &domain.AgentState{
		AlertID:     vuln.AlertID,
		Status:      status,
		Patch:       patch,
		Verified:    true,
		CreatedAt:   time.Now(),
		AWSAccount:  vuln.AWSAccountID,
		ServiceName: vuln.Microservice,
	}

	return state, nil
}