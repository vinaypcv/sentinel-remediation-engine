package controller

import (
	"context"
	"fmt"
	"strings"
)

type VerificationController struct{}

func NewVerificationController() *VerificationController {
	return &VerificationController{}
}

// VerifyEpistemicGuardrails blocks adversarial code transformations or invariant violations.
func (vc *VerificationController) VerifyEpistemicGuardrails(ctx context.Context, patch string, rules []string) error {
	_ = ctx

	maliciousKeywords := []string{"sudo ", "chmod 777", "rm -rf", "curl -s http"}
	lowerPatch := strings.ToLower(patch)
	for _, kw := range maliciousKeywords {
		if strings.Contains(lowerPatch, kw) {
			return fmt.Errorf("guardrail_breach: restricted execution path pattern detected (%s)", kw)
		}
	}

	for _, rule := range rules {
		if rule == "PRESERVE_MEDIA_INGESTION_FLOW" && strings.Contains(patch, "ingest_controller.go") {
			return fmt.Errorf("guardrail_breach: violation of system invariant (%s) - restricted file modification blocked", rule)
		}
	}

	return nil
}
