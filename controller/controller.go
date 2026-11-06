package controller

import (
	"context"
	"errors"
	"strings"
)

type VerificationController struct{}

func NewVerificationController() *VerificationController {
	return &VerificationController{}
}

func (vc *VerificationController) VerifyRemediation(ctx context.Context, patch string) error {
	_ = ctx
	if strings.TrimSpace(patch) == "" {
		return errors.New("empty remediation patch")
	}
	return nil
}