package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type VerificationController struct {
	bundle PolicyBundle
}

func NewVerificationController() *VerificationController {
	bundle := DefaultPolicyBundle()
	if path := os.Getenv("SENTINEL_POLICY_BUNDLE"); path != "" {
		if b, err := LoadPolicyBundle(path); err == nil {
			bundle = b
		}
	}
	return &VerificationController{bundle: bundle}
}

type PolicyBundle struct {
	ForbiddenSubstrings []string `json:"forbidden_substrings"`
	ForbiddenImports    []string `json:"forbidden_imports"`
	Invariants          []string `json:"invariants"`
}

func DefaultPolicyBundle() PolicyBundle {
	return PolicyBundle{
		ForbiddenSubstrings: []string{
			"sudo ",
			"chmod 777",
			"rm -rf",
			"curl -s http",
			"curl -s https",
			"| bash",
		},
		ForbiddenImports: []string{
			"os/exec",
			"syscall",
			"unsafe",
		},
		Invariants: []string{"PRESERVE_MEDIA_INGESTION_FLOW"},
	}
}

func LoadPolicyBundle(path string) (PolicyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PolicyBundle{}, err
	}
	var b PolicyBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return PolicyBundle{}, err
	}
	return b, nil
}

// VerifyEpistemicGuardrails blocks adversarial code transformations or invariant violations.
//
// Production hardening:
// - Applies a policy bundle (built-in defaults, optionally overridden by SENTINEL_POLICY_BUNDLE JSON)
// - Performs substring-based checks
// - Performs Go AST import checks when the patch parses as Go code
func (vc *VerificationController) VerifyEpistemicGuardrails(ctx context.Context, patch string, rules []string) error {
	_ = ctx

	bundle := vc.bundle

	lowerPatch := strings.ToLower(patch)
	for _, kw := range bundle.ForbiddenSubstrings {
		if kw == "" {
			continue
		}
		if strings.Contains(lowerPatch, strings.ToLower(kw)) {
			return fmt.Errorf("guardrail_breach: forbidden substring detected (%s)", kw)
		}
	}

	for _, rule := range rules {
		if rule == "PRESERVE_MEDIA_INGESTION_FLOW" && strings.Contains(patch, "ingest_controller.go") {
			return fmt.Errorf("guardrail_breach: violation of system invariant (%s) - restricted file modification blocked", rule)
		}
	}

	// AST-based check (best-effort): if this looks like Go code, parse and block forbidden imports.
	if strings.Contains(patch, "package ") {
		if err := vc.verifyGoAST(patch, bundle); err != nil {
			return err
		}
	}

	return nil
}

func (vc *VerificationController) verifyGoAST(src string, bundle PolicyBundle) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "patch.go", src, parser.AllErrors)
	if err != nil {
		// If it doesn't parse, we don't fail purely on parsing; treat as non-Go payload.
		return nil
	}

	forbidden := make(map[string]struct{}, len(bundle.ForbiddenImports))
	for _, imp := range bundle.ForbiddenImports {
		forbidden[imp] = struct{}{}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		imp, ok := n.(*ast.ImportSpec)
		if !ok || imp.Path == nil {
			return true
		}
		p := strings.Trim(imp.Path.Value, "\"")
		if _, exists := forbidden[p]; exists {
			err = fmt.Errorf("guardrail_breach: forbidden import detected (%s)", p)
			return false
		}
		return true
	})
	return err
}
