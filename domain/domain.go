package domain

import "context"

// Vulnerability represents an ingested security flaw or compliance risk.
type Vulnerability struct {
	ID           string   `json:"id"`
	Service      string   `json:"service"`
	TargetFile   string   `json:"target_file"`
	Dependency   string   `json:"dependency,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	RiskScore    float64  `json:"risk_score"`
	Description  string   `json:"description"`
	Invariants   []string `json:"invariants"` // e.g., "PRESERVE_MEDIA_INGESTION_FLOW"
}

// AgentState tracks the cognitive lifecycle and rollback markers of the remediation engine.
type AgentState struct {
	TaskID         string   `json:"task_id"`
	CurrentPhase   string   `json:"current_phase"` // "ANALYSIS", "PATCHING", "VERIFYING", "COMPLETED", "ROLLED_BACK"
	Uncertainty    float64  `json:"uncertainty"`
	ExecutionTrace []string `json:"execution_trace"`
}

// SecurityWorkflowPort dictates entrypoint behavior for inbound automated telemetry.
type SecurityWorkflowPort interface {
	ProcessAlert(ctx context.Context, vuln Vulnerability) (*AgentState, error)
}
