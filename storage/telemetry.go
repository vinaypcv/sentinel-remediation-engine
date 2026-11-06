package storage

import (
	"context"
	"sync"
	"time"

	"twitch-security/domain"
)

type SecurityTelemetryEvent struct {
	EventID      string    `json:"event_id"`
	AWSAccountID string    `json:"aws_account_id"`
	Microservice string    `json:"microservice"`
	Payload      string    `json:"payload"`
	Timestamp    time.Time `json:"timestamp"`
}

type TelemetryBuffer struct {
	mu         sync.Mutex
	EventQueue []SecurityTelemetryEvent
	Remediator domain.SecurityWorkflowPort
}

func NewTelemetryBuffer(rp domain.SecurityWorkflowPort) *TelemetryBuffer {
	return &TelemetryBuffer{
		EventQueue: make([]SecurityTelemetryEvent, 0),
		Remediator: rp,
	}
}

func (tb *TelemetryBuffer) IngestStream(ctx context.Context, event SecurityTelemetryEvent) {
	if tb == nil {
		return
	}

	tb.mu.Lock()
	tb.EventQueue = append(tb.EventQueue, event)
	tb.mu.Unlock()

	if tb.Remediator == nil {
		return
	}

	if len(event.Payload) > 0 {
		vuln := domain.Vulnerability{
			ID:         event.EventID,
			Service:    event.Microservice,
			TargetFile: "go.mod",
			Invariants: []string{"PRESERVE_MEDIA_INGESTION_FLOW"},
		}
		go tb.Remediator.ProcessAlert(ctx, vuln)
	}
}
