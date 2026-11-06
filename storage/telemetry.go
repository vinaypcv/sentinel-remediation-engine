package storage

import (
	"context"
	"time"

	"twitch-security/domain"
)

type SecurityTelemetryEvent struct {
	EventID      string
	AWSAccountID string
	Microservice string
	Payload      string
	Timestamp    time.Time
}

type SecurityWorkflowPort interface {
	ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error)
}

type TelemetryBuffer struct {
	port SecurityWorkflowPort
}

func NewTelemetryBuffer(port SecurityWorkflowPort) *TelemetryBuffer {
	return &TelemetryBuffer{port: port}
}

func (tb *TelemetryBuffer) IngestStream(ctx context.Context, event SecurityTelemetryEvent) {
	if tb == nil || tb.port == nil {
		return
	}

	vuln := domain.Vulnerability{
		AlertID:      event.EventID,
		AWSAccountID: event.AWSAccountID,
		Microservice: event.Microservice,
		Payload:      event.Payload,
		Timestamp:    event.Timestamp,
	}

	go func() {
		_, _ = tb.port.ProcessAlert(ctx, vuln)
	}()
}