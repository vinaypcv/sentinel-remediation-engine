package storage

import (
	"context"
	"fmt"
	"time"

	"twitch-security/domain"
)

type SecurityTelemetryEvent struct {
	EventID      string    `json:"event_id"`
	AWSAccountID string    `json:"aws_account_id"`
	Microservice string    `json:"microservice"`
	Payload      string    `json:"payload"`
	Dependency   string    `json:"dependency,omitempty"`
	FixedVersion string    `json:"fixed_version,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type TelemetryBuffer struct {
	Remediator  domain.SecurityWorkflowPort
	Idempotency EventIdempotencyStore
}

func NewTelemetryBuffer(rp domain.SecurityWorkflowPort) *TelemetryBuffer {
	return &TelemetryBuffer{Remediator: rp}
}

func NewTelemetryBufferWithIdempotency(rp domain.SecurityWorkflowPort, idempotencyPath string) (*TelemetryBuffer, error) {
	idx, err := NewIdempotencyIndex(idempotencyPath)
	if err != nil {
		return nil, err
	}

	return &TelemetryBuffer{
		Remediator:  rp,
		Idempotency: idx,
	}, nil
}

func (tb *TelemetryBuffer) IngestStream(ctx context.Context, event SecurityTelemetryEvent) {
	go func() {
		_ = tb.ProcessEvent(ctx, event)
	}()
}

func (tb *TelemetryBuffer) ProcessEvent(ctx context.Context, event SecurityTelemetryEvent) error {
	_, err := tb.ProcessEventWithResult(ctx, event)
	return err
}

func (tb *TelemetryBuffer) ProcessEventWithResult(ctx context.Context, event SecurityTelemetryEvent) (bool, error) {
	return tb.processEventWithResult(ctx, event, true)
}

func (tb *TelemetryBuffer) processEventWithResult(ctx context.Context, event SecurityTelemetryEvent, countIngest bool) (bool, error) {
	if tb == nil {
		return false, nil
	}
	if event.EventID == "" {
		return false, fmt.Errorf("event ID is required")
	}
	if len(event.EventID) > 256 {
		return false, fmt.Errorf("event ID exceeds 256 bytes")
	}
	if countIngest {
		GlobalMetrics.IncrementIngest()
	}

	claimed := false
	if tb.Idempotency != nil {
		var err error
		claimed, err = tb.Idempotency.Claim(ctx, event.EventID)
		if err != nil {
			return false, err
		}
		if !claimed {
			GlobalMetrics.RecordDuplicate()
			return false, nil
		}
		defer tb.Idempotency.Release(event.EventID)
	}

	if tb.Remediator == nil {
		if claimed {
			if err := tb.Idempotency.CompleteContext(ctx, event.EventID, event.Timestamp); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	if event.Payload == "" {
		return false, fmt.Errorf("event payload is required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	vuln := domain.Vulnerability{
		ID:           event.EventID,
		Service:      event.Microservice,
		TargetFile:   "go.mod",
		Dependency:   event.Dependency,
		FixedVersion: event.FixedVersion,
		Invariants:   []string{"PRESERVE_MEDIA_INGESTION_FLOW"},
	}
	processCtx := ctx
	var cancelProcess context.CancelFunc
	var heartbeatErr chan error
	if claimed {
		if interval := tb.Idempotency.ClaimHeartbeatInterval(); interval > 0 {
			processCtx, cancelProcess = context.WithCancel(ctx)
			heartbeatErr = make(chan error, 1)
			stopHeartbeat := make(chan struct{})
			heartbeatDone := make(chan struct{})
			go func() {
				defer close(heartbeatDone)
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-stopHeartbeat:
						return
					case <-processCtx.Done():
						return
					case <-ticker.C:
						if err := tb.Idempotency.RenewClaim(processCtx, event.EventID); err != nil {
							heartbeatErr <- err
							cancelProcess()
							return
						}
					}
				}
			}()
			_, remediationErr := tb.Remediator.ProcessAlert(processCtx, vuln)
			close(stopHeartbeat)
			<-heartbeatDone
			cancelProcess()
			select {
			case err := <-heartbeatErr:
				return false, fmt.Errorf("maintain idempotency claim: %w", err)
			default:
			}
			if remediationErr != nil {
				return false, remediationErr
			}
		} else if _, err := tb.Remediator.ProcessAlert(processCtx, vuln); err != nil {
			return false, err
		}
	} else if _, err := tb.Remediator.ProcessAlert(processCtx, vuln); err != nil {
		return false, err
	}
	if claimed {
		if err := tb.Idempotency.CompleteContext(ctx, event.EventID, event.Timestamp); err != nil {
			return false, err
		}
	}
	return true, nil
}
