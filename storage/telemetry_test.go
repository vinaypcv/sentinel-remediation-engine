package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"twitch-security/domain"
)

type countingRemediator struct {
	calls int
	fail  bool
}

type heartbeatIdempotencyStore struct {
	renewals   int
	completed  bool
	claimLease time.Duration
}

func (s *heartbeatIdempotencyStore) Claim(context.Context, string) (bool, error) { return true, nil }
func (s *heartbeatIdempotencyStore) Release(string)                              {}
func (s *heartbeatIdempotencyStore) RenewClaim(context.Context, string) error {
	s.renewals++
	return nil
}
func (s *heartbeatIdempotencyStore) ClaimHeartbeatInterval() time.Duration { return s.claimLease }
func (s *heartbeatIdempotencyStore) CompleteContext(context.Context, string, time.Time) error {
	s.completed = true
	return nil
}

type slowRemediator struct{}

func (slowRemediator) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	timer := time.NewTimer(30 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return &domain.AgentState{TaskID: vuln.ID, CurrentPhase: "COMPLETED"}, nil
	}
}

func (r *countingRemediator) ProcessAlert(_ context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	r.calls++
	if r.fail {
		return nil, errors.New("test remediation failure")
	}
	return &domain.AgentState{TaskID: vuln.ID, CurrentPhase: "COMPLETED"}, nil
}

func TestProcessEventWithResultReportsDurableDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotency.jsonl")
	firstIndex, err := NewIdempotencyIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	event := SecurityTelemetryEvent{
		EventID: "TX-REPLAY-1", Payload: "test alert", Timestamp: time.Now().UTC(),
	}
	firstRemediator := &countingRemediator{}
	firstBuffer := &TelemetryBuffer{Remediator: firstRemediator, Idempotency: firstIndex}
	processed, err := firstBuffer.ProcessEventWithResult(context.Background(), event)
	if err != nil || !processed {
		t.Fatalf("first ProcessEventWithResult() = (%v, %v), want (true, nil)", processed, err)
	}

	reloadedIndex, err := NewIdempotencyIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicateRemediator := &countingRemediator{}
	duplicateBuffer := &TelemetryBuffer{Remediator: duplicateRemediator, Idempotency: reloadedIndex}
	processed, err = duplicateBuffer.ProcessEventWithResult(context.Background(), event)
	if err != nil || processed {
		t.Fatalf("duplicate ProcessEventWithResult() = (%v, %v), want (false, nil)", processed, err)
	}
	if firstRemediator.calls != 1 || duplicateRemediator.calls != 0 {
		t.Fatalf("duplicate remediation calls: first=%d duplicate=%d, want 1 and 0", firstRemediator.calls, duplicateRemediator.calls)
	}
}

func TestProcessEventRenewsLongRunningDistributedIdempotencyClaim(t *testing.T) {
	store := &heartbeatIdempotencyStore{claimLease: 5 * time.Millisecond}
	buffer := &TelemetryBuffer{Remediator: slowRemediator{}, Idempotency: store}
	processed, err := buffer.ProcessEventWithResult(context.Background(), SecurityTelemetryEvent{
		EventID: "TX-long-running", Payload: "alert", Timestamp: time.Now().UTC(),
	})
	if err != nil || !processed {
		t.Fatalf("ProcessEventWithResult() = (%v, %v), want (true, nil)", processed, err)
	}
	if store.renewals == 0 || !store.completed {
		t.Fatalf("claim renewals=%d completed=%v, want at least one renewal and completion", store.renewals, store.completed)
	}
}
