package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

var ErrEventInFlight = errors.New("event is already being processed")

type EventIdempotencyStore interface {
	Claim(context.Context, string) (bool, error)
	Release(string)
	RenewClaim(context.Context, string) error
	ClaimHeartbeatInterval() time.Duration
	CompleteContext(context.Context, string, time.Time) error
}

type IdempotencyIndex struct {
	mu sync.Mutex

	seen     map[string]time.Time
	inFlight map[string]struct{}

	persistPath string
}

func NewIdempotencyIndex(persistPath string) (*IdempotencyIndex, error) {
	idx := &IdempotencyIndex{
		seen:        make(map[string]time.Time),
		inFlight:    make(map[string]struct{}),
		persistPath: persistPath,
	}

	if persistPath == "" {
		return idx, nil
	}

	f, err := os.Open(persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return idx, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		var rec struct {
			ID        string    `json:"id"`
			SeenAt    time.Time `json:"seen_at"`
			EventTime time.Time `json:"event_time"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.ID == "" {
			continue
		}
		idx.seen[rec.ID] = rec.SeenAt
	}

	return idx, nil
}

func (ix *IdempotencyIndex) Seen(id string) bool {
	if ix == nil || id == "" {
		return false
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	_, ok := ix.seen[id]
	return ok
}

func (ix *IdempotencyIndex) Begin(id string) (bool, error) {
	if ix == nil || id == "" {
		return false, fmt.Errorf("idempotency event ID is required")
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, exists := ix.seen[id]; exists {
		return false, nil
	}
	if _, exists := ix.inFlight[id]; exists {
		return false, ErrEventInFlight
	}
	ix.inFlight[id] = struct{}{}
	return true, nil
}

func (ix *IdempotencyIndex) Claim(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return ix.Begin(id)
}

func (ix *IdempotencyIndex) Release(id string) {
	if ix == nil {
		return
	}
	ix.mu.Lock()
	delete(ix.inFlight, id)
	ix.mu.Unlock()
}

func (ix *IdempotencyIndex) RenewClaim(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, exists := ix.inFlight[id]; !exists {
		return ErrEventInFlight
	}
	return nil
}

func (ix *IdempotencyIndex) ClaimHeartbeatInterval() time.Duration { return 0 }

func (ix *IdempotencyIndex) MarkSeen(id string, eventTime time.Time) error {
	if ix == nil || id == "" {
		return nil
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()

	return ix.completeLocked(id, eventTime)
}

func (ix *IdempotencyIndex) Complete(id string, eventTime time.Time) error {
	if ix == nil || id == "" {
		return fmt.Errorf("idempotency event ID is required")
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.completeLocked(id, eventTime)
}

func (ix *IdempotencyIndex) CompleteContext(ctx context.Context, id string, eventTime time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ix.Complete(id, eventTime)
}

func (ix *IdempotencyIndex) completeLocked(id string, eventTime time.Time) error {
	now := time.Now()
	if ix.persistPath != "" {
		f, err := os.OpenFile(ix.persistPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		rec := struct {
			ID        string    `json:"id"`
			SeenAt    time.Time `json:"seen_at"`
			EventTime time.Time `json:"event_time"`
		}{ID: id, SeenAt: now, EventTime: eventTime}
		payload, err := json.Marshal(rec)
		if err == nil {
			_, err = f.Write(append(payload, '\n'))
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	ix.seen[id] = now
	delete(ix.inFlight, id)
	return nil
}
