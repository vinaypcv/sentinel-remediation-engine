package storage

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"twitch-security/domain"
)

type ImmutableLedger struct {
	path string
	mu   sync.Mutex
}

func NewImmutableLedger(path string) (*ImmutableLedger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &ImmutableLedger{path: path}, nil
}

func (l *ImmutableLedger) CommitStateToLedger(ctx context.Context, state *domain.AgentState) error {
	_ = ctx
	if state == nil {
		return nil
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	w, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err := w.Write(append(payload, '\n')); err != nil {
		return err
	}

	return nil
}