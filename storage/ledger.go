package storage

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"twitch-security/domain"
)

type ImmutableLedger struct {
	mu          sync.Mutex
	LogFile     *os.File
	TargetStore map[string]domain.AgentState
}

func NewImmutableLedger(filepath string) (*ImmutableLedger, error) {
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return nil, err
	}
	return &ImmutableLedger{
		LogFile:     file,
		TargetStore: make(map[string]domain.AgentState),
	}, nil
}

func (il *ImmutableLedger) Close() error {
	if il == nil {
		return nil
	}

	il.mu.Lock()
	defer il.mu.Unlock()

	if il.LogFile == nil {
		return nil
	}
	err := il.LogFile.Close()
	il.LogFile = nil
	return err
}

func (il *ImmutableLedger) CommitStateToLedger(ctx context.Context, state *domain.AgentState) error {
	_ = ctx

	if il == nil || state == nil {
		return nil
	}

	il.mu.Lock()
	defer il.mu.Unlock()

	if il.TargetStore != nil {
		il.TargetStore[state.TaskID] = *state
	}

	logEntry := fmt.Sprintf("[%s] Task: %s | Phase: %s | TraceCount: %d\n",
		time.Now().Format(time.RFC3339), state.TaskID, state.CurrentPhase, len(state.ExecutionTrace))

	if il.LogFile == nil {
		return fmt.Errorf("ledger_closed")
	}

	_, err := il.LogFile.WriteString(logEntry)
	return err
}
