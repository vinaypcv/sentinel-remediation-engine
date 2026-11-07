package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"twitch-security/domain"
)

type LedgerRecord struct {
	Timestamp time.Time          `json:"timestamp"`
	State     *domain.AgentState `json:"state"`
}

type ImmutableLedger struct {
	mu sync.Mutex

	LogFile     *os.File
	JSONLogFile *os.File

	TargetStore map[string]domain.AgentState
}

func NewImmutableLedger(path string) (*ImmutableLedger, error) {
	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}

	jsonPath := path + ".jsonl"
	jsonFile, err := os.OpenFile(jsonPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}

	return &ImmutableLedger{
		LogFile:     logFile,
		JSONLogFile: jsonFile,
		TargetStore: make(map[string]domain.AgentState),
	}, nil
}

func (il *ImmutableLedger) Close() error {
	if il == nil {
		return nil
	}

	il.mu.Lock()
	defer il.mu.Unlock()

	var firstErr error
	if il.LogFile != nil {
		if err := il.LogFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if il.JSONLogFile != nil {
		if err := il.JSONLogFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	il.LogFile = nil
	il.JSONLogFile = nil
	return firstErr
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

	if il.LogFile == nil || il.JSONLogFile == nil {
		return fmt.Errorf("ledger_closed")
	}

	ts := time.Now()

	// Human-readable line
	logEntry := fmt.Sprintf("[%s] Task: %s | Phase: %s | TraceCount: %d\n",
		ts.Format(time.RFC3339), state.TaskID, state.CurrentPhase, len(state.ExecutionTrace))
	if _, err := il.LogFile.WriteString(logEntry); err != nil {
		return err
	}
	if err := il.LogFile.Sync(); err != nil {
		return err
	}

	// Structured JSONL
	rec := LedgerRecord{Timestamp: ts, State: state}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := il.JSONLogFile.Write(append(payload, '\n')); err != nil {
		return err
	}
	if err := il.JSONLogFile.Sync(); err != nil {
		return err
	}

	return nil
}

func LedgerJSONPath(humanPath string) string {
	base := filepath.Clean(humanPath)
	return base + ".jsonl"
}
