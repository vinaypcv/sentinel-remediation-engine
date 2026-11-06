package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type SecretToken struct {
	TokenID   string
	Value     string
	IsActive  bool
	ExpiresAt time.Time
	Version   int
}

type TokenRotationBroker struct {
	mu         sync.RWMutex
	ActiveKeys map[string][]SecretToken
}

func NewTokenRotationBroker() *TokenRotationBroker {
	return &TokenRotationBroker{
		ActiveKeys: make(map[string][]SecretToken),
	}
}

// RemediateLeakedToken issues a clean credential with a multi-version grace window for active streams.
func (trb *TokenRotationBroker) RemediateLeakedToken(ctx context.Context, service string, leakedValue string) (string, error) {
	_ = ctx

	trb.mu.Lock()
	defer trb.mu.Unlock()

	tokens, exists := trb.ActiveKeys[service]
	if !exists || len(tokens) == 0 {
		return "", errors.New("rotation_failure: target service context not found")
	}

	leakedTokenIdx := -1
	for i, t := range tokens {
		if t.Value == leakedValue {
			leakedTokenIdx = i
			break
		}
	}

	if leakedTokenIdx == -1 {
		return "", errors.New("rotation_failure: token mismatch or already revoked")
	}

	newSecretValue := fmt.Sprintf("sec_v2_clean_%d", time.Now().UnixNano())
	newToken := SecretToken{
		TokenID:   fmt.Sprintf("TKN-%d", time.Now().Unix()),
		Value:     newSecretValue,
		IsActive:  true,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Version:   tokens[leakedTokenIdx].Version + 1,
	}

	trb.ActiveKeys[service] = append(trb.ActiveKeys[service], newToken)

	go func(oldIdx int) {
		time.Sleep(2 * time.Second)
		trb.mu.Lock()
		defer trb.mu.Unlock()
		trb.ActiveKeys[service][oldIdx].IsActive = false
	}(leakedTokenIdx)

	return newSecretValue, nil
}
