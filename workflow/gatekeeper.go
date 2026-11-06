package workflow

import (
	"sync"
	"time"
)

type BackpressureGatekeeper struct {
	mu           sync.Mutex
	MaxCapacity  int64
	CurrentToken float64
	LastRefill   time.Time
	RefillRate   float64
}

func NewBackpressureGatekeeper(maxCapacity int64, refillRate float64) *BackpressureGatekeeper {
	return &BackpressureGatekeeper{
		MaxCapacity:  maxCapacity,
		CurrentToken: float64(maxCapacity),
		LastRefill:   time.Now(),
		RefillRate:   refillRate,
	}
}

func (bg *BackpressureGatekeeper) AllowExecution() bool {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(bg.LastRefill).Seconds()
	bg.LastRefill = now

	bg.CurrentToken += elapsed * bg.RefillRate
	if bg.CurrentToken > float64(bg.MaxCapacity) {
		bg.CurrentToken = float64(bg.MaxCapacity)
	}

	if bg.CurrentToken >= 1.0 {
		bg.CurrentToken -= 1.0
		return true
	}
	return false
}
