package storage

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type OperationalMetrics struct {
	mu                 sync.RWMutex
	ActiveIngestCount  int64
	PatchesApplied     int64
	RollbacksTriggered int64
	ProcessingLatency  time.Duration
}

var GlobalMetrics = &OperationalMetrics{}

func (om *OperationalMetrics) IncrementIngest() {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.ActiveIngestCount++
}

func (om *OperationalMetrics) RecordPatch() {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.PatchesApplied++
}

func (om *OperationalMetrics) RecordRollback() {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.RollbacksTriggered++
}

func StartMetricsServer(address string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		GlobalMetrics.mu.RLock()
		defer GlobalMetrics.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "# HELP sentinel_ingested_events_total Total security telemetry records handled.\n")
		fmt.Fprintf(w, "sentinel_ingested_events_total %d\n", GlobalMetrics.ActiveIngestCount)

		fmt.Fprintf(w, "# HELP sentinel_patches_applied_total Total autonomous code modifications deployed.\n")
		fmt.Fprintf(w, "sentinel_patches_applied_total %d\n", GlobalMetrics.PatchesApplied)

		fmt.Fprintf(w, "# HELP sentinel_rollbacks_triggered_total Total safe invariant state rollbacks.\n")
		fmt.Fprintf(w, "sentinel_rollbacks_triggered_total %d\n", GlobalMetrics.RollbacksTriggered)
	})

	server := &http.Server{Addr: address, Handler: mux}
	go func() { _ = server.ListenAndServe() }()
	return server
}
