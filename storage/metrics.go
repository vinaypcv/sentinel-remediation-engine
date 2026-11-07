package storage

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

type OperationalMetrics struct {
	mu sync.RWMutex

	ActiveIngestCount  int64
	PatchesApplied     int64
	RollbacksTriggered int64
	DuplicateEvents    int64
	DeadLetteredEvents int64

	PhaseTransitions map[string]int64

	LatencyBuckets    map[float64]int64
	LatencySumSeconds float64
	LatencyCount      int64
	SandboxStages     map[string]*durationHistogram
}

type durationHistogram struct {
	Buckets    map[float64]int64
	SumSeconds float64
	Count      int64
}

var GlobalMetrics = NewOperationalMetrics()

func NewOperationalMetrics() *OperationalMetrics {
	return &OperationalMetrics{
		PhaseTransitions: make(map[string]int64),
		LatencyBuckets:   make(map[float64]int64),
		SandboxStages:    make(map[string]*durationHistogram),
	}
}

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

func (om *OperationalMetrics) RecordDuplicate() {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.DuplicateEvents++
}

func (om *OperationalMetrics) RecordDeadLetter() {
	om.mu.Lock()
	defer om.mu.Unlock()
	om.DeadLetteredEvents++
}

func (om *OperationalMetrics) RecordPhase(phase string) {
	if phase == "" {
		return
	}
	om.mu.Lock()
	defer om.mu.Unlock()
	om.PhaseTransitions[phase]++
}

func (om *OperationalMetrics) RecordLatency(d time.Duration) {
	if d < 0 {
		d = 0
	}

	seconds := d.Seconds()
	om.mu.Lock()
	defer om.mu.Unlock()

	om.LatencySumSeconds += seconds
	om.LatencyCount++
	observeDuration(om.LatencyBuckets, om.LatencyCount, seconds)
}

func (om *OperationalMetrics) RecordSandboxStage(stage string, d time.Duration) {
	if stage != "workspace_prepare" && stage != "docker_verify" {
		return
	}
	if d < 0 {
		d = 0
	}

	om.mu.Lock()
	defer om.mu.Unlock()
	histogram := om.SandboxStages[stage]
	if histogram == nil {
		histogram = &durationHistogram{Buckets: make(map[float64]int64)}
		om.SandboxStages[stage] = histogram
	}
	histogram.Count++
	histogram.SumSeconds += d.Seconds()
	observeDuration(histogram.Buckets, histogram.Count, d.Seconds())
}

func observeDuration(buckets map[float64]int64, count int64, seconds float64) {
	for _, bound := range defaultLatencyBuckets() {
		if seconds <= bound {
			buckets[bound]++
		}
	}
	buckets[math.Inf(1)] = count
}

func defaultLatencyBuckets() []float64 {
	return []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 180, 300, 600}
}

func StartMetricsServer(address string) (*http.Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for Prometheus metrics on %s: %w", address, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		GlobalMetrics.mu.RLock()
		defer GlobalMetrics.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "# HELP sentinel_ingested_events_total Total security telemetry records handled.\n")
		fmt.Fprintf(w, "# TYPE sentinel_ingested_events_total counter\n")
		fmt.Fprintf(w, "sentinel_ingested_events_total %d\n", GlobalMetrics.ActiveIngestCount)

		fmt.Fprintf(w, "# HELP sentinel_patches_applied_total Total autonomous code modifications deployed.\n")
		fmt.Fprintf(w, "# TYPE sentinel_patches_applied_total counter\n")
		fmt.Fprintf(w, "sentinel_patches_applied_total %d\n", GlobalMetrics.PatchesApplied)

		fmt.Fprintf(w, "# HELP sentinel_rollbacks_triggered_total Total safe invariant state rollbacks.\n")
		fmt.Fprintf(w, "# TYPE sentinel_rollbacks_triggered_total counter\n")
		fmt.Fprintf(w, "sentinel_rollbacks_triggered_total %d\n", GlobalMetrics.RollbacksTriggered)
		fmt.Fprintf(w, "# HELP sentinel_duplicate_events_total Events skipped because their IDs were already completed.\n")
		fmt.Fprintf(w, "# TYPE sentinel_duplicate_events_total counter\n")
		fmt.Fprintf(w, "sentinel_duplicate_events_total %d\n", GlobalMetrics.DuplicateEvents)
		fmt.Fprintf(w, "# HELP sentinel_dead_lettered_events_total Kinesis records durably handed off to the dead-letter queue.\n")
		fmt.Fprintf(w, "# TYPE sentinel_dead_lettered_events_total counter\n")
		fmt.Fprintf(w, "sentinel_dead_lettered_events_total %d\n", GlobalMetrics.DeadLetteredEvents)

		fmt.Fprintf(w, "# HELP sentinel_phase_transitions_total Phase transition counters.\n")
		fmt.Fprintf(w, "# TYPE sentinel_phase_transitions_total counter\n")

		phases := make([]string, 0, len(GlobalMetrics.PhaseTransitions))
		for phase := range GlobalMetrics.PhaseTransitions {
			phases = append(phases, phase)
		}
		sort.Strings(phases)
		for _, phase := range phases {
			fmt.Fprintf(w, "sentinel_phase_transitions_total{phase=\"%s\"} %d\n", phase, GlobalMetrics.PhaseTransitions[phase])
		}

		fmt.Fprintf(w, "# HELP sentinel_processing_latency_seconds Remediation processing latency histogram.\n")
		fmt.Fprintf(w, "# TYPE sentinel_processing_latency_seconds histogram\n")

		bucketKeys := make([]float64, 0, len(GlobalMetrics.LatencyBuckets))
		for b := range GlobalMetrics.LatencyBuckets {
			bucketKeys = append(bucketKeys, b)
		}
		sort.Float64s(bucketKeys)

		for _, b := range bucketKeys {
			count := GlobalMetrics.LatencyBuckets[b]
			if math.IsInf(b, 1) {
				fmt.Fprintf(w, "sentinel_processing_latency_seconds_bucket{le=\"+Inf\"} %d\n", count)
				continue
			}
			fmt.Fprintf(w, "sentinel_processing_latency_seconds_bucket{le=\"%g\"} %d\n", b, count)
		}
		fmt.Fprintf(w, "sentinel_processing_latency_seconds_sum %g\n", GlobalMetrics.LatencySumSeconds)
		fmt.Fprintf(w, "sentinel_processing_latency_seconds_count %d\n", GlobalMetrics.LatencyCount)

		fmt.Fprintf(w, "# HELP sentinel_sandbox_stage_duration_seconds Duration of sandbox preparation and verification stages.\n")
		fmt.Fprintf(w, "# TYPE sentinel_sandbox_stage_duration_seconds histogram\n")
		stages := make([]string, 0, len(GlobalMetrics.SandboxStages))
		for stage := range GlobalMetrics.SandboxStages {
			stages = append(stages, stage)
		}
		sort.Strings(stages)
		for _, stage := range stages {
			histogram := GlobalMetrics.SandboxStages[stage]
			bounds := make([]float64, 0, len(histogram.Buckets))
			for bound := range histogram.Buckets {
				bounds = append(bounds, bound)
			}
			sort.Float64s(bounds)
			for _, bound := range bounds {
				if math.IsInf(bound, 1) {
					fmt.Fprintf(w, "sentinel_sandbox_stage_duration_seconds_bucket{stage=\"%s\",le=\"+Inf\"} %d\n", stage, histogram.Buckets[bound])
					continue
				}
				fmt.Fprintf(w, "sentinel_sandbox_stage_duration_seconds_bucket{stage=\"%s\",le=\"%g\"} %d\n", stage, bound, histogram.Buckets[bound])
			}
			fmt.Fprintf(w, "sentinel_sandbox_stage_duration_seconds_sum{stage=\"%s\"} %g\n", stage, histogram.SumSeconds)
			fmt.Fprintf(w, "sentinel_sandbox_stage_duration_seconds_count{stage=\"%s\"} %d\n", stage, histogram.Count)
		}
	})

	srv := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	return srv, nil
}
