package storage

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOperationalMetricsBucketsLongDurationsAndSandboxStages(t *testing.T) {
	metrics := NewOperationalMetrics()
	metrics.RecordLatency(159 * time.Second)
	metrics.RecordSandboxStage("workspace_prepare", 2*time.Second)
	metrics.RecordSandboxStage("docker_verify", 159*time.Second)
	metrics.RecordSandboxStage("unexpected", time.Second)

	if metrics.LatencyCount != 1 || metrics.LatencyBuckets[180] != 1 || metrics.LatencyBuckets[math.Inf(1)] != 1 {
		t.Fatalf("long remediation latency was not bucketed: count=%d buckets=%v", metrics.LatencyCount, metrics.LatencyBuckets)
	}
	if metrics.SandboxStages["workspace_prepare"].Count != 1 || metrics.SandboxStages["workspace_prepare"].Buckets[2] != 1 {
		t.Fatalf("workspace preparation stage was not recorded: %+v", metrics.SandboxStages["workspace_prepare"])
	}
	if metrics.SandboxStages["docker_verify"].Count != 1 || metrics.SandboxStages["docker_verify"].Buckets[180] != 1 {
		t.Fatalf("Docker verification stage was not bucketed: %+v", metrics.SandboxStages["docker_verify"])
	}
	if _, exists := metrics.SandboxStages["unexpected"]; exists {
		t.Fatal("unexpected stage label was recorded")
	}
}

func TestMetricsServerExposesLivenessAndDeadLetterMetric(t *testing.T) {
	GlobalMetrics.RecordDeadLetter()
	server, err := StartMetricsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartMetricsServer() error = %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	response, err := http.Get("http://" + server.Addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", response.StatusCode)
	}

	response, err = http.Get("http://" + server.Addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# HELP sentinel_dead_lettered_events_total") || !strings.Contains(string(body), "sentinel_dead_lettered_events_total ") {
		t.Fatalf("dead-letter metric missing from scrape output: %s", body)
	}
}
