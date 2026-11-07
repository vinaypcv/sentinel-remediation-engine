package main

import "testing"

func TestSimulationResultMessageDistinguishesDuplicate(t *testing.T) {
	if got := simulationResultMessage("TX-1", true); got != "simulation processed: TX-1" {
		t.Fatalf("processed message = %q", got)
	}
	if got := simulationResultMessage("TX-1", false); got != "simulation skipped (duplicate event): TX-1" {
		t.Fatalf("duplicate message = %q", got)
	}
}
