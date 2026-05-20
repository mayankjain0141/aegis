package main

import (
	"strings"
	"testing"
	"time"
)

// TestEvalInline_ReturnsWithinTimeout verifies that evalInline returns within 4 seconds
// even for pathological input (deeply nested command substitution).
// This test is expected to FAIL until evalInline is given a 3s context timeout (Stage 2).
func TestEvalInline_ReturnsWithinTimeout(t *testing.T) {
	// Construct a pathological command: 50 levels of nested command substitution.
	cmd := strings.Repeat("$(echo ", 50) + "x" + strings.Repeat(")", 50)
	req := &normalizedRequest{
		Tool:      "Shell",
		Arguments: map[string]any{"command": cmd},
		CWD:       "/tmp",
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		evalInline(req)
	}()

	select {
	case <-done:
		// returned in time — pass
	case <-time.After(4 * time.Second):
		t.Fatal("evalInline did not return within 4s — missing timeout")
	}
}

// TestEvalInline_BasicShell_Completes verifies that evalInline returns a non-nil decision
// for a simple, benign shell command.
func TestEvalInline_BasicShell_Completes(t *testing.T) {
	req := &normalizedRequest{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "ls -la /tmp"},
		CWD:       "/tmp",
	}

	decision := evalInline(req)
	if decision == nil {
		t.Fatal("evalInline returned nil decision for a benign command")
	}
}
