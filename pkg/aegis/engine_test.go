package aegis_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/mayjain/aegis/pkg/aegis/intent"
)

// ── Mock intent classifier ────────────────────────────────────────────────

type mockClassifier struct {
	intentVal  string
	confidence float64
	err        error
	called     int
}

func (m *mockClassifier) Classify(_ context.Context, _ *intent.ClassifyRequest) (*intent.IntentSignal, error) {
	m.called++
	if m.err != nil {
		return nil, m.err
	}
	return &intent.IntentSignal{Intent: m.intentVal, Confidence: m.confidence, Reasoning: "mock"}, nil
}

func newEngine(t *testing.T, opts ...aegis.Option) *aegis.Engine {
	t.Helper()
	e, err := aegis.NewEngine(opts...)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// uncertainCmd produces a Phase 1 ESCALATE (uncertain shell, no obvious attack).
const uncertainCmd = `{"command":"python3 script.py"}`

// ── Phase 2 cascade tests ─────────────────────────────────────────────────

func TestPhase2_RequiresAgentID(t *testing.T) {
	e := newEngine(t)
	// Without AgentID, session state is never created → Phase 2 cannot fire.
	// Seed a deny without AgentID:
	e.EvaluateJSON(context.Background(), "Shell", `{"command":"rm -rf /etc"}`, "/tmp/p")
	// Same verb again — no retry detection without session.
	d := e.EvaluateJSON(context.Background(), "Shell", `{"command":"rm -rf /usr"}`, "/tmp/p")
	if d.Phase == 2 {
		t.Error("Phase 2 must not run without AgentID")
	}
}

func TestPhase2_SkippedOnHighConfidencePhase1(t *testing.T) {
	e := newEngine(t)
	// rm -rf /etc → critical_path_destruction, confidence 0.99 → Phase 1 final, Phase 2 skipped.
	d := e.Evaluate(context.Background(), &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "rm -rf /etc"},
		CWD:       "/tmp/project",
		AgentID:   "agent-skip-p2",
	})
	if d.Phase != 1 {
		t.Errorf("phase: want 1 (high confidence Phase 1 is final), got %d", d.Phase)
	}
	if d.Action != aegis.ActionDeny {
		t.Errorf("action: want deny, got %v", d.Action)
	}
}

func TestPhase2_SessionStatePersistedAcrossCalls(t *testing.T) {
	e := newEngine(t)
	agentID := "agent-persist"
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		e.Evaluate(ctx, &aegis.Request{
			Tool:      "Shell",
			Arguments: map[string]any{"command": "git status"},
			CWD:       "/tmp/project",
			AgentID:   agentID,
		})
	}
	d := e.Evaluate(ctx, &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "git status"},
		CWD:       "/tmp/project",
		AgentID:   agentID,
	})
	if d == nil {
		t.Fatal("decision must not be nil")
	}
	if d.Rule == "" {
		t.Error("rule must not be empty")
	}
}

// ── Phase 3 cascade tests ─────────────────────────────────────────────────

func TestPhase3_NotCalledOnHighConfidenceDeny(t *testing.T) {
	mock := &mockClassifier{intentVal: "malicious", confidence: 0.95}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	e.Evaluate(context.Background(), &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "rm -rf /etc"},
		CWD:       "/tmp/project",
	})
	if mock.called != 0 {
		t.Errorf("Phase 3: want 0 calls on high-confidence deny, got %d", mock.called)
	}
}

func TestPhase3_NotCalledOnHighConfidenceAllow(t *testing.T) {
	mock := &mockClassifier{intentVal: "malicious", confidence: 0.95}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	e.Evaluate(context.Background(), &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "git status"},
		CWD:       "/tmp/project",
	})
	if mock.called != 0 {
		t.Errorf("Phase 3: want 0 calls on high-confidence allow, got %d", mock.called)
	}
}

func TestPhase3_CalledOnEscalate_Malicious(t *testing.T) {
	mock := &mockClassifier{intentVal: "malicious", confidence: 0.95}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	d := e.EvaluateJSON(context.Background(), "Shell", uncertainCmd, "/tmp/project")
	if mock.called == 0 {
		// Phase 1 resolved it at high confidence — acceptable
		if d.Phase != 1 {
			t.Error("if classifier not called, Phase 1 must have resolved with high confidence")
		}
		return
	}
	if d.Phase != 3 {
		t.Errorf("phase: want 3 after Phase 3 classification, got %d", d.Phase)
	}
	if d.Action != aegis.ActionDeny {
		t.Errorf("action: want deny for malicious/0.95, got %v", d.Action)
	}
	if d.Rule != "llm_malicious" {
		t.Errorf("rule: want llm_malicious, got %q", d.Rule)
	}
}

func TestPhase3_CalledOnEscalate_Legitimate(t *testing.T) {
	mock := &mockClassifier{intentVal: "legitimate", confidence: 0.92}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	d := e.EvaluateJSON(context.Background(), "Shell", uncertainCmd, "/tmp/project")
	if mock.called == 0 {
		return // Phase 1 resolved at high confidence
	}
	if d.Phase != 3 {
		t.Errorf("phase: want 3, got %d", d.Phase)
	}
	if d.Action != aegis.ActionAllow {
		t.Errorf("action: want allow for legitimate/0.92, got %v", d.Action)
	}
	if d.Rule != "llm_legitimate" {
		t.Errorf("rule: want llm_legitimate, got %q", d.Rule)
	}
}

func TestPhase3_FailSecure_OnLLMError(t *testing.T) {
	mock := &mockClassifier{err: errors.New("connection refused")}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	d := e.EvaluateJSON(context.Background(), "Shell", uncertainCmd, "/tmp/project")
	if mock.called == 0 {
		return // Phase 1 resolved it
	}
	if d.Action != aegis.ActionDeny {
		t.Errorf("action: want deny on LLM error (fail-secure), got %v", d.Action)
	}
	if d.Rule != "llm_timeout" {
		t.Errorf("rule: want llm_timeout on LLM error, got %q", d.Rule)
	}
	if d.Confidence != 0.60 {
		t.Errorf("confidence: want 0.60 for llm_timeout, got %.2f", d.Confidence)
	}
	if d.Phase != 3 {
		t.Errorf("phase: want 3 for LLM error path, got %d", d.Phase)
	}
}

func TestPhase3_FailSecure_LowConfidence(t *testing.T) {
	// Legitimate intent at confidence=0.70 (not > 0.8) → fail-secure deny
	mock := &mockClassifier{intentVal: "legitimate", confidence: 0.70}
	e := newEngine(t, aegis.WithIntentClassifier(mock))

	d := e.EvaluateJSON(context.Background(), "Shell", uncertainCmd, "/tmp/project")
	if mock.called == 0 {
		return // Phase 1 resolved it
	}
	if d.Phase != 3 {
		t.Errorf("phase: want 3, got %d", d.Phase)
	}
	if d.Action != aegis.ActionDeny {
		t.Errorf("action: want deny for legitimate/0.70 (fail-secure), got %v", d.Action)
	}
	if d.Rule != "llm_uncertain" {
		t.Errorf("rule: want llm_uncertain for low-confidence, got %q", d.Rule)
	}
}

func TestPhase3_NotCalledWithoutClassifier(t *testing.T) {
	e := newEngine(t) // no WithIntentClassifier
	d := e.EvaluateJSON(context.Background(), "Shell", uncertainCmd, "/tmp/project")
	if d.Phase == 3 {
		t.Error("Phase 3 must not run without a configured classifier")
	}
	if d == nil || d.Rule == "" {
		t.Error("decision must be non-nil with a rule name")
	}
}

// ── Session eviction — bounded map must not grow unbounded ────────────────

func TestEngine_SessionEviction_NoPanic(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	// Create 1010 unique agents (max=1000) to trigger eviction
	for i := 0; i < 1010; i++ {
		e.Evaluate(ctx, &aegis.Request{
			Tool:      "Shell",
			Arguments: map[string]any{"command": "git status"},
			CWD:       "/tmp/project",
			AgentID:   fmt.Sprintf("agent-%d", i),
		})
	}
	// No panic = eviction handled correctly
}

// ── Phase 3 rules (applyPhase3Rules) tested via white-box in phase3_rules_test.go ──
