package rules

import (
	"testing"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

func p2bundle(p2 signals.BehavioralSignal) BehavioralBundle {
	return BehavioralBundle{Phase1: &signals.SignalBundle{}, Phase2: p2}
}

func p2bundleWithPhase1Network(p2 signals.BehavioralSignal, networkScore float64) BehavioralBundle {
	b := &signals.SignalBundle{}
	b.Network.Score = networkScore
	return BehavioralBundle{Phase1: b, Phase2: p2}
}

func p2bundleWithPhase1Critical(p2 signals.BehavioralSignal) BehavioralBundle {
	b := &signals.SignalBundle{}
	b.Path.HasCritical = true
	return BehavioralBundle{Phase1: b, Phase2: p2}
}

// ── Individual rule tests ─────────────────────────────────────────────────

func TestBehavioralEvaluate_RetryAfterDeny(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{RetryAfterDeny: true}))
	if !matched {
		t.Fatal("expected match for retry_after_deny")
	}
	if rule.Action != ActionDeny {
		t.Errorf("action: want deny, got %v", rule.Action)
	}
	if rule.Name != "retry_after_deny" {
		t.Errorf("name: want retry_after_deny, got %q", rule.Name)
	}
	if rule.Confidence != 0.92 {
		t.Errorf("confidence: want 0.92, got %.2f", rule.Confidence)
	}
}

func TestBehavioralEvaluate_ExfilSequence(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		SequenceRisk: 0.90,
		SequenceName: "exfil_after_sensitive_read",
	}))
	if !matched {
		t.Fatal("expected match for exfil sequence")
	}
	if rule.Action != ActionDeny {
		t.Errorf("action: want deny, got %v", rule.Action)
	}
	if rule.Name != "exfil_after_sensitive_read" {
		t.Errorf("name: want exfil_after_sensitive_read, got %q", rule.Name)
	}
}

func TestBehavioralEvaluate_EscalatingAccess(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		SequenceRisk: 0.60,
		SequenceName: "escalating_access",
	}))
	if !matched {
		t.Fatal("expected match for escalating_access sequence")
	}
	if rule.Action != ActionEscalate {
		t.Errorf("action: want escalate, got %v", rule.Action)
	}
}

func TestBehavioralEvaluate_RateBurst(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{RateBurst: 0.80}))
	if !matched {
		t.Fatal("expected match for rate_burst")
	}
	if rule.Action != ActionThrottle {
		t.Errorf("action: want throttle, got %v", rule.Action)
	}
	if rule.Name != "rate_burst" {
		t.Errorf("name: want rate_burst, got %q", rule.Name)
	}
	if rule.Confidence != 0.95 {
		t.Errorf("confidence: want 0.95, got %.2f", rule.Confidence)
	}
}

func TestBehavioralEvaluate_SuddenToolShift_NetworkScore(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundleWithPhase1Network(
		signals.BehavioralSignal{BaselineDeviation: 0.8}, 0.6,
	))
	if !matched {
		t.Fatal("expected match for sudden_tool_shift (network)")
	}
	if rule.Action != ActionEscalate {
		t.Errorf("action: want escalate, got %v", rule.Action)
	}
	if rule.Name != "sudden_tool_shift" {
		t.Errorf("name: want sudden_tool_shift, got %q", rule.Name)
	}
	if rule.Confidence != 0.70 {
		t.Errorf("confidence: want 0.70, got %.2f", rule.Confidence)
	}
}

func TestBehavioralEvaluate_SuddenToolShift_CriticalPath(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundleWithPhase1Critical(
		signals.BehavioralSignal{BaselineDeviation: 0.75},
	))
	if !matched {
		t.Fatal("expected match for sudden_tool_shift (critical path)")
	}
	if rule.Name != "sudden_tool_shift" {
		t.Errorf("name: want sudden_tool_shift, got %q", rule.Name)
	}
}

func TestBehavioralEvaluate_SuddenToolShift_NotTriggeredWithoutCritical(t *testing.T) {
	// High deviation but no critical path or high network score → no sudden_tool_shift
	b := p2bundle(signals.BehavioralSignal{BaselineDeviation: 0.9})
	// Phase1 has no critical path, no high network
	_, matched := BehavioralEvaluate(b)
	// If it matches, it should NOT be sudden_tool_shift
	if matched {
		// Could match session_fits_baseline — not sudden_tool_shift
		rule, _ := BehavioralEvaluate(b)
		if rule.Name == "sudden_tool_shift" {
			t.Error("sudden_tool_shift: must not fire without critical path or high network score")
		}
	}
}

// KEY REGRESSION TEST: session_fits_baseline must NOT fire without established baseline.
// Before the fix, BaselineDeviation=0 (from a fresh session) would incorrectly trigger this.
func TestBehavioralEvaluate_SessionFitsBaseline_WithoutEstablishedBaseline(t *testing.T) {
	_, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		BaselineEstablished: false,
		BaselineDeviation:   0.0, // looks like "perfect match" but baseline isn't set
		RateBurst:           0,
		RetryAfterDeny:      false,
	}))
	if matched {
		rule, _ := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
			BaselineEstablished: false, BaselineDeviation: 0.0,
		}))
		if rule.Name == "session_fits_baseline" {
			t.Error("session_fits_baseline: must NOT fire when baseline is not established (regression)")
		}
	}
}

func TestBehavioralEvaluate_SessionFitsBaseline_WithEstablishedBaseline(t *testing.T) {
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		BaselineEstablished: true,
		BaselineDeviation:   0.1,
		RateBurst:           0,
		RetryAfterDeny:      false,
	}))
	if !matched {
		t.Fatal("session_fits_baseline: expected match with established baseline and low deviation")
	}
	if rule.Action != ActionAllow {
		t.Errorf("action: want allow, got %v", rule.Action)
	}
	if rule.Name != "session_fits_baseline" {
		t.Errorf("name: want session_fits_baseline, got %q", rule.Name)
	}
	if rule.Confidence != 0.85 {
		t.Errorf("confidence: want 0.85, got %.2f", rule.Confidence)
	}
}

func TestBehavioralEvaluate_SessionFitsBaseline_BlockedByRetryAfterDeny(t *testing.T) {
	// Both conditions present: retry_after_deny (priority 200) must win over session_fits_baseline (250)
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		RetryAfterDeny:      true,
		BaselineEstablished: true,
		BaselineDeviation:   0.1,
	}))
	if !matched {
		t.Fatal("expected a rule to match")
	}
	if rule.Name != "retry_after_deny" {
		t.Errorf("priority: want retry_after_deny (200) to beat session_fits_baseline (250), got %q", rule.Name)
	}
}

func TestBehavioralEvaluate_PriorityOrder_RetryBeatsExfil(t *testing.T) {
	// retry_after_deny (200) must beat exfil sequence (201)
	rule, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{
		RetryAfterDeny: true,
		SequenceRisk:   0.90,
		SequenceName:   "exfil_after_sensitive_read",
	}))
	if !matched {
		t.Fatal("expected a match")
	}
	if rule.Name != "retry_after_deny" {
		t.Errorf("priority: want retry_after_deny (200) before exfil (201), got %q", rule.Name)
	}
}

func TestBehavioralEvaluate_NoMatch(t *testing.T) {
	// All signals at zero/false — no rule should fire
	_, matched := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{}))
	if matched {
		rule, _ := BehavioralEvaluate(p2bundle(signals.BehavioralSignal{}))
		// session_fits_baseline requires BaselineEstablished=true — won't fire
		t.Errorf("expected no match for empty behavioral signal, got rule %q", rule.Name)
	}
}

// ── Table-driven summary ──────────────────────────────────────────────────

func TestBehavioralEvaluate_Table(t *testing.T) {
	cases := []struct {
		name        string
		sig         signals.BehavioralSignal
		wantMatch   bool
		wantAction  Action
		wantRule    string
	}{
		{
			name:       "retry_after_deny fires",
			sig:        signals.BehavioralSignal{RetryAfterDeny: true},
			wantMatch:  true,
			wantAction: ActionDeny,
			wantRule:   "retry_after_deny",
		},
		{
			name:       "high sequence risk → deny",
			sig:        signals.BehavioralSignal{SequenceRisk: 0.92, SequenceName: "exfil_after_sensitive_read"},
			wantMatch:  true,
			wantAction: ActionDeny,
			wantRule:   "exfil_after_sensitive_read",
		},
		{
			name:       "medium sequence risk → escalate",
			sig:        signals.BehavioralSignal{SequenceRisk: 0.62, SequenceName: "escalating_access"},
			wantMatch:  true,
			wantAction: ActionEscalate,
			wantRule:   "escalating_access",
		},
		{
			name:       "rate burst → throttle",
			sig:        signals.BehavioralSignal{RateBurst: 0.80},
			wantMatch:  true,
			wantAction: ActionThrottle,
			wantRule:   "rate_burst",
		},
		{
			name:       "below rate burst threshold → no rate_burst",
			sig:        signals.BehavioralSignal{RateBurst: 0.79},
			wantMatch:  false, // 0.79 < 0.80 threshold
		},
		{
			name: "session fits baseline",
			sig: signals.BehavioralSignal{
				BaselineEstablished: true,
				BaselineDeviation:   0.2,
			},
			wantMatch:  true,
			wantAction: ActionAllow,
			wantRule:   "session_fits_baseline",
		},
		{
			name: "session fits baseline blocked — no established baseline",
			sig: signals.BehavioralSignal{
				BaselineEstablished: false,
				BaselineDeviation:   0.0,
			},
			wantMatch: false,
		},
		{
			name:      "all zero → no match",
			sig:       signals.BehavioralSignal{},
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, matched := BehavioralEvaluate(p2bundle(tc.sig))
			if matched != tc.wantMatch {
				t.Fatalf("matched: want %v, got %v (rule=%q)", tc.wantMatch, matched, rule.Name)
			}
			if !tc.wantMatch {
				return
			}
			if rule.Action != tc.wantAction {
				t.Errorf("action: want %v, got %v", tc.wantAction, rule.Action)
			}
			if tc.wantRule != "" && rule.Name != tc.wantRule {
				t.Errorf("rule: want %q, got %q", tc.wantRule, rule.Name)
			}
		})
	}
}
