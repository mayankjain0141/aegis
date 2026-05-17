package aegis

// Tests for applyPhase3Rules — in package aegis to access the unexported function.

import (
	"testing"

	"github.com/mayjain/aegis/pkg/aegis/intent"
)

func TestApplyPhase3Rules(t *testing.T) {
	cases := []struct {
		name       string
		intent_    string
		confidence float64
		wantAction Action
		wantRule   string
		wantConf   float64
	}{
		{
			name: "malicious high confidence → deny",
			intent_: "malicious", confidence: 0.95,
			wantAction: ActionDeny, wantRule: "llm_malicious", wantConf: 0.90,
		},
		{
			name: "malicious exactly 0.8 → fail-secure (not > 0.8)",
			intent_: "malicious", confidence: 0.80,
			wantAction: ActionDeny, wantRule: "llm_uncertain", wantConf: 0.65,
		},
		{
			name: "malicious low confidence → fail-secure",
			intent_: "malicious", confidence: 0.50,
			wantAction: ActionDeny, wantRule: "llm_uncertain", wantConf: 0.65,
		},
		{
			name: "suspicious high confidence → escalate",
			intent_: "suspicious", confidence: 0.85,
			wantAction: ActionEscalate, wantRule: "llm_suspicious_high", wantConf: 0.75,
		},
		{
			name: "suspicious low confidence → fail-secure",
			intent_: "suspicious", confidence: 0.75,
			wantAction: ActionDeny, wantRule: "llm_uncertain", wantConf: 0.65,
		},
		{
			name: "legitimate high confidence → allow",
			intent_: "legitimate", confidence: 0.92,
			wantAction: ActionAllow, wantRule: "llm_legitimate", wantConf: 0.85,
		},
		{
			name: "legitimate low confidence → fail-secure",
			intent_: "legitimate", confidence: 0.60,
			wantAction: ActionDeny, wantRule: "llm_uncertain", wantConf: 0.65,
		},
		{
			name: "empty intent → fail-secure",
			intent_: "", confidence: 0.95,
			wantAction: ActionDeny, wantRule: "llm_uncertain", wantConf: 0.65,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &intent.IntentSignal{
				Intent:     tc.intent_,
				Confidence: tc.confidence,
				Reasoning:  "test",
			}
			d := applyPhase3Rules(sig, 0.5)
			if d.Action != tc.wantAction {
				t.Errorf("action: want %v, got %v", tc.wantAction, d.Action)
			}
			if d.Rule != tc.wantRule {
				t.Errorf("rule: want %q, got %q", tc.wantRule, d.Rule)
			}
			if d.Confidence != tc.wantConf {
				t.Errorf("confidence: want %.2f, got %.2f", tc.wantConf, d.Confidence)
			}
			if d.Phase != 3 {
				t.Errorf("phase: want 3, got %d", d.Phase)
			}
		})
	}
}

func TestApplyPhase3Rules_CompositeScorePreserved(t *testing.T) {
	sig := &intent.IntentSignal{Intent: "malicious", Confidence: 0.95}
	composite := 0.87
	d := applyPhase3Rules(sig, composite)
	if d.CompositeScore != composite {
		t.Errorf("CompositeScore: want %.2f, got %.2f", composite, d.CompositeScore)
	}
}
