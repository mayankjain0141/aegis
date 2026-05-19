package policy_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/policy"
)

func TestBehavioralCond_LoadAndValidate(t *testing.T) {
	src := `
rules:
  - name: retry_test
    priority: 10
    action: deny
    severity: high
    confidence: 0.90
    description: "Test behavioral rule"
    condition:
      behavioral:
        retry_after_deny: true
`
	pf, err := policy.LoadString(src)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	if len(pf.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(pf.Rules))
	}
	if pf.Rules[0].Condition.Behavioral == nil {
		t.Error("Behavioral condition should be populated")
	}
	if pf.Rules[0].Condition.Behavioral.RetryAfterDeny == nil || !*pf.Rules[0].Condition.Behavioral.RetryAfterDeny {
		t.Error("RetryAfterDeny should be true")
	}
}

func TestBehavioralCond_LoadThresholds(t *testing.T) {
	src := `
rules:
  - name: seq_risk_test
    priority: 20
    action: deny
    severity: high
    confidence: 0.88
    description: "Test sequence risk threshold"
    condition:
      behavioral:
        sequence_risk:
          gte: 0.85
`
	pf, err := policy.LoadString(src)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	b := pf.Rules[0].Condition.Behavioral
	if b == nil {
		t.Fatal("Behavioral condition should be populated")
	}
	if b.SequenceRisk == nil {
		t.Fatal("SequenceRisk should be populated")
	}
	if b.SequenceRisk.Gte == nil || *b.SequenceRisk.Gte != 0.85 {
		t.Errorf("SequenceRisk.Gte = %v, want 0.85", b.SequenceRisk.Gte)
	}
}

func TestBehavioralCond_CompilesWithoutError(t *testing.T) {
	boolTrue := true
	cond := policy.Condition{
		Behavioral: &policy.BehavioralCond{
			RetryAfterDeny: &boolTrue,
		},
	}
	pred, err := policy.Compile(cond)
	if err != nil {
		t.Fatalf("Compile behavioral: %v", err)
	}
	// Behavioral conditions always return false in Phase 1 context (no session data)
	if pred != nil {
		result := pred(nil)
		if result {
			t.Error("behavioral predicate should always return false in Phase 1 context")
		}
	}
}

func TestBehavioralCond_Phase2YAMLLoads(t *testing.T) {
	pf, err := policy.LoadFile("../../policies/phase2-behavioral.yaml")
	if err != nil {
		t.Fatalf("LoadFile phase2-behavioral.yaml: %v", err)
	}
	if len(pf.Rules) == 0 {
		t.Fatal("expected at least one behavioral rule")
	}
	for _, r := range pf.Rules {
		if r.Condition.Behavioral == nil {
			t.Errorf("rule %q: expected behavioral condition, got nil", r.Name)
		}
	}
}
