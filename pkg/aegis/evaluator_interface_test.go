package aegis

import (
	"testing"

	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// mockEvaluator implements RuleEvaluator for testing.
type mockEvaluator struct {
	rule    rules.Rule
	matched bool
}

func (m *mockEvaluator) Evaluate(b *signals.SignalBundle) (rules.Rule, bool) {
	return m.rule, m.matched
}

func TestRuleEvaluator_MockReturnsDecision(t *testing.T) {
	mock := &mockEvaluator{
		rule:    rules.Rule{Name: "test_rule", Action: rules.ActionDeny, Confidence: 0.99},
		matched: true,
	}
	bundle := &signals.SignalBundle{}
	got, ok := mock.Evaluate(bundle)
	if !ok || got.Name != "test_rule" {
		t.Errorf("mock evaluator should return test_rule, got %q ok=%v", got.Name, ok)
	}
}

func TestRuleEvaluator_MockNoMatch(t *testing.T) {
	mock := &mockEvaluator{matched: false}
	_, ok := mock.Evaluate(&signals.SignalBundle{})
	if ok {
		t.Error("mock with matched=false should return ok=false")
	}
}
