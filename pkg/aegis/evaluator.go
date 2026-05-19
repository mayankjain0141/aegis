package aegis

import (
	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// RuleEvaluator evaluates a SignalBundle against a set of rules.
// The returned Rule is the first match; bool is false when no rule matched.
type RuleEvaluator interface {
	Evaluate(b *signals.SignalBundle) (rules.Rule, bool)
}

// staticRuleEvaluator wraps the legacy rules.Evaluate function.
type staticRuleEvaluator struct {
	rules []rules.Rule
}

func newStaticRuleEvaluator(r []rules.Rule) RuleEvaluator {
	return &staticRuleEvaluator{rules: r}
}

func (e *staticRuleEvaluator) Evaluate(b *signals.SignalBundle) (rules.Rule, bool) {
	return rules.Evaluate(e.rules, b)
}
