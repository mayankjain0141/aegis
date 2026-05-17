package rules

import (
	"sort"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// Action is the decision an evaluation produces.
type Action string

const (
	ActionAllow    Action = "allow"
	ActionDeny     Action = "deny"
	ActionEscalate Action = "escalate"
	ActionThrottle Action = "throttle"
)

// Rule is a single policy rule with a condition and outcome.
type Rule struct {
	Name       string
	Priority   int    // lower number = higher priority; first match wins
	Action     Action
	Severity   string  // "critical", "high", "medium", "low", ""
	Confidence float64 // empirically calibrated; 1.0 - FPR on eval corpus
	Condition  func(*signals.SignalBundle) bool
}

// Evaluate returns the first matching rule in priority order.
// Returns the matched rule and true, or zero value and false.
func Evaluate(rules []Rule, bundle *signals.SignalBundle) (Rule, bool) {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	// SliceStable preserves source-order for equal priorities, making
	// evaluation order deterministic even when priorities collide.
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	for _, rule := range sorted {
		if rule.Condition(bundle) {
			return rule, true
		}
	}
	return Rule{}, false
}
