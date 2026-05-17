package rules

import (
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// BehavioralBundle pairs Phase 1 signals with Phase 2 behavioral signal.
type BehavioralBundle struct {
	Phase1 *signals.SignalBundle
	Phase2 signals.BehavioralSignal
}

// Phase2Rules returns the behavioral Phase 2 rule set.
// These rules run when Phase 1 confidence is below the threshold.
func Phase2Rules() []Rule {
	return []Rule{
		{
			Name:       "retry_after_deny",
			Priority:   200,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.92,
			Condition:  func(b *signals.SignalBundle) bool { return false }, // unused; Phase2 uses BehavioralEvaluate
		},
	}
}

// BehavioralEvaluate evaluates Phase 2 behavioral rules.
// Returns a decision and true if a rule fired, or zero and false.
func BehavioralEvaluate(bundle BehavioralBundle) (Rule, bool) {
	b2 := bundle.Phase2
	b1 := bundle.Phase1

	// Priority 200: retry after deny
	if b2.RetryAfterDeny {
		return Rule{
			Name:       "retry_after_deny",
			Priority:   200,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.92,
		}, true
	}

	// Priority 201: known exfil sequence
	if b2.SequenceRisk >= 0.85 {
		return Rule{
			Name:       b2.SequenceName,
			Priority:   201,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: b2.SequenceRisk,
		}, true
	}

	// Priority 202: escalating access sequence
	if b2.SequenceRisk >= 0.60 {
		return Rule{
			Name:       b2.SequenceName,
			Priority:   202,
			Action:     ActionEscalate,
			Severity:   "high",
			Confidence: b2.SequenceRisk,
		}, true
	}

	// Priority 203: rate burst
	if b2.RateBurst >= 0.80 {
		return Rule{
			Name:       "rate_burst",
			Priority:   203,
			Action:     ActionThrottle,
			Severity:   "medium",
			Confidence: 0.95,
		}, true
	}

	// Priority 204: sudden tool shift from safe baseline
	if b2.BaselineDeviation > 0.7 && (b1.Network.Score > 0.5 || b1.Path.HasCritical) {
		return Rule{
			Name:       "sudden_tool_shift",
			Priority:   204,
			Action:     ActionEscalate,
			Severity:   "medium",
			Confidence: 0.70,
		}, true
	}

	// Priority 250: session fits baseline — only fires after baseline is established (>5 min)
	// If no baseline yet, don't trust the low deviation score
	if b2.BaselineEstablished && b2.BaselineDeviation < 0.3 && b2.RateBurst == 0 && !b2.RetryAfterDeny {
		return Rule{
			Name:       "session_fits_baseline",
			Priority:   250,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
		}, true
	}

	return Rule{}, false
}
