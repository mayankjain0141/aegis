package rules

import (
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// BehavioralBundle pairs static signals with behavioral signal.
type BehavioralBundle struct {
	Signals  *signals.SignalBundle
	Behavior signals.BehavioralSignal
}

// Deprecated: BehavioralEvaluate will be replaced by YAML-driven behavioral rules
// when Phase 7 runtime evaluation is complete. Currently still used by Engine.
func BehavioralEvaluate(bundle BehavioralBundle) (Rule, bool) {
	b2 := bundle.Behavior
	b1 := bundle.Signals

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

	// Priority 205: ML high-danger signal combined with evasion
	if b1.MLScore > 0.8 && b1.Evasion.Score > 0.2 {
		return Rule{
			Name:       "ml_high_danger_evasion",
			Priority:   205,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.85,
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
