package signals

import (
	"strings"
	"time"
)

// BehavioralSignal is the Phase 2 signal derived from session history.
type BehavioralSignal struct {
	RateBurst           float64 // calls/min vs baseline; 0=normal, 0.8=burst
	SequenceRisk        float64 // 0-1 from known-bad sequence matching
	EscalationGradient  float64 // slope of risk scores; positive = escalating
	BaselineDeviation   float64 // cosine distance from baseline tool distribution
	BaselineEstablished bool    // whether the baseline has been set (>5 min of traffic)
	RetryAfterDeny      bool    // same or equivalent verb within 60s of deny
	RetryVerb           string  // the verb being retried
	SequenceName        string  // which known-bad sequence matched (if any)
	Score               float64 // composite behavioral score
}

// SessionHistoryEntry is what Phase 2 receives from session state (avoids import cycle).
type SessionHistoryEntry struct {
	Time           time.Time
	Tool           string
	ArgSummary     string
	Decision       string
	Rule           string
	CompositeScore float64
	// Derived fields set from signal analysis
	PathSensitive bool
	PathCritical  bool
	NetworkWrite  bool
	DLPHit        bool
	Verb          string
}

// ComputeBehavioral computes Phase 2 signal from session history.
func ComputeBehavioral(
	current *SignalBundle,
	currentVerb string,
	history []SessionHistoryEntry,
	callsLastMinute int,
	lastDenyTimeAgo time.Duration,
	lastDenyVerb string,
	baselineDeviation float64,
	riskTrend float64,
) BehavioralSignal {
	sig := BehavioralSignal{
		EscalationGradient: riskTrend,
		BaselineDeviation:  baselineDeviation,
	}

	// Rate burst: >60 calls/min is suspicious
	if callsLastMinute > 60 {
		sig.RateBurst = 0.80
	} else if callsLastMinute > 30 {
		sig.RateBurst = 0.40
	}

	// Retry after deny
	if lastDenyVerb != "" && lastDenyTimeAgo > 0 && lastDenyTimeAgo < 60*time.Second {
		if currentVerb != "" && (currentVerb == lastDenyVerb || equivalentVerb(currentVerb, lastDenyVerb)) {
			sig.RetryAfterDeny = true
			sig.RetryVerb = currentVerb
		}
	}

	// Sequence matching
	sig.SequenceRisk, sig.SequenceName = matchSequences(current, history)

	// Composite behavioral score
	score := 0.0
	if sig.RateBurst > 0 {
		score += sig.RateBurst * 0.3
	}
	if sig.RetryAfterDeny {
		score += 0.6
	}
	score += sig.SequenceRisk * 0.4
	if sig.EscalationGradient > 0.1 {
		score += sig.EscalationGradient * 0.2
	}
	if sig.BaselineDeviation > 0.7 {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}
	sig.Score = score

	return sig
}

func equivalentVerb(a, b string) bool {
	// Evasion variants: same semantic, different spelling
	groups := [][]string{
		{"rm", "rmdir", "shred", "unlink"},
		{"curl", "wget", "fetch"},
		{"nc", "ncat", "netcat", "socat"},
		{"python", "python3", "py"},
		{"bash", "sh", "zsh"},
	}
	for _, g := range groups {
		inA, inB := false, false
		for _, v := range g {
			if v == a {
				inA = true
			}
			if v == b {
				inB = true
			}
		}
		if inA && inB {
			return true
		}
	}
	return false
}

func matchSequences(current *SignalBundle, history []SessionHistoryEntry) (float64, string) {
	// exfil_after_sensitive_read: sensitive file read in last 30s, now network write
	if current.Network.HasDataFlag || current.Network.Score > 0.5 {
		cutoff := time.Now().Add(-30 * time.Second)
		for _, h := range history {
			if h.Time.After(cutoff) && h.PathSensitive {
				return 0.90, "exfil_after_sensitive_read"
			}
		}
	}

	// escalating_access: 3+ critical path accesses in 2 minutes
	if current.Path.HasCritical {
		cutoff := time.Now().Add(-2 * time.Minute)
		critCount := 0
		for _, h := range history {
			if h.Time.After(cutoff) && h.PathCritical {
				critCount++
			}
		}
		if critCount >= 2 {
			return 0.60, "escalating_access"
		}
	}

	// encoded_exfil: sensitive read → base64 → network
	if current.Network.HasDataFlag {
		cutoff := time.Now().Add(-60 * time.Second)
		var steps []string
		for _, h := range history {
			if h.Time.After(cutoff) {
				steps = append(steps, h.ArgSummary)
			}
		}
		hasSensitiveRead := false
		hasBase64 := false
		for _, h := range history {
			if h.Time.After(cutoff) {
				if h.PathSensitive {
					hasSensitiveRead = true
				}
				if strings.Contains(h.ArgSummary, "base64") || strings.Contains(h.ArgSummary, "xxd") {
					hasBase64 = true
				}
			}
		}
		if hasSensitiveRead && hasBase64 {
			return 0.85, "encoded_exfil"
		}
		_ = steps
	}

	return 0.0, ""
}
