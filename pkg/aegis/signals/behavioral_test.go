package signals

import (
	"testing"
	"time"
)

// helpers to build minimal signal bundles for behavioral tests

func bundleWithNetwork(score float64, hasDataFlag bool) *SignalBundle {
	b := &SignalBundle{}
	b.Network.Score = score
	b.Network.HasDataFlag = hasDataFlag
	return b
}

func bundleWithPath(hasCritical, hasSensitive bool) *SignalBundle {
	b := &SignalBundle{}
	b.Path.HasCritical = hasCritical
	b.Path.HasSensitive = hasSensitive
	return b
}

func historyEntry(t time.Time, pathSensitive, pathCritical bool, argSummary string) SessionHistoryEntry {
	return SessionHistoryEntry{
		Time:          t,
		Tool:          "Shell",
		ArgSummary:    argSummary,
		PathSensitive: pathSensitive,
		PathCritical:  pathCritical,
		Decision:      "allow",
	}
}

func callBehavioral(bundle *SignalBundle, verb string, history []SessionHistoryEntry,
	callsPerMin int, lastDenyAgo time.Duration, lastDenyVerb string,
	baselineDev, riskTrend float64) BehavioralSignal {
	b2 := ComputeBehavioral(bundle, verb, history, callsPerMin, lastDenyAgo, lastDenyVerb, baselineDev, riskTrend, time.Now())
	return b2
}

// ── RetryAfterDeny ────────────────────────────────────────────────────────

func TestRetryAfterDeny_SameVerb(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "rm", nil, 0, 30*time.Second, "rm", 0, 0)
	if !b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want true for same verb within 60s of deny")
	}
	if b.RetryVerb != "rm" {
		t.Errorf("RetryVerb: want 'rm', got %q", b.RetryVerb)
	}
}

func TestRetryAfterDeny_EquivalentVerbs(t *testing.T) {
	cases := []struct {
		lastVerb, currentVerb string
	}{
		{"rm", "shred"},
		{"rm", "unlink"},
		{"curl", "wget"},
		{"nc", "ncat"},
		{"nc", "socat"},
		{"bash", "sh"},
		{"python", "python3"},
	}
	for _, tc := range cases {
		b := callBehavioral(&SignalBundle{}, tc.currentVerb, nil, 0, 30*time.Second, tc.lastVerb, 0, 0)
		if !b.RetryAfterDeny {
			t.Errorf("RetryAfterDeny(%s→%s): want true for semantically equivalent verbs", tc.lastVerb, tc.currentVerb)
		}
	}
}

func TestRetryAfterDeny_DifferentVerb(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "git", nil, 0, 30*time.Second, "rm", 0, 0)
	if b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want false for unrelated verb")
	}
}

func TestRetryAfterDeny_TooLongAgo(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "rm", nil, 0, 90*time.Second, "rm", 0, 0)
	if b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want false when deny was >60s ago")
	}
}

// Regression: before the fix, lastDenyVerb was always "" causing RetryAfterDeny to never fire.
// This test ensures the guard on empty lastDenyVerb prevents false positives.
func TestRetryAfterDeny_EmptyLastVerb(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "rm", nil, 0, 30*time.Second, "", 0, 0)
	if b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want false when lastDenyVerb is empty (guard against old bug)")
	}
}

func TestRetryAfterDeny_EmptyCurrentVerb(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 0, 30*time.Second, "rm", 0, 0)
	if b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want false when current verb is empty")
	}
}

func TestRetryAfterDeny_ZeroDenyTime(t *testing.T) {
	// lastDenyTimeAgo == 0 means no deny recorded
	b := callBehavioral(&SignalBundle{}, "rm", nil, 0, 0, "rm", 0, 0)
	if b.RetryAfterDeny {
		t.Error("RetryAfterDeny: want false when deny time is zero (no deny recorded)")
	}
}

// ── Rate Burst ────────────────────────────────────────────────────────────

func TestRateBurst_High(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 70, 0, "", 0, 0)
	if b.RateBurst != 0.80 {
		t.Errorf("RateBurst: want 0.80 for >60 calls/min, got %.2f", b.RateBurst)
	}
}

func TestRateBurst_Medium(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 35, 0, "", 0, 0)
	if b.RateBurst != 0.40 {
		t.Errorf("RateBurst: want 0.40 for >30 calls/min, got %.2f", b.RateBurst)
	}
}

func TestRateBurst_Normal(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 10, 0, "", 0, 0)
	if b.RateBurst != 0.0 {
		t.Errorf("RateBurst: want 0.0 for normal rate, got %.2f", b.RateBurst)
	}
}

// ── Sequence matching ─────────────────────────────────────────────────────

func TestMatchSequences_ExfilAfterSensitiveRead(t *testing.T) {
	bundle := bundleWithNetwork(0, true) // HasDataFlag=true
	history := []SessionHistoryEntry{
		historyEntry(time.Now().Add(-20*time.Second), true, false, "cat /etc/shadow"),
	}
	b := callBehavioral(bundle, "curl", history, 0, 0, "", 0, 0)
	if b.SequenceRisk < 0.89 {
		t.Errorf("SequenceRisk: want ~0.90 for exfil_after_sensitive_read, got %.2f", b.SequenceRisk)
	}
	if b.SequenceName != "exfil_after_sensitive_read" {
		t.Errorf("SequenceName: want 'exfil_after_sensitive_read', got %q", b.SequenceName)
	}
}

func TestMatchSequences_ExfilAfterSensitiveRead_TooOld(t *testing.T) {
	bundle := bundleWithNetwork(0, true)
	history := []SessionHistoryEntry{
		// 45 seconds ago — outside the 30s window
		historyEntry(time.Now().Add(-45*time.Second), true, false, "cat /etc/shadow"),
	}
	b := callBehavioral(bundle, "curl", history, 0, 0, "", 0, 0)
	if b.SequenceRisk > 0.01 {
		t.Errorf("SequenceRisk: want 0.0 (too old), got %.2f", b.SequenceRisk)
	}
}

func TestMatchSequences_EncodedExfil(t *testing.T) {
	bundle := bundleWithNetwork(0, true)
	history := []SessionHistoryEntry{
		historyEntry(time.Now().Add(-50*time.Second), true, false, "cat /etc/shadow"),
		historyEntry(time.Now().Add(-40*time.Second), false, false, "cat /etc/shadow | base64"),
	}
	b := callBehavioral(bundle, "curl", history, 0, 0, "", 0, 0)
	if b.SequenceRisk < 0.84 {
		t.Errorf("SequenceRisk: want ~0.85 for encoded_exfil, got %.2f", b.SequenceRisk)
	}
	if b.SequenceName != "encoded_exfil" {
		t.Errorf("SequenceName: want 'encoded_exfil', got %q", b.SequenceName)
	}
}

func TestMatchSequences_EscalatingAccess(t *testing.T) {
	bundle := bundleWithPath(true, false)
	history := []SessionHistoryEntry{
		historyEntry(time.Now().Add(-1*time.Minute), false, true, "cat /etc/passwd"),
		historyEntry(time.Now().Add(-30*time.Second), false, true, "ls /etc"),
	}
	b := callBehavioral(bundle, "cat", history, 0, 0, "", 0, 0)
	if b.SequenceRisk < 0.59 {
		t.Errorf("SequenceRisk: want ~0.60 for escalating_access, got %.2f", b.SequenceRisk)
	}
	if b.SequenceName != "escalating_access" {
		t.Errorf("SequenceName: want 'escalating_access', got %q", b.SequenceName)
	}
}

func TestMatchSequences_NoMatch(t *testing.T) {
	bundle := &SignalBundle{}
	history := []SessionHistoryEntry{
		historyEntry(time.Now().Add(-10*time.Second), false, false, "git status"),
	}
	b := callBehavioral(bundle, "npm", history, 0, 0, "", 0, 0)
	if b.SequenceRisk > 0.01 {
		t.Errorf("SequenceRisk: want 0 for benign sequence, got %.2f", b.SequenceRisk)
	}
}

// ── Composite score ───────────────────────────────────────────────────────

func TestCompositeScore_RetryAfterDeny_Dominates(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "rm", nil, 0, 30*time.Second, "rm", 0, 0)
	// RetryAfterDeny contributes 0.6 to the score
	if b.Score < 0.55 {
		t.Errorf("Score: want >= 0.55 when RetryAfterDeny=true, got %.2f", b.Score)
	}
}

func TestCompositeScore_RateBurst(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 70, 0, "", 0, 0)
	// RateBurst=0.80 * 0.3 = 0.24
	if b.Score < 0.20 || b.Score > 0.30 {
		t.Errorf("Score: want ~0.24 for rate burst only, got %.2f", b.Score)
	}
}

func TestCompositeScore_Capped(t *testing.T) {
	// All signals maxed out
	b := callBehavioral(&SignalBundle{}, "rm", nil, 70, 30*time.Second, "rm", 0.8, 1.0)
	if b.Score > 1.0 {
		t.Errorf("Score: must be capped at 1.0, got %.2f", b.Score)
	}
}

// ── BaselineEstablished propagation ──────────────────────────────────────

func TestBaselineEstablished_FieldSettable(t *testing.T) {
	b := callBehavioral(&SignalBundle{}, "", nil, 0, 0, "", 0, 0)
	// Initially false from ComputeBehavioral (engine sets it separately)
	if b.BaselineEstablished {
		t.Error("BaselineEstablished: want false from ComputeBehavioral (set externally by engine)")
	}
	// Engine sets it explicitly:
	b.BaselineEstablished = true
	if !b.BaselineEstablished {
		t.Error("BaselineEstablished: field must be settable after ComputeBehavioral")
	}
}
