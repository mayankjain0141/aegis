package session

import (
	"math"
	"testing"
	"time"
)

// recordAt injects a ToolCall with explicit time so tests are time-independent.
func recordAt(s *State, t time.Time, tool, verb, decision, rule string, score float64) {
	s.Record(ToolCall{
		Time:           t,
		Tool:           tool,
		PrimaryVerb:    verb,
		Decision:       decision,
		Rule:           rule,
		CompositeScore: score,
	})
}

func TestWindowCounting_CallsLastMinute(t *testing.T) {
	s := New("agent-1")
	now := time.Now()

	// Record in chronological order (oldest first) — ring buffer walks newest-inserted first,
	// so time-ordering of insertions must match wall-clock ordering for break-early to work.
	for i := 2; i >= 0; i-- {
		recordAt(s, now.Add(-90*time.Second-time.Duration(i)*time.Second), "Shell", "", "allow", "", 0.1)
	}
	for i := 4; i >= 0; i-- {
		recordAt(s, now.Add(-time.Duration(i)*10*time.Second), "Shell", "", "allow", "", 0.1)
	}

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.CallsLastMinute != 5 {
		t.Errorf("CallsLastMinute: want 5, got %d", sig.CallsLastMinute)
	}
	if sig.CallsLast5Minutes != 8 {
		t.Errorf("CallsLast5Minutes: want 8, got %d", sig.CallsLast5Minutes)
	}
}

func TestWindowCounting_EmptySession(t *testing.T) {
	s := New("agent-empty")
	sig := s.Signal(ToolCall{Time: time.Now(), Tool: "Shell"})
	if sig.CallsLastMinute != 0 {
		t.Errorf("CallsLastMinute: want 0, got %d", sig.CallsLastMinute)
	}
	if sig.CallsLast5Minutes != 0 {
		t.Errorf("CallsLast5Minutes: want 0, got %d", sig.CallsLast5Minutes)
	}
	if sig.RecentDenyCount != 0 {
		t.Errorf("RecentDenyCount: want 0, got %d", sig.RecentDenyCount)
	}
}

func TestDenyTracking_VerbAndRule(t *testing.T) {
	s := New("agent-deny")
	now := time.Now()

	// chronological order: older first
	recordAt(s, now.Add(-30*time.Second), "Shell", "rm", "deny", "critical_path_destruction", 0.9)
	recordAt(s, now.Add(-20*time.Second), "Shell", "", "allow", "benign_git_ops", 0.1) // allow after deny

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})

	if sig.LastDenyVerb != "rm" {
		t.Errorf("LastDenyVerb: want 'rm', got %q", sig.LastDenyVerb)
	}
	if sig.LastDenyRule != "critical_path_destruction" {
		t.Errorf("LastDenyRule: want 'critical_path_destruction', got %q", sig.LastDenyRule)
	}
	if sig.RecentDenyCount != 1 {
		t.Errorf("RecentDenyCount: want 1, got %d", sig.RecentDenyCount)
	}
	if sig.LastDenyTimeAgo < 25*time.Second || sig.LastDenyTimeAgo > 35*time.Second {
		t.Errorf("LastDenyTimeAgo: want ~30s, got %v", sig.LastDenyTimeAgo)
	}
}

// Regression test: before the bug fix, lastDenyVerb was always "" because
// DenyEvent.Verb was never populated from ToolCall.PrimaryVerb.
func TestDenyTracking_EmptyVerbNocrash(t *testing.T) {
	s := New("agent-empty-verb")
	now := time.Now()

	// Record deny without a primary verb — should not panic
	s.Record(ToolCall{Time: now.Add(-10 * time.Second), Tool: "Shell", Decision: "deny", Rule: "system_control"})

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.LastDenyVerb != "" {
		t.Errorf("LastDenyVerb: want '', got %q (should be empty when no PrimaryVerb set)", sig.LastDenyVerb)
	}
	if sig.RecentDenyCount != 1 {
		t.Errorf("RecentDenyCount: want 1, got %d", sig.RecentDenyCount)
	}
}

func TestDenyTracking_StaleDenieExcluded(t *testing.T) {
	s := New("agent-stale")
	now := time.Now()

	// Record in chronological order (oldest first)
	recordAt(s, now.Add(-6*time.Minute), "Shell", "shutdown", "deny", "r3", 0.9) // stale
	recordAt(s, now.Add(-2*time.Minute), "Shell", "nc", "deny", "r2", 0.9)
	recordAt(s, now.Add(-1*time.Minute), "Shell", "rm", "deny", "r1", 0.9)

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.RecentDenyCount != 2 {
		t.Errorf("RecentDenyCount: want 2, got %d (stale deny should be excluded)", sig.RecentDenyCount)
	}
}

func TestBaselineEstablished_FreshSession(t *testing.T) {
	s := New("agent-fresh")
	sig := s.Signal(ToolCall{Time: time.Now(), Tool: "Shell"})
	if sig.BaselineEstablished {
		t.Error("BaselineEstablished: want false for fresh session, got true")
	}
}

func TestBaselineEstablished_After5Minutes(t *testing.T) {
	s := New("agent-old")
	s.StartTime = time.Now().Add(-6 * time.Minute)
	now := time.Now()

	for i := 0; i < 10; i++ {
		recordAt(s, now.Add(-time.Duration(i)*30*time.Second), "Shell", "", "allow", "", 0.1)
	}

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if !sig.BaselineEstablished {
		t.Error("BaselineEstablished: want true after 5+ minutes of traffic, got false")
	}
}

func TestBaselineEstablished_Before5Minutes(t *testing.T) {
	s := New("agent-young")
	s.StartTime = time.Now().Add(-4 * time.Minute)
	now := time.Now()

	for i := 0; i < 5; i++ {
		recordAt(s, now.Add(-time.Duration(i)*30*time.Second), "Shell", "", "allow", "", 0.1)
	}

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.BaselineEstablished {
		t.Error("BaselineEstablished: want false before 5 minutes, got true")
	}
}

func TestRingBuffer_Wraparound(t *testing.T) {
	s := New("agent-wrap")
	now := time.Now()

	// Record more than the ring buffer capacity (100)
	for i := 0; i < 105; i++ {
		recordAt(s, now.Add(time.Duration(i)*time.Millisecond), "Shell", "", "allow", "", 0.1)
	}

	// Should not panic; ring buffer wraps correctly
	recent := s.RecentCalls(10)
	if len(recent) != 10 {
		t.Errorf("RecentCalls(10): want 10, got %d", len(recent))
	}
}

func TestRecentCalls_Ordering(t *testing.T) {
	s := New("agent-order")
	now := time.Now()

	t1 := now.Add(-10 * time.Second)
	t2 := now.Add(-5 * time.Second)
	t3 := now.Add(-1 * time.Second)

	// Record in chronological order (oldest first) for correct break-early window logic
	recordAt(s, t1, "Shell", "", "allow", "", 0.1) // oldest
	recordAt(s, t2, "Read", "", "allow", "", 0.1)
	recordAt(s, t3, "Write", "", "allow", "", 0.1) // newest

	recent := s.RecentCalls(3)
	if len(recent) != 3 {
		t.Fatalf("RecentCalls(3): want 3, got %d", len(recent))
	}
	// RecentCalls returns chronological order (oldest first, newest last)
	if recent[0].Tool != "Shell" {
		t.Errorf("recent[0]: want Shell (oldest, recorded at T-10s), got %s", recent[0].Tool)
	}
	if recent[2].Tool != "Write" {
		t.Errorf("recent[2]: want Write (newest, recorded at T-1s), got %s", recent[2].Tool)
	}
}

func TestRiskTrend_Increasing(t *testing.T) {
	s := New("agent-trend-up")
	now := time.Now()

	// Chronological: i=0 is oldest (score=0.1, time=-10s), i=9 newest (score=1.0, time=-1s)
	for i := 0; i < 10; i++ {
		score := float64(i+1) / 10.0 // 0.1, 0.2, ..., 1.0
		recordAt(s, now.Add(-time.Duration(10-i)*time.Second), "Shell", "", "allow", "", score)
	}

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.RiskTrend <= 0 {
		t.Errorf("RiskTrend: want > 0 for increasing scores, got %.4f", sig.RiskTrend)
	}
}

func TestRiskTrend_Stable(t *testing.T) {
	s := New("agent-stable")
	now := time.Now()

	for i := 0; i < 10; i++ {
		recordAt(s, now.Add(-time.Duration(10-i)*time.Second), "Shell", "", "allow", "", 0.5)
	}

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if math.Abs(sig.RiskTrend) > 0.01 {
		t.Errorf("RiskTrend: want ~0 for stable scores, got %.4f", sig.RiskTrend)
	}
}

func TestUniqueToolsUsed(t *testing.T) {
	s := New("agent-tools")
	now := time.Now()

	recordAt(s, now.Add(-3*time.Second), "Shell", "", "allow", "", 0)
	recordAt(s, now.Add(-2*time.Second), "Read", "", "allow", "", 0)
	recordAt(s, now.Add(-1*time.Second), "Write", "", "allow", "", 0)

	sig := s.Signal(ToolCall{Time: now, Tool: "Shell"})
	if sig.UniqueToolsUsed != 3 {
		t.Errorf("UniqueToolsUsed: want 3, got %d", sig.UniqueToolsUsed)
	}
}

func TestConcurrentAccess_NoRace(t *testing.T) {
	s := New("agent-concurrent")
	done := make(chan struct{})

	go func() {
		for i := 0; i < 50; i++ {
			s.Record(ToolCall{Time: time.Now(), Tool: "Shell", Decision: "allow"})
		}
		close(done)
	}()

	for i := 0; i < 20; i++ {
		s.Signal(ToolCall{Time: time.Now(), Tool: "Shell"})
	}
	<-done
}

