package session

import (
	"testing"
	"time"
)

func TestRingBuffer_Push(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(CallSummary{Timestamp: time.Now(), Tool: "shell", RiskScore: 0.5, Decision: "allow"})
	rb.Push(CallSummary{Timestamp: time.Now(), Tool: "file_write", RiskScore: 0.8, Decision: "allow"})

	if rb.count != 2 {
		t.Errorf("count = %d, want 2", rb.count)
	}
}

func TestRingBuffer_Push_Wraps(t *testing.T) {
	rb := NewRingBuffer()
	for i := 0; i < 300; i++ {
		rb.Push(CallSummary{Timestamp: time.Now(), Tool: "tool", RiskScore: 0.1})
	}
	if rb.count != 256 {
		t.Errorf("count = %d, want 256 (max ring size)", rb.count)
	}
}

func TestRingBuffer_CallsInWindow(t *testing.T) {
	rb := NewRingBuffer()

	old := time.Now().Add(-2 * time.Minute)
	rb.Push(CallSummary{Timestamp: old, Tool: "old_tool"})

	recent := time.Now().Add(-10 * time.Second)
	rb.Push(CallSummary{Timestamp: recent, Tool: "recent_tool"})

	now := time.Now()
	rb.Push(CallSummary{Timestamp: now, Tool: "now_tool"})

	count := rb.CallsInWindow(time.Minute)
	if count != 2 {
		t.Errorf("CallsInWindow(1m) = %d, want 2", count)
	}

	count = rb.CallsInWindow(time.Hour)
	if count != 3 {
		t.Errorf("CallsInWindow(1h) = %d, want 3", count)
	}
}

func TestRecordCall(t *testing.T) {
	state := &SessionState{
		StartedAt:   time.Now(),
		RecentCalls: NewRingBuffer(),
	}

	state.RecordCall("shell_exec", 0.7, "allow")
	state.RecordCall("file_write", 0.9, "deny")

	if state.CallCount.Load() != 2 {
		t.Errorf("CallCount = %d, want 2", state.CallCount.Load())
	}

	lastCall := state.LastCallAt.Load()
	if lastCall == nil {
		t.Fatal("LastCallAt should be set")
	}
	if _, ok := lastCall.(time.Time); !ok {
		t.Fatal("LastCallAt should be time.Time")
	}
}

func TestGetContext(t *testing.T) {
	state := &SessionState{
		StartedAt:   time.Now().Add(-5 * time.Minute),
		RecentCalls: NewRingBuffer(),
	}

	state.RecordCall("tool_a", 0.1, "allow")
	state.RecordCall("tool_b", 0.2, "allow")
	state.RecordCall("tool_c", 0.3, "deny")

	ctx := state.GetContext()
	if ctx.CallsLastMinute != 3 {
		t.Errorf("CallsLastMinute = %d, want 3", ctx.CallsLastMinute)
	}
	if ctx.CallsLastHour != 3 {
		t.Errorf("CallsLastHour = %d, want 3", ctx.CallsLastHour)
	}
	if len(ctx.RecentTools) != 3 {
		t.Errorf("len(RecentTools) = %d, want 3", len(ctx.RecentTools))
	}
	if ctx.RecentTools[0] != "tool_c" {
		t.Errorf("RecentTools[0] = %q, want %q (most recent first)", ctx.RecentTools[0], "tool_c")
	}
	if ctx.SessionStarted.IsZero() {
		t.Error("SessionStarted should not be zero")
	}
}
