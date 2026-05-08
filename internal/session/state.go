package session

import (
	"sync"
	"sync/atomic"
	"time"
)

// SessionState holds per-agent session context used by risk scoring and rate limiting.
type SessionState struct {
	AgentID     string
	ShimID      string
	ToolName    string
	SessionID   string
	StartedAt   time.Time
	CallCount   atomic.Int64
	LastCallAt  atomic.Value // time.Time
	RecentCalls *RingBuffer
	mu          sync.Mutex
}

// CallSummary is a single entry in the ring buffer.
type CallSummary struct {
	Timestamp time.Time
	Tool      string
	RiskScore float64
	Decision  string
}

// RingBuffer is a fixed-size circular buffer of CallSummary entries.
type RingBuffer struct {
	entries [256]CallSummary
	head    int
	count   int
	mu      sync.Mutex
}

// SessionContext is passed to policy evaluators and risk scorers.
type SessionContext struct {
	CallsLastMinute int
	CallsLastHour   int
	RecentTools     []string
	SessionStarted  time.Time
}

func NewRingBuffer() *RingBuffer {
	return &RingBuffer{}
}

func (rb *RingBuffer) Push(cs CallSummary) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.entries[rb.head] = cs
	rb.head = (rb.head + 1) % len(rb.entries)
	if rb.count < len(rb.entries) {
		rb.count++
	}
}

// CallsInWindow counts entries within the given time window from now.
func (rb *RingBuffer) CallsInWindow(window time.Duration) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	cutoff := time.Now().Add(-window)
	count := 0
	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + len(rb.entries)) % len(rb.entries)
		if rb.entries[idx].Timestamp.Before(cutoff) {
			break
		}
		count++
	}
	return count
}

// recentTools returns the tool names from the last n entries (most recent first).
func (rb *RingBuffer) recentTools(n int) []string {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if n > rb.count {
		n = rb.count
	}
	tools := make([]string, 0, n)
	for i := 0; i < n; i++ {
		idx := (rb.head - 1 - i + len(rb.entries)) % len(rb.entries)
		tools = append(tools, rb.entries[idx].Tool)
	}
	return tools
}

func (s *SessionState) RecordCall(tool string, riskScore float64, decision string) {
	s.CallCount.Add(1)
	s.LastCallAt.Store(time.Now())
	s.RecentCalls.Push(CallSummary{
		Timestamp: time.Now(),
		Tool:      tool,
		RiskScore: riskScore,
		Decision:  decision,
	})
}

func (s *SessionState) GetContext() *SessionContext {
	return &SessionContext{
		CallsLastMinute: s.RecentCalls.CallsInWindow(time.Minute),
		CallsLastHour:   s.RecentCalls.CallsInWindow(time.Hour),
		RecentTools:     s.RecentCalls.recentTools(10),
		SessionStarted:  s.StartedAt,
	}
}
