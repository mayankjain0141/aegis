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
