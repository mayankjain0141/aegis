package trace

import "time"

// TraceEvent represents a single tool call trace record.
type TraceEvent struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	RequestID     string    `json:"request_id"`
	AgentID       string    `json:"agent_id"`
	Timestamp     time.Time `json:"timestamp"`
	Tool          string    `json:"tool"`
	ArgsHash      string    `json:"args_hash"`
	ArgsSummary   string    `json:"args_summary"`
	RiskScore     float64   `json:"risk_score"`
	Decision      string    `json:"decision"`
	PolicyID      string    `json:"policy_id,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	Mode          string    `json:"mode"` // "enforce" or "audit"
	LatencyMs     int       `json:"latency_ms"`
	ErrorCode     *int      `json:"error_code,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// Collector is the interface for emitting trace events.
type Collector interface {
	Emit(event *TraceEvent)
	Flush() error
	Close() error
}
