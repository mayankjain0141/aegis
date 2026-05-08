package policy

import "context"

// Action represents the outcome of a policy evaluation.
type Action string

const (
	ActionAllow         Action = "allow"
	ActionDeny          Action = "deny"
	ActionEscalateHuman Action = "escalate_human"
	ActionThrottle      Action = "throttle"
)

// PolicyDecision is the result of evaluating a tool call request.
type PolicyDecision struct {
	Action        Action
	PolicyName    string // which rule matched
	PolicyVersion string // version of the policy file
	Severity      string // "low", "medium", "high", "critical"
	Reason        string // human-readable explanation
}

// ToolCallRequest represents an incoming tool call to be evaluated.
type ToolCallRequest struct {
	AgentID    string
	Tool       string
	Arguments  string // serialized JSON of tool arguments
	RequestID  string
	SessionCtx *SessionContext
}

// SessionContext provides session-level context for policy evaluation.
type SessionContext struct {
	CallsLastMinute int
	CallsLastHour   int
	RecentTools     []string
	SessionStarted  string // ISO 8601
}

// PolicyEvaluator evaluates a tool call request and returns a decision.
// Returns nil decision if this evaluator has no opinion (pass to next in chain).
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req *ToolCallRequest) (*PolicyDecision, error)
}

// EvaluatorChain evaluates in order, returns first non-nil decision.
// If all return nil, returns default-deny.
type EvaluatorChain []PolicyEvaluator
