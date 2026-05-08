package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// BroadcastFunc is a function that broadcasts a message to all WebSocket clients.
type BroadcastFunc func(msg []byte)

// PendingApproval represents a tool call awaiting human decision.
type PendingApproval struct {
	ID          string
	RequestID   string
	AgentID     string
	Tool        string
	ArgsSummary string
	RiskScore   float64
	Response    chan ApprovalResponse
	Deadline    time.Time
	CreatedAt   time.Time
}

// ApprovalResponse holds the human operator's decision.
type ApprovalResponse struct {
	Action string // "approve" or "deny"
	Reason string
}

// Gate manages pending human approval requests.
type Gate struct {
	pending   sync.Map
	broadcast BroadcastFunc
	timeout   time.Duration
	logger    *slog.Logger
}

// NewGate creates a new approval Gate.
func NewGate(broadcast BroadcastFunc, timeout time.Duration, logger *slog.Logger) *Gate {
	return &Gate{
		broadcast: broadcast,
		timeout:   timeout,
		logger:    logger,
	}
}

// Escalate pauses execution and waits for a human response.
// It broadcasts the approval request to the dashboard via WebSocket and blocks
// until approved, denied, timed out, or the context is cancelled.
func (g *Gate) Escalate(ctx context.Context, req *PendingApproval) (*ApprovalResponse, error) {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	req.Deadline = req.CreatedAt.Add(g.timeout)
	req.Response = make(chan ApprovalResponse, 1)

	g.pending.Store(req.ID, req)
	defer g.pending.Delete(req.ID)

	g.broadcastRequest(req)

	g.logger.Info("approval escalated",
		"approval_id", req.ID,
		"tool", req.Tool,
		"risk_score", req.RiskScore,
		"deadline", req.Deadline.Format(time.RFC3339),
	)

	timer := time.NewTimer(time.Until(req.Deadline))
	defer timer.Stop()

	select {
	case resp := <-req.Response:
		g.logger.Info("approval resolved",
			"approval_id", req.ID,
			"action", resp.Action,
			"reason", resp.Reason,
		)
		return &resp, nil
	case <-timer.C:
		resp := ApprovalResponse{Action: "deny", Reason: "approval timed out"}
		g.logger.Warn("approval timed out", "approval_id", req.ID)
		return &resp, nil
	case <-ctx.Done():
		resp := ApprovalResponse{Action: "deny", Reason: "cancelled"}
		g.logger.Warn("approval cancelled", "approval_id", req.ID)
		return &resp, nil
	}
}

// Resolve is called when the dashboard sends an approve/deny decision.
func (g *Gate) Resolve(approvalID string, action string, reason string) error {
	val, ok := g.pending.Load(approvalID)
	if !ok {
		return fmt.Errorf("unknown approval ID: %s", approvalID)
	}

	pa := val.(*PendingApproval)

	if action != "approve" && action != "deny" {
		return errors.New("action must be 'approve' or 'deny'")
	}

	select {
	case pa.Response <- ApprovalResponse{Action: action, Reason: reason}:
	default:
		return errors.New("approval already resolved")
	}

	g.broadcastResolved(approvalID, action, reason)
	return nil
}

// PendingCount returns the number of pending approvals.
func (g *Gate) PendingCount() int {
	count := 0
	g.pending.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func (g *Gate) broadcastResolved(approvalID string, action string, reason string) {
	msg := map[string]any{
		"type": "approval_resolved",
		"data": map[string]any{
			"approval_id": approvalID,
			"action":      action,
			"reason":      reason,
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		g.logger.Error("failed to marshal approval_resolved", "error", err)
		return
	}
	if g.broadcast != nil {
		g.broadcast(data)
	}
}

func (g *Gate) broadcastRequest(req *PendingApproval) {
	msg := map[string]any{
		"type": "approval_request",
		"data": map[string]any{
			"id":           req.ID,
			"request_id":   req.RequestID,
			"agent_id":     req.AgentID,
			"tool":         req.Tool,
			"args_summary": req.ArgsSummary,
			"risk_score":   req.RiskScore,
			"deadline":     req.Deadline.Format(time.RFC3339),
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		g.logger.Error("failed to marshal approval request", "error", err)
		return
	}
	if g.broadcast != nil {
		g.broadcast(data)
	}
}
