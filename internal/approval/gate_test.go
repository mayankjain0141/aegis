package approval_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/approval"
)

func newTestGate(timeout time.Duration) (*approval.Gate, *[][]byte) {
	var mu sync.Mutex
	var messages [][]byte
	broadcast := func(msg []byte) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]byte, len(msg))
		copy(cp, msg)
		messages = append(messages, cp)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	gate := approval.NewGate(broadcast, timeout, logger)
	return gate, &messages
}

func TestApproval_Approved_ReturnsApprove(t *testing.T) {
	gate, _ := newTestGate(5 * time.Second)

	var resp *approval.ApprovalResponse
	var escalateErr error
	done := make(chan struct{})

	pa := &approval.PendingApproval{
		ID:          "test-1",
		RequestID:   "req-1",
		AgentID:     "agent-1",
		Tool:        "file_write",
		ArgsSummary: "/etc/hosts",
		RiskScore:   0.8,
	}

	go func() {
		resp, escalateErr = gate.Escalate(context.Background(), pa)
		close(done)
	}()

	// Wait for pending to register
	deadline := time.Now().Add(2 * time.Second)
	for gate.PendingCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	err := gate.Resolve("test-1", "approve", "looks safe")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	<-done
	if escalateErr != nil {
		t.Fatalf("escalate error: %v", escalateErr)
	}
	if resp.Action != "approve" {
		t.Fatalf("expected approve, got %q", resp.Action)
	}
	if resp.Reason != "looks safe" {
		t.Fatalf("expected reason 'looks safe', got %q", resp.Reason)
	}
}

func TestApproval_Denied_ReturnsDeny(t *testing.T) {
	gate, _ := newTestGate(5 * time.Second)

	var resp *approval.ApprovalResponse
	done := make(chan struct{})

	pa := &approval.PendingApproval{
		ID:        "test-2",
		RequestID: "req-2",
		AgentID:   "agent-1",
		Tool:      "shell_exec",
		RiskScore: 0.9,
	}

	go func() {
		resp, _ = gate.Escalate(context.Background(), pa)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for gate.PendingCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	err := gate.Resolve("test-2", "deny", "too risky")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	<-done
	if resp.Action != "deny" {
		t.Fatalf("expected deny, got %q", resp.Action)
	}
	if resp.Reason != "too risky" {
		t.Fatalf("expected reason 'too risky', got %q", resp.Reason)
	}
}

func TestApproval_Timeout_AutoDenies(t *testing.T) {
	gate, _ := newTestGate(50 * time.Millisecond)

	pa := &approval.PendingApproval{
		ID:        "test-3",
		RequestID: "req-3",
		AgentID:   "agent-1",
		Tool:      "file_delete",
		RiskScore: 0.95,
	}

	resp, err := gate.Escalate(context.Background(), pa)
	if err != nil {
		t.Fatalf("escalate error: %v", err)
	}
	if resp.Action != "deny" {
		t.Fatalf("expected deny on timeout, got %q", resp.Action)
	}
	if resp.Reason != "approval timed out" {
		t.Fatalf("expected 'approval timed out', got %q", resp.Reason)
	}
}

func TestApproval_ContextCancelled_Denies(t *testing.T) {
	gate, _ := newTestGate(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	pa := &approval.PendingApproval{
		ID:        "test-4",
		RequestID: "req-4",
		AgentID:   "agent-1",
		Tool:      "file_delete",
		RiskScore: 0.95,
	}

	var resp *approval.ApprovalResponse
	done := make(chan struct{})
	go func() {
		resp, _ = gate.Escalate(ctx, pa)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for gate.PendingCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-done

	if resp.Action != "deny" {
		t.Fatalf("expected deny on cancel, got %q", resp.Action)
	}
	if resp.Reason != "cancelled" {
		t.Fatalf("expected 'cancelled', got %q", resp.Reason)
	}
}

func TestApproval_Resolve_UnknownID_ReturnsError(t *testing.T) {
	gate, _ := newTestGate(5 * time.Second)

	err := gate.Resolve("nonexistent-id", "approve", "")
	if err == nil {
		t.Fatal("expected error for unknown approval ID")
	}
	if err.Error() != "unknown approval ID: nonexistent-id" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApproval_PendingCount(t *testing.T) {
	gate, _ := newTestGate(5 * time.Second)

	if gate.PendingCount() != 0 {
		t.Fatalf("expected 0 pending, got %d", gate.PendingCount())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		gate.Escalate(ctx, &approval.PendingApproval{
			ID: "count-1", RequestID: "r1", Tool: "a",
		})
		close(done1)
	}()
	go func() {
		gate.Escalate(ctx, &approval.PendingApproval{
			ID: "count-2", RequestID: "r2", Tool: "b",
		})
		close(done2)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for gate.PendingCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if gate.PendingCount() != 2 {
		t.Fatalf("expected 2 pending, got %d", gate.PendingCount())
	}

	cancel()
	<-done1
	<-done2

	// After cancellation, pending map should be cleaned up
	deadline = time.Now().Add(time.Second)
	for gate.PendingCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if gate.PendingCount() != 0 {
		t.Fatalf("expected 0 pending after cancel, got %d", gate.PendingCount())
	}
}

func TestApproval_BroadcastFormat(t *testing.T) {
	gate, messages := newTestGate(50 * time.Millisecond)

	pa := &approval.PendingApproval{
		ID:          "bc-1",
		RequestID:   "req-bc",
		AgentID:     "agent-bc",
		Tool:        "file_delete",
		ArgsSummary: "/tmp/important",
		RiskScore:   0.8,
	}

	// Will timeout — that's fine, we just want to check broadcast
	gate.Escalate(context.Background(), pa)

	if len(*messages) == 0 {
		t.Fatal("expected broadcast message")
	}

	var msg struct {
		Type string `json:"type"`
		Data struct {
			ID          string  `json:"id"`
			RequestID   string  `json:"request_id"`
			AgentID     string  `json:"agent_id"`
			Tool        string  `json:"tool"`
			ArgsSummary string  `json:"args_summary"`
			RiskScore   float64 `json:"risk_score"`
			Deadline    string  `json:"deadline"`
		} `json:"data"`
	}
	if err := json.Unmarshal((*messages)[0], &msg); err != nil {
		t.Fatalf("unmarshal broadcast: %v", err)
	}

	if msg.Type != "approval_request" {
		t.Fatalf("expected type 'approval_request', got %q", msg.Type)
	}
	if msg.Data.ID != "bc-1" {
		t.Fatalf("expected id 'bc-1', got %q", msg.Data.ID)
	}
	if msg.Data.Tool != "file_delete" {
		t.Fatalf("expected tool 'file_delete', got %q", msg.Data.Tool)
	}
	if msg.Data.RiskScore != 0.8 {
		t.Fatalf("expected risk_score 0.8, got %f", msg.Data.RiskScore)
	}
}
