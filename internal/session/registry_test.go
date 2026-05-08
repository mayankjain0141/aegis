package session

import (
	"sync"
	"testing"
)

func TestRegister(t *testing.T) {
	r := NewRegistry()
	state := r.Register("shim1", "agent1", "tool1")

	if state.ShimID != "shim1" {
		t.Errorf("ShimID = %q, want %q", state.ShimID, "shim1")
	}
	if state.AgentID != "agent1" {
		t.Errorf("AgentID = %q, want %q", state.AgentID, "agent1")
	}
	if state.ToolName != "tool1" {
		t.Errorf("ToolName = %q, want %q", state.ToolName, "tool1")
	}
	if state.SessionID == "" {
		t.Error("SessionID should not be empty")
	}
	if state.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}
	if state.RecentCalls == nil {
		t.Error("RecentCalls should be initialized")
	}
}

func TestGet(t *testing.T) {
	r := NewRegistry()
	r.Register("shim1", "agent1", "tool1")

	got, ok := r.Get("shim1")
	if !ok {
		t.Fatal("expected to find shim1")
	}
	if got.AgentID != "agent1" {
		t.Errorf("AgentID = %q, want %q", got.AgentID, "agent1")
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent shim")
	}
}

func TestDeregister(t *testing.T) {
	r := NewRegistry()
	r.Register("shim1", "agent1", "tool1")

	r.Deregister("shim1")

	_, ok := r.Get("shim1")
	if ok {
		t.Error("shim1 should be deregistered")
	}
}

func TestDuplicateReplaces(t *testing.T) {
	r := NewRegistry()
	first := r.Register("shim1", "agent1", "tool1")
	second := r.Register("shim1", "agent2", "tool2")

	if first.SessionID == second.SessionID {
		t.Error("duplicate register should create a new session ID")
	}

	got, ok := r.Get("shim1")
	if !ok {
		t.Fatal("expected to find shim1")
	}
	if got.AgentID != "agent2" {
		t.Errorf("AgentID = %q, want %q (should be replaced)", got.AgentID, "agent2")
	}
}

func TestCount(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Errorf("Count() = %d, want 0", r.Count())
	}

	r.Register("shim1", "a1", "t1")
	r.Register("shim2", "a2", "t2")
	r.Register("shim3", "a3", "t3")

	if r.Count() != 3 {
		t.Errorf("Count() = %d, want 3", r.Count())
	}

	r.Deregister("shim2")
	if r.Count() != 2 {
		t.Errorf("Count() = %d, want 2", r.Count())
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			shimID := "shim_" + string(rune('A'+id%26))
			r.Register(shimID, "agent", "tool")
			r.Get(shimID)
			if id%3 == 0 {
				r.Deregister(shimID)
			}
		}(i)
	}
	wg.Wait()
}
