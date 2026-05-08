package session

import (
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Registry manages active shim sessions.
type Registry struct {
	sessions sync.Map
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(shimID, agentID, toolName string) *SessionState {
	sessionID := generateSessionID()

	state := &SessionState{
		AgentID:     agentID,
		ShimID:      shimID,
		ToolName:    toolName,
		SessionID:   sessionID,
		StartedAt:   time.Now(),
		RecentCalls: NewRingBuffer(),
	}

	if old, loaded := r.sessions.LoadAndDelete(shimID); loaded {
		prev := old.(*SessionState)
		slog.Warn("replacing existing session", "shim_id", shimID, "old_session", prev.SessionID, "new_session", sessionID)
	}

	r.sessions.Store(shimID, state)
	return state
}

func (r *Registry) Get(shimID string) (*SessionState, bool) {
	val, ok := r.sessions.Load(shimID)
	if !ok {
		return nil, false
	}
	return val.(*SessionState), true
}

func (r *Registry) Deregister(shimID string) {
	r.sessions.Delete(shimID)
}

func (r *Registry) Count() int {
	count := 0
	r.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func generateSessionID() string {
	return uuid.New().String()
}
