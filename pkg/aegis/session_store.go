package aegis

import (
	"sync"

	"github.com/mayjain/aegis/pkg/aegis/session"
)

// SessionStore manages per-agent session state.
type SessionStore interface {
	GetOrCreate(agentID string) *session.State
}

type inMemorySessionStore struct {
	sessions map[string]*session.State
	mu       sync.Mutex
}

func newInMemorySessionStore() SessionStore {
	return &inMemorySessionStore{sessions: make(map[string]*session.State)}
}

func (s *inMemorySessionStore) GetOrCreate(agentID string) *session.State {
	if agentID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[agentID]
	if !ok {
		st = session.New(agentID)
		s.sessions[agentID] = st
	}
	return st
}
