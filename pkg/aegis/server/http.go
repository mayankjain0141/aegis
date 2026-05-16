// Package server exposes the aegis engine over a local HTTP/Unix-socket API
// for use by Python SDK adapters (OpenAI, Anthropic, LangGraph).
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/mayjain/aegis/pkg/aegis"
)

const DefaultSocketPath = "/tmp/aegis-engine.sock"

// Server wraps an Engine and serves it over HTTP on a Unix socket.
type Server struct {
	engine     *aegis.Engine
	socketPath string
	httpServer *http.Server
}

// New creates a server using the default socket path.
func New(engine *aegis.Engine, socketPath string) *Server {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Server{engine: engine, socketPath: socketPath}
}

// Start begins listening on the Unix socket. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	os.Remove(s.socketPath) //nolint:errcheck

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	os.Chmod(s.socketPath, 0o600) //nolint:errcheck

	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", s.handleEvaluate)
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		s.httpServer.Close()
	}()

	return s.httpServer.Serve(ln)
}

type evaluateRequest struct {
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	CWD       string         `json:"cwd"`
	AgentID   string         `json:"agent_id"`
}

type evaluateResponse struct {
	Action         string   `json:"action"`
	Rule           string   `json:"rule"`
	Severity       string   `json:"severity,omitempty"`
	Confidence     float64  `json:"confidence"`
	Evidence       []string `json:"evidence,omitempty"`
	CompositeScore float64  `json:"composite_score"`
	Phase          int      `json:"phase"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req evaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	decision := s.engine.Evaluate(r.Context(), &aegis.Request{
		Tool:      req.Tool,
		Arguments: req.Args,
		CWD:       req.CWD,
		AgentID:   req.AgentID,
	})

	resp := evaluateResponse{
		Action:         string(decision.Action),
		Rule:           decision.Rule,
		Severity:       decision.Severity,
		Confidence:     decision.Confidence,
		Evidence:       decision.Evidence,
		CompositeScore: decision.CompositeScore,
		Phase:          decision.Phase,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}
