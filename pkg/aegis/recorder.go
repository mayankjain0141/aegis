package aegis

import (
	"strings"
	"time"

	"github.com/mayjain/aegis/pkg/aegis/session"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// DecisionRecorder records a tool call decision into session state.
type DecisionRecorder interface {
	Record(req *Request, d *Decision, composite float64, bundle *signals.SignalBundle)
}

type sessionRecorder struct {
	sessions SessionStore
}

func newSessionRecorder(store SessionStore) DecisionRecorder {
	return &sessionRecorder{sessions: store}
}

func (r *sessionRecorder) Record(req *Request, d *Decision, composite float64, bundle *signals.SignalBundle) {
	if req.AgentID == "" {
		return
	}
	s := r.sessions.GetOrCreate(req.AgentID)
	if s == nil {
		return
	}

	argSummary := req.Tool
	if cmd, ok := req.Arguments["command"]; ok {
		if cs, ok := cmd.(string); ok {
			if len(cs) > 80 {
				cs = cs[:80]
			}
			argSummary = cs
		}
	}
	primaryVerb := ""
	if cmd, ok := req.Arguments["command"]; ok {
		if cmdStr, ok := cmd.(string); ok && cmdStr != "" {
			fields := strings.Fields(cmdStr)
			if len(fields) > 0 {
				primaryVerb = fields[0]
			}
		}
	}
	tc := session.ToolCall{
		Time:           time.Now(),
		Tool:           req.Tool,
		ArgSummary:     argSummary,
		PrimaryVerb:    primaryVerb,
		Decision:       string(d.Action),
		Rule:           d.Rule,
		CompositeScore: composite,
	}
	if bundle != nil {
		tc.PathSensitive = bundle.Path.HasSensitive
		tc.PathCritical = bundle.Path.HasCritical
		tc.NetworkWrite = bundle.Network.HasDataFlag || bundle.Network.Score > 0.5
	}
	s.Record(tc)
}
