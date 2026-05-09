package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// OPAStep evaluates enriched requests against Rego policies.
// It uses PrepareForEval for fast per-request evaluation and supports
// atomic hot-reload of policies.
type OPAStep struct {
	query atomic.Pointer[rego.PreparedEvalQuery]
	mu    sync.Mutex
}

// NewOPAStep compiles the given Rego module and optional JSON data into a prepared query.
func NewOPAStep(module string, dataJSON []byte) (*OPAStep, error) {
	s := &OPAStep{}
	if err := s.compile(module, dataJSON); err != nil {
		return nil, err
	}
	return s, nil
}

// NewOPAStepFromFiles loads Rego policy and data from the filesystem.
func NewOPAStepFromFiles(regoPath, dataPath string) (*OPAStep, error) {
	module, err := os.ReadFile(regoPath)
	if err != nil {
		return nil, fmt.Errorf("read rego: %w", err)
	}
	var dataJSON []byte
	if dataPath != "" {
		dataJSON, err = os.ReadFile(dataPath)
		if err != nil {
			return nil, fmt.Errorf("read data: %w", err)
		}
	}
	return NewOPAStep(string(module), dataJSON)
}

func (s *OPAStep) Name() string { return "opa" }

// Reload compiles new policy and swaps it atomically.
// In-flight Evaluate calls continue using the old query until they return.
func (s *OPAStep) Reload(module string, dataJSON []byte) error {
	return s.compile(module, dataJSON)
}

// ReloadFromFiles reloads policy from filesystem paths.
func (s *OPAStep) ReloadFromFiles(regoPath, dataPath string) error {
	module, err := os.ReadFile(regoPath)
	if err != nil {
		return fmt.Errorf("reload read rego: %w", err)
	}
	var dataJSON []byte
	if dataPath != "" {
		dataJSON, err = os.ReadFile(dataPath)
		if err != nil {
			return fmt.Errorf("reload read data: %w", err)
		}
	}
	return s.compile(string(module), dataJSON)
}

func (s *OPAStep) compile(module string, dataJSON []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	opts := []func(*rego.Rego){
		rego.Query("data.aegis.decide"),
		rego.Module("aegis.rego", module),
	}

	if len(dataJSON) > 0 {
		store := inmem.NewFromReader(bytes.NewReader(dataJSON))
		opts = append(opts, rego.Store(store))
	}

	prepared, err := rego.New(opts...).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("opa compile: %w", err)
	}

	s.query.Store(&prepared)
	return nil
}

// Evaluate runs the Rego query against the enriched request.
// Returns nil if the result is undefined (no matching rule = no opinion).
func (s *OPAStep) Evaluate(ctx context.Context, req *EnrichedRequest) (*PolicyDecision, error) {
	q := s.query.Load()
	if q == nil {
		return nil, nil
	}

	input := toOPAInput(req)
	results, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("opa eval: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil // undefined = no opinion
	}

	val := results[0].Expressions[0].Value
	resultMap, ok := val.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	action := stringVal(resultMap, "action")
	if action == "" {
		return nil, nil
	}

	return &PolicyDecision{
		Action:   Action(action),
		Severity: stringVal(resultMap, "severity"),
		Reason:   stringVal(resultMap, "reason"),
	}, nil
}

func toOPAInput(req *EnrichedRequest) map[string]interface{} {
	commands := make([]map[string]interface{}, 0, len(req.Commands))
	for _, cmd := range req.Commands {
		args := cmd.Args
		if args == nil {
			args = []string{}
		}
		commands = append(commands, map[string]interface{}{
			"name": cmd.Name,
			"args": args,
		})
	}

	input := map[string]interface{}{
		"agent_id":    req.AgentID,
		"tool":        req.Tool,
		"commands":    commands,
		"paths":       nonNilSlice(req.Paths),
		"hosts":       nonNilSlice(req.Hosts),
		"risk_score":  req.RiskScore,
		"parse_error": errToJSON(req.ParseErr),
	}

	if req.SessionCtx != nil {
		input["session"] = map[string]interface{}{
			"calls_last_minute": req.SessionCtx.CallsLastMinute,
			"calls_last_hour":   req.SessionCtx.CallsLastHour,
			"recent_tools":      nonNilSlice(req.SessionCtx.RecentTools),
			"session_started":   req.SessionCtx.SessionStarted,
		}
	}

	return input
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func errToJSON(err error) interface{} {
	if err == nil {
		return nil
	}
	return err.Error()
}

func stringVal(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// DefaultRegoModule is a minimal inline policy for Phase 0 MVP.
// It blocks destructive commands on critical system paths.
const DefaultRegoModule = `package aegis

import rego.v1

decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	cmd.name == "rm"
	some path in input.paths
	critical_path(path)
	reason := sprintf("destructive command 'rm' on critical path: %s", [path])
}

decide := {"action": "escalate_human", "severity": "medium", "reason": reason} if {
	input.parse_error != null
	reason := sprintf("command could not be parsed: %s", [input.parse_error])
}

critical_path(path) if startswith(path, "/etc")
critical_path(path) if startswith(path, "/usr")
critical_path(path) if startswith(path, "/bin")
critical_path(path) if startswith(path, "/sbin")
critical_path(path) if startswith(path, "/boot")
critical_path(path) if path == "/"
`

// MarshalEnrichedRequest serializes an EnrichedRequest to JSON (for debugging/logging).
func MarshalEnrichedRequest(req *EnrichedRequest) ([]byte, error) {
	return json.Marshal(toOPAInput(req))
}
