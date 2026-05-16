// Package aegis is the V2 risk evaluation engine for agentic AI tool calls.
// It uses a three-phase cascade: static rules, behavioral analysis, and LLM intent.
// Phase 1 (this package) handles the static rule engine only.
package aegis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mayjain/aegis/internal/extract"
	"github.com/mayjain/aegis/pkg/aegis/bloom"
	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/session"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// Action mirrors rules.Action for the public API.
type Action = rules.Action

const (
	ActionAllow    = rules.ActionAllow
	ActionDeny     = rules.ActionDeny
	ActionEscalate = rules.ActionEscalate
	ActionThrottle = rules.ActionThrottle
)

// Request is a single tool call to evaluate.
type Request struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	CWD       string         `json:"cwd"`
	AgentID   string         `json:"agent_id,omitempty"` // for session tracking; optional
}

// Decision is the evaluation result.
type Decision struct {
	Action         Action   `json:"action"`
	Rule           string   `json:"rule"`
	Severity       string   `json:"severity,omitempty"`
	Confidence     float64  `json:"confidence"`
	Evidence       []string `json:"evidence,omitempty"`
	CompositeScore float64  `json:"composite_score"`
	Phase          int      `json:"phase"` // 0=fast_path, 1=static, 2=behavioral
}

// Engine is the V2 risk evaluation engine.
type Engine struct {
	rules     []rules.Rule
	bloom     *bloom.Filter
	extractor *extract.Extractor
	sessions  map[string]*session.State
	sessionMu sync.Mutex
}

// Option configures the Engine.
type Option func(*Engine)

// WithBenignCorpus pre-populates the bloom filter from a JSONL file.
func WithBenignCorpus(path string) Option {
	return func(e *Engine) {
		if err := e.loadBenignCorpus(path); err != nil {
			// Non-fatal: bloom filter just won't have fast-path hits
			fmt.Fprintf(os.Stderr, "aegis: bloom filter load warning: %v\n", err)
		}
	}
}

// WithRules replaces the default rule set.
func WithRules(r []rules.Rule) Option {
	return func(e *Engine) {
		e.rules = r
	}
}

// NewEngine creates an Engine with Phase 1 static rules.
// If no corpus path is provided via options, it tries to load from the default location.
func NewEngine(opts ...Option) (*Engine, error) {
	db, err := loadCommandDB()
	if err != nil {
		// Non-fatal: extractor works without DB (reduced accuracy)
		db = nil
	}

	e := &Engine{
		rules:     rules.Phase1Rules(),
		bloom:     bloom.New(1000, 0.01),
		extractor: extract.NewExtractor(db),
		sessions:  make(map[string]*session.State),
	}

	for _, opt := range opts {
		opt(e)
	}

	// Try default corpus locations for bloom filter
	if e.bloom.Len() == 0 {
		for _, candidate := range defaultCorpusPaths() {
			if _, err := os.Stat(candidate); err == nil {
				e.loadBenignCorpus(candidate) //nolint:errcheck
				break
			}
		}
	}

	return e, nil
}

// Evaluate runs the tool call through the engine and returns a decision.
func (e *Engine) Evaluate(ctx context.Context, req *Request) *Decision {
	argsJSON := marshalArgs(req.Arguments)

	// Fast path: bloom filter exact match
	key := bloom.CanonicalKey(req.Tool, req.Arguments)
	if e.bloom.Contains(key) {
		d := &Decision{Action: ActionAllow, Rule: "fast_path_allow", Confidence: 1.00, Phase: 0}
		e.recordCall(req, d, 0.0)
		return d
	}

	// Phase 1: static rule engine
	bundle := e.computeSignals(req.Tool, argsJSON, req.CWD)
	composite := signals.CompositeScore(bundle)

	rule, matched := rules.Evaluate(e.rules, bundle)
	var d1 *Decision
	if !matched {
		d1 = &Decision{Action: ActionDeny, Rule: "no_rule_matched", Severity: "medium", Confidence: 0.50, CompositeScore: composite, Phase: 1}
	} else {
		d1 = &Decision{Action: rule.Action, Rule: rule.Name, Severity: rule.Severity, Confidence: rule.Confidence, Evidence: buildEvidence(bundle), CompositeScore: composite, Phase: 1}
	}

	// High-confidence Phase 1 decisions are final
	if d1.Confidence >= 0.85 {
		e.recordCall(req, d1, composite)
		return d1
	}

	// Phase 2: behavioral analysis for low-confidence decisions
	sess := e.getOrCreateSession(req.AgentID)
	if sess != nil {
		sig := sess.Signal(session.ToolCall{Time: time.Now(), Tool: req.Tool})
		history := toHistoryEntries(sess.RecentCalls(20), bundle)
		primaryVerb := ""
		if len(bundle.Command.Verbs) > 0 {
			primaryVerb = bundle.Command.Verbs[0]
		}
		b2 := signals.ComputeBehavioral(
			bundle, primaryVerb, history,
			sig.CallsLastMinute,
			sig.LastDenyTimeAgo, "",
			sig.BaselineDeviation,
			sig.RiskTrend,
		)
		bBundle := rules.BehavioralBundle{Phase1: bundle, Phase2: b2}
		if p2rule, p2matched := rules.BehavioralEvaluate(bBundle); p2matched {
			d2 := &Decision{
				Action:         p2rule.Action,
				Rule:           p2rule.Name,
				Severity:       p2rule.Severity,
				Confidence:     p2rule.Confidence,
				CompositeScore: composite,
				Phase:          2,
			}
			e.recordCall(req, d2, composite)
			return d2
		}
	}

	e.recordCall(req, d1, composite)
	return d1
}

func (e *Engine) getOrCreateSession(agentID string) *session.State {
	if agentID == "" {
		return nil
	}
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	s, ok := e.sessions[agentID]
	if !ok {
		s = session.New(agentID)
		e.sessions[agentID] = s
	}
	return s
}

func (e *Engine) recordCall(req *Request, d *Decision, composite float64) {
	if req.AgentID == "" {
		return
	}
	s := e.getOrCreateSession(req.AgentID)
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
	s.Record(session.ToolCall{
		Tool:           req.Tool,
		ArgSummary:     argSummary,
		Decision:       string(d.Action),
		Rule:           d.Rule,
		CompositeScore: composite,
	})
}

func toHistoryEntries(calls []session.ToolCall, _ *signals.SignalBundle) []signals.SessionHistoryEntry {
	entries := make([]signals.SessionHistoryEntry, len(calls))
	for i, c := range calls {
		entries[i] = signals.SessionHistoryEntry{
			Tool:           c.Tool,
			ArgSummary:     c.ArgSummary,
			Decision:       c.Decision,
			Rule:           c.Rule,
			CompositeScore: c.CompositeScore,
		}
	}
	return entries
}

// EvaluateJSON is a convenience wrapper that accepts raw JSON arguments string.
func (e *Engine) EvaluateJSON(ctx context.Context, tool, argsJSON, cwd string) *Decision {
	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		args = map[string]any{}
	}
	return e.Evaluate(ctx, &Request{Tool: tool, Arguments: args, CWD: cwd})
}

func (e *Engine) computeSignals(tool, argsJSON, cwd string) *signals.SignalBundle {
	// Signal 1: tool classification
	toolClass := signals.ClassifyTool(tool)

	// Signal 2: command analysis (uses extractor for AST parsing)
	cmd := signals.AnalyzeCommand(tool, argsJSON, e.extractor)

	// Signal 3: path analysis — combine paths from shell extractor + direct args
	// Also detect @file patterns in curl/wget commands
	extraPaths := append([]string(nil), cmd.Paths...)
	for _, c := range cmd.Commands {
		if hasDataFile, filePath := signals.HasDataFilePattern(c.Args); hasDataFile && filePath != "" {
			extraPaths = append(extraPaths, filePath)
		}
	}
	pathSig := signals.AnalyzePathsFromArgs(tool, argsJSON, cwd, extraPaths)

	// Signal 4: network analysis — use hosts extracted from shell commands
	netSig := signals.AnalyzeNetworkFromExtracted(cmd)

	// Signal 5: DLP scan
	dlpSig := signals.ScanDLP(argsJSON)

	// Signal 6: evasion indicators
	evasionSig := signals.AnalyzeEvasion(cmd, argsJSON)

	return &signals.SignalBundle{
		ToolClass: toolClass,
		Command:   cmd,
		Path:      pathSig,
		Network:   netSig,
		DLP:       dlpSig,
		Evasion:   evasionSig,
	}
}


func buildEvidence(b *signals.SignalBundle) []string {
	var ev []string

	if b.Path.HasCritical {
		ev = append(ev, fmt.Sprintf("critical path accessed (risk=%.2f)", b.Path.MaxPathRisk))
	}
	if b.Path.HasSensitive {
		ev = append(ev, "sensitive file pattern matched")
	}
	if b.DLP.HasHit {
		for _, h := range b.DLP.Hits {
			if !h.IsTest {
				ev = append(ev, fmt.Sprintf("credential detected: %s", h.Provider))
			}
		}
	}
	if b.Network.Score > 0.3 {
		ev = append(ev, fmt.Sprintf("network score=%.2f", b.Network.Score))
	}
	if b.Evasion.Score > 0.2 {
		ev = append(ev, fmt.Sprintf("evasion score=%.2f", b.Evasion.Score))
	}
	if b.Command.MaxVerbDanger > 0.5 {
		ev = append(ev, fmt.Sprintf("dangerous verb detected (danger=%.2f)", b.Command.MaxVerbDanger))
	}

	return ev
}

func marshalArgs(args map[string]any) string {
	if args == nil {
		return "{}"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// benignCorpusCase is the subset of fields needed from JSONL for bloom seeding.
type benignCorpusCase struct {
	Tool      string `json:"tool"`
	Arguments string `json:"arguments"` // raw JSON string in old format
}

func (e *Engine) loadBenignCorpus(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var tc benignCorpusCase
		if err := json.Unmarshal([]byte(line), &tc); err != nil {
			continue
		}
		var args map[string]any
		if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
			continue
		}
		key := bloom.CanonicalKey(tc.Tool, args)
		e.bloom.Add(key)
	}
	return scanner.Err()
}

func defaultCorpusPaths() []string {
	// Try paths relative to binary location and common development layouts
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	return []string{
		"testdata/eval/benign.jsonl",
		"testdata/eval/benign-native.jsonl",
		filepath.Join(exeDir, "../../testdata/eval/benign.jsonl"),
	}
}

func loadCommandDB() (*extract.CommandDB, error) {
	candidates := []string{
		"policies/data/commands.yaml",
		"../../policies/data/commands.yaml",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return extract.LoadCommandDB(p)
		}
	}
	return nil, fmt.Errorf("command DB not found")
}
