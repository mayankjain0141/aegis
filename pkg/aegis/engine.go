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
	"github.com/mayjain/aegis/pkg/aegis/allowlist"
	"github.com/mayjain/aegis/pkg/aegis/bloom"
	"github.com/mayjain/aegis/pkg/aegis/intent"
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
	rules            []rules.Rule
	bloom            *bloom.Filter
	extractor        *extract.Extractor // fast (AST-only) for Phase 1
	fullExtractor    *extract.Extractor // full (with dry-run) for Phase 2
	sessions         map[string]*session.State
	sessionMu        sync.Mutex
	intentClassifier intentClassifier
	allowlist        *allowlist.Config
}

// intentClassifier is an interface so we can wire in intent.Classifier without a hard dep.
type intentClassifier interface {
	Classify(ctx context.Context, req *intent.ClassifyRequest) (*intent.IntentSignal, error)
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
		rules:         rules.Phase1Rules(),
		bloom:         bloom.New(1000, 0.01),
		extractor:     extract.NewFastExtractor(db), // AST-only for Phase 1 speed
		fullExtractor: extract.NewExtractor(db),     // full dry-run for Phase 2
		sessions:      make(map[string]*session.State),
		allowlist:     allowlist.Empty(),
	}

	// Auto-load project allowlist if CWD exists
	if cwd, err := os.Getwd(); err == nil {
		if cfg := allowlist.Load(cwd); len(cfg.Hosts)+len(cfg.Commands)+len(cfg.PathsSafe) > 0 {
			e.allowlist = cfg
		}
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

	// Allowlist fast path: check project/user allowlist before rule evaluation
	if allow, rule := e.checkAllowlist(req, argsJSON); allow {
		d := &Decision{Action: ActionAllow, Rule: rule, Confidence: 1.00, Phase: 0}
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
	var d2 *Decision
	var d2matched bool
	sess := e.getOrCreateSession(req.AgentID)
	if sess != nil {
		// Recompute with full extractor for better signal quality
		bundle = e.computeSignalsFull(req.Tool, argsJSON, req.CWD)
		composite = signals.CompositeScore(bundle)

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
		b2.BaselineEstablished = sig.BaselineEstablished
		bBundle := rules.BehavioralBundle{Phase1: bundle, Phase2: b2}
		if p2rule, p2matched2 := rules.BehavioralEvaluate(bBundle); p2matched2 {
			d2matched = true
			d2 = &Decision{
				Action:         p2rule.Action,
				Rule:           p2rule.Name,
				Severity:       p2rule.Severity,
				Confidence:     p2rule.Confidence,
				CompositeScore: composite,
				Phase:          2,
			}
		}
	}

	// Phase 3: LLM intent for persistent uncertainty (ESCALATE decisions)
	if e.intentClassifier != nil {
		finalAction := d1.Action
		if d2matched {
			finalAction = d2.Action
		}
		if finalAction == ActionEscalate {
			creq := &intent.ClassifyRequest{
				Tool: req.Tool,
				Args: req.Arguments,
			}
			if sess != nil {
				for _, h := range sess.RecentCalls(5) {
					creq.SessionLast = append(creq.SessionLast, intent.SessionEntry{
						Tool:    h.Tool,
						Summary: h.ArgSummary,
						AgoS:    int(time.Since(h.Time).Seconds()),
					})
				}
			}
			sig, err := e.intentClassifier.Classify(ctx, creq)
			if err != nil {
				d3 := &Decision{Action: ActionDeny, Rule: "llm_timeout", Confidence: 0.60, CompositeScore: composite, Phase: 3}
				e.recordCall(req, d3, composite)
				return d3
			}
			d3 := applyPhase3Rules(sig, composite)
			e.recordCall(req, d3, composite)
			return d3
		}
	}

	if d2matched {
		e.recordCall(req, d2, composite)
		return d2
	}
	e.recordCall(req, d1, composite)
	return d1
}

func applyPhase3Rules(sig *intent.IntentSignal, composite float64) *Decision {
	switch {
	case sig.Intent == "malicious" && sig.Confidence > 0.8:
		return &Decision{Action: ActionDeny, Rule: "llm_malicious", Severity: "high", Confidence: 0.90, CompositeScore: composite, Phase: 3}
	case sig.Intent == "suspicious" && sig.Confidence > 0.8:
		return &Decision{Action: ActionEscalate, Rule: "llm_suspicious_high", Severity: "medium", Confidence: 0.75, CompositeScore: composite, Phase: 3}
	case sig.Intent == "legitimate" && sig.Confidence > 0.8:
		return &Decision{Action: ActionAllow, Rule: "llm_legitimate", Confidence: 0.85, CompositeScore: composite, Phase: 3}
	default:
		return &Decision{Action: ActionDeny, Rule: "llm_uncertain", Confidence: 0.65, CompositeScore: composite, Phase: 3}
	}
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

// checkAllowlist returns (true, ruleName) if the request matches any allowlist entry.
func (e *Engine) checkAllowlist(req *Request, argsJSON string) (bool, string) {
	if e.allowlist == nil {
		return false, ""
	}
	// Command allowlist: match raw shell command string
	if cmd, ok := req.Arguments["command"]; ok {
		if cmdStr, ok := cmd.(string); ok && cmdStr != "" {
			if e.allowlist.MatchesCommand(cmdStr) {
				return true, "allowlist_command"
			}
		}
	}
	// Path allowlist: match path argument for file tools
	for _, key := range []string{"path", "file", "filename"} {
		if p, ok := req.Arguments[key]; ok {
			if pathStr, ok := p.(string); ok && e.allowlist.IsSafePath(pathStr) {
				return true, "allowlist_path"
			}
		}
	}
	return false, ""
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

// WithIntentClassifier wires a Phase 3 LLM intent classifier into the engine.
func WithIntentClassifier(c *intent.Classifier) Option {
	return func(e *Engine) { e.intentClassifier = c }
}

// WithAllowlist loads an allowlist configuration into the engine.
// Allowlisted commands/hosts/paths skip deny rules and return allow.
func WithAllowlist(cfg *allowlist.Config) Option {
	return func(e *Engine) { e.allowlist = cfg }
}

// WithAllowlistFromCWD auto-loads allowlist from the given project directory.
func WithAllowlistFromCWD(cwd string) Option {
	return func(e *Engine) { e.allowlist = allowlist.Load(cwd) }
}

func (e *Engine) computeSignalsFull(tool, argsJSON, cwd string) *signals.SignalBundle {
	toolClass := signals.ClassifyTool(tool)
	cmd := signals.AnalyzeCommand(tool, argsJSON, e.fullExtractor)
	extraPaths := append([]string(nil), cmd.Paths...)
	for _, c := range cmd.Commands {
		if hasDataFile, filePath := signals.HasDataFilePattern(c.Args); hasDataFile && filePath != "" {
			extraPaths = append(extraPaths, filePath)
		}
	}
	pathSig := signals.AnalyzePathsFromArgs(tool, argsJSON, cwd, extraPaths)
	netSig := signals.AnalyzeNetworkFromExtracted(cmd)
	dlpSig := signals.ScanDLP(argsJSON)
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

	// Apply path allowlist: downgrade "sensitive" classification for explicitly safe paths
	if e.allowlist != nil {
		for i := range pathSig.Paths {
			if pathSig.Paths[i].Sensitive && e.allowlist.IsSafePath(pathSig.Paths[i].Raw) {
				pathSig.Paths[i].Sensitive = false
			}
		}
		// Recompute HasSensitive
		pathSig.HasSensitive = false
		for _, p := range pathSig.Paths {
			if p.Sensitive {
				pathSig.HasSensitive = true
				break
			}
		}
	}

	// Signal 4: network analysis — use hosts extracted from shell commands
	// Apply host allowlist: mark configured hosts as known-safe
	netSig := signals.AnalyzeNetworkFromExtracted(cmd)
	if e.allowlist != nil {
		for i := range netSig.Hosts {
			if !netSig.Hosts[i].IsKnownSafe && e.allowlist.IsAllowedHost(netSig.Hosts[i].Host) {
				netSig.Hosts[i].IsKnownSafe = true
			}
		}
		// Recompute score with updated host classifications
		netSig = signals.RecomputeNetworkScore(netSig)
	}

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
