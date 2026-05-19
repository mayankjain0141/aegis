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
	"time"

	"github.com/mayjain/aegis/internal/extract"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/allowlist"
	"github.com/mayjain/aegis/pkg/aegis/bloom"
	"github.com/mayjain/aegis/pkg/aegis/intent"
	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/session"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// mlScorer is the default ML scorer used when no WithMLModel option is given.
var mlScorer = signals.NewMLScorer("")

// EvaluationStage identifies which layer of the evaluation cascade produced a Decision.
type EvaluationStage string

const (
	StageFastPath    EvaluationStage = "fast_path"    // bloom filter / allowlist short-circuit
	StageStaticRules EvaluationStage = "static_rules" // YAML-compiled rule engine
	StageBehavioral  EvaluationStage = "behavioral"   // session history analysis
	StageIntentLLM   EvaluationStage = "intent_llm"   // LLM intent classifier
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
	Action         Action          `json:"action"`
	Rule           string          `json:"rule"`
	Severity       string          `json:"severity,omitempty"`
	Confidence     float64         `json:"confidence"`
	Evidence       []string        `json:"evidence,omitempty"`
	CompositeScore float64         `json:"composite_score"`
	Stage          EvaluationStage `json:"stage"`
}

// IntentClassifier is the interface for Phase 3 LLM intent classification.
// Satisfied by *intent.Classifier; also usable with test mocks.
type IntentClassifier interface {
	Classify(ctx context.Context, req *intent.ClassifyRequest) (*intent.IntentSignal, error)
}

// intentClassifier is the unexported alias used internally.
type intentClassifier = IntentClassifier

// Engine is the V2 risk evaluation engine.
type Engine struct {
	fastPath   FastPath
	evaluator  RuleEvaluator
	sigComp    SignalComputer
	sessions   SessionStore
	phase3     IntentClassifier
	recorder   DecisionRecorder
	policyMode string
	scorer     *signals.MLScorer
	// bloom is kept for loadBenignCorpus access (WithBenignCorpus option).
	bloom *bloom.Filter
}

// Option configures the Engine.
type Option func(*Engine)

// WithBenignCorpus pre-populates the bloom filter from a JSONL file.
func WithBenignCorpus(path string) Option {
	return func(e *Engine) {
		if err := e.loadBenignCorpus(path); err != nil {
			fmt.Fprintf(os.Stderr, "aegis: bloom filter load warning: %v\n", err)
		}
	}
}

// WithRules replaces the default rule set.
func WithRules(r []rules.Rule) Option {
	return func(e *Engine) {
		e.evaluator = newStaticRuleEvaluator(r)
	}
}

// WithIntentClassifier wires a Phase 3 LLM intent classifier into the engine.
func WithIntentClassifier(c IntentClassifier) Option {
	return func(e *Engine) { e.phase3 = c }
}

// WithAllowlist sets a fixed allowlist used for all requests regardless of CWD.
func WithAllowlist(cfg *allowlist.Config) Option {
	return func(e *Engine) {
		e.fastPath.setAllowlist("", cfg)
	}
}

// WithAllowlistFromCWD pre-loads an allowlist for a specific project directory.
func WithAllowlistFromCWD(cwd string) Option {
	return func(e *Engine) {
		e.fastPath.loadCWD(cwd)
	}
}

// WithPolicyMode sets the policy evaluation mode (yaml|hybrid).
// Default is yaml — YAML is now the sole source of truth.
func WithPolicyMode(mode string) Option {
	return func(e *Engine) {
		e.policyMode = mode
	}
}

// WithMLModel loads a LightGBM model from modelPath and uses it for ML scoring.
// If modelPath is empty or the file cannot be loaded, the heuristic scorer is used.
func WithMLModel(modelPath string) Option {
	return func(e *Engine) {
		e.scorer = signals.NewMLScorer(modelPath)
	}
}

// NewEngine creates an Engine with Phase 1 static rules.
func NewEngine(opts ...Option) (*Engine, error) {
	db, err := loadCommandDB()
	if err != nil {
		db = nil
	}

	bl := bloom.New(1000, 0.01)
	fp := newDefaultFastPath(bl, nil)
	store := newInMemorySessionStore()
	fast := extract.NewFastExtractor(db)
	full := extract.NewExtractor(db)
	sigComp := newDefaultSignalComputer(fast, full, fp)

	e := &Engine{
		fastPath: fp,
		sigComp:  sigComp,
		sessions: store,
		recorder: newSessionRecorder(store),
		bloom:    bl,
	}

	for _, opt := range opts {
		opt(e)
	}

	// Re-wire signal computer with the engine's ML scorer if set by an option.
	if e.scorer != nil {
		e.sigComp = newDefaultSignalComputerWithScorer(fast, full, fp, e.scorer)
	}

	// Wire PolicyEvaluator — policyMode from option overrides env var.
	evalMode := policy.ModeFromEnv()
	if e.policyMode != "" {
		switch strings.ToLower(e.policyMode) {
		case "hybrid":
			evalMode = policy.ModeHybrid
		default:
			evalMode = policy.ModeYAML
		}
	}

	yamlRules := loadYAMLRules()
	if pe, err := policy.NewPolicyEvaluator(evalMode, yamlRules); err == nil {
		e.evaluator = pe
	}
	// If PolicyEvaluator fails, fall back to a no-op static evaluator.
	if e.evaluator == nil {
		e.evaluator = newStaticRuleEvaluator(nil)
	}

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

	// Fast path: bloom filter + allowlist short-circuit
	if allow, rule := e.fastPath.Check(req, argsJSON); allow {
		d := &Decision{Action: ActionAllow, Rule: rule, Confidence: 1.00, Stage: StageFastPath}
		e.recorder.Record(req, d, 0.0, nil)
		return d
	}

	// Static rule engine
	bundle := e.sigComp.Compute(req.Tool, argsJSON, req.CWD)
	composite := signals.CompositeScore(bundle)

	rule, matched := e.evaluator.Evaluate(bundle)
	var staticDecision *Decision
	if !matched {
		staticDecision = &Decision{Action: ActionDeny, Rule: "no_rule_matched", Severity: "medium", Confidence: 0.50, CompositeScore: composite, Stage: StageStaticRules}
	} else {
		staticDecision = &Decision{Action: rule.Action, Rule: rule.Name, Severity: rule.Severity, Confidence: rule.Confidence, Evidence: buildEvidence(bundle), CompositeScore: composite, Stage: StageStaticRules}
	}

	// High-confidence static rule decisions are final
	if staticDecision.Confidence >= 0.85 {
		e.recorder.Record(req, staticDecision, composite, bundle)
		return staticDecision
	}

	// Behavioral analysis for low-confidence decisions
	var behavioralDecision *Decision
	var behavioralMatched bool
	sess := e.sessions.GetOrCreate(req.AgentID)
	if sess != nil {
		bundle = e.sigComp.ComputeFull(req.Tool, argsJSON, req.CWD)
		composite = signals.CompositeScore(bundle)

		sessionSig := sess.Signal(session.ToolCall{Time: time.Now(), Tool: req.Tool})
		history := toHistoryEntries(sess.RecentCalls(20), bundle)
		primaryVerb := ""
		if len(bundle.Command.Verbs) > 0 {
			primaryVerb = bundle.Command.Verbs[0]
		}
		behavioralSig := signals.ComputeBehavioral(
			bundle, primaryVerb, history,
			sessionSig.CallsLastMinute,
			sessionSig.LastDenyTimeAgo, sessionSig.LastDenyVerb,
			sessionSig.BaselineDeviation,
			sessionSig.RiskTrend,
			time.Now(),
		)
		behavioralSig.BaselineEstablished = sessionSig.BaselineEstablished
		behavioralBundle := rules.BehavioralBundle{Signals: bundle, Behavior: behavioralSig}
		if p2rule, p2matched2 := rules.BehavioralEvaluate(behavioralBundle); p2matched2 {
			behavioralMatched = true
			behavioralDecision = &Decision{
				Action:         p2rule.Action,
				Rule:           p2rule.Name,
				Severity:       p2rule.Severity,
				Confidence:     p2rule.Confidence,
				CompositeScore: composite,
				Stage:          StageBehavioral,
			}
		}
	}

	// LLM intent classifier for persistent uncertainty (ESCALATE decisions)
	if e.phase3 != nil {
		finalAction := staticDecision.Action
		if behavioralMatched {
			finalAction = behavioralDecision.Action
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
			intentSig, err := e.phase3.Classify(ctx, creq)
			if err != nil {
				rule := "llm_error"
				if err.Error() == "model_refusal" {
					rule = "llm_refusal"
				}
				d3 := &Decision{Action: ActionDeny, Rule: rule, Confidence: 0.60, CompositeScore: composite, Stage: StageIntentLLM}
				e.recorder.Record(req, d3, composite, bundle)
				return d3
			}
			d3 := classifyIntent(intentSig, composite)
			e.recorder.Record(req, d3, composite, bundle)
			return d3
		}
	}

	if behavioralMatched {
		e.recorder.Record(req, behavioralDecision, composite, bundle)
		return behavioralDecision
	}
	e.recorder.Record(req, staticDecision, composite, bundle)
	return staticDecision
}

func classifyIntent(intentSig *intent.IntentSignal, composite float64) *Decision {
	switch {
	case intentSig.Intent == "malicious" && intentSig.Confidence > 0.8:
		return &Decision{Action: ActionDeny, Rule: "llm_malicious", Severity: "high", Confidence: 0.90, CompositeScore: composite, Stage: StageIntentLLM}
	case intentSig.Intent == "suspicious" && intentSig.Confidence > 0.8:
		return &Decision{Action: ActionEscalate, Rule: "llm_suspicious_high", Severity: "medium", Confidence: 0.75, CompositeScore: composite, Stage: StageIntentLLM}
	case intentSig.Intent == "legitimate" && intentSig.Confidence > 0.8:
		return &Decision{Action: ActionAllow, Rule: "llm_legitimate", Confidence: 0.85, CompositeScore: composite, Stage: StageIntentLLM}
	default:
		return &Decision{Action: ActionDeny, Rule: "llm_uncertain", Confidence: 0.65, CompositeScore: composite, Stage: StageIntentLLM}
	}
}

func toHistoryEntries(calls []session.ToolCall, _ *signals.SignalBundle) []signals.SessionHistoryEntry {
	entries := make([]signals.SessionHistoryEntry, len(calls))
	for i, c := range calls {
		entries[i] = signals.SessionHistoryEntry{
			Time:           c.Time,
			Tool:           c.Tool,
			ArgSummary:     c.ArgSummary,
			Decision:       c.Decision,
			Rule:           c.Rule,
			CompositeScore: c.CompositeScore,
			PathSensitive:  c.PathSensitive,
			PathCritical:   c.PathCritical,
			NetworkWrite:   c.NetworkWrite,
		}
	}
	return entries
}

// ComputeSignals computes all signals for a tool call without evaluating rules.
func (e *Engine) ComputeSignals(tool, command, cwd string) *signals.SignalBundle {
	argsJSON := marshalArgs(map[string]any{"command": command})
	return e.sigComp.Compute(tool, argsJSON, cwd)
}

// ExportSignals is an alias for ComputeSignals for use in demo/observability code.
func (e *Engine) ExportSignals(tool, command, cwd string) *signals.SignalBundle {
	return e.ComputeSignals(tool, command, cwd)
}

// EvaluateJSON is a convenience wrapper that accepts raw JSON arguments string.
func (e *Engine) EvaluateJSON(ctx context.Context, tool, argsJSON, cwd string) *Decision {
	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		args = map[string]any{}
	}
	return e.Evaluate(ctx, &Request{Tool: tool, Arguments: args, CWD: cwd})
}

// applyAllowlistMutations mutates a signal bundle to reflect project allowlist exceptions.
func applyAllowlistMutations(bundle *signals.SignalBundle, al *allowlist.Config) {
	for i := range bundle.Path.Paths {
		if bundle.Path.Paths[i].Sensitive && al.IsSafePath(bundle.Path.Paths[i].Raw) {
			bundle.Path.Paths[i].Sensitive = false
		}
	}
	bundle.Path.HasSensitive = false
	for _, p := range bundle.Path.Paths {
		if p.Sensitive {
			bundle.Path.HasSensitive = true
			break
		}
	}

	changed := false
	for i := range bundle.Network.Hosts {
		if !bundle.Network.Hosts[i].IsKnownSafe && al.IsAllowedHost(bundle.Network.Hosts[i].Host) {
			bundle.Network.Hosts[i].IsKnownSafe = true
			changed = true
		}
	}
	if changed {
		bundle.Network = signals.RecomputeNetworkScore(bundle.Network)
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
	if b.MLScore > 0.7 {
		ev = append(ev, fmt.Sprintf("ml score=%.2f (heuristic maliciousness)", b.MLScore))
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
	Arguments string `json:"arguments"`
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

func loadYAMLRules() []policy.CompiledRule {
	var allRules []policy.CompiledRule
	patterns := []string{
		"policies/phase1-deny.yaml",
		"policies/phase1-allow.yaml",
		"policies/phase1-escalate.yaml",
		"../../policies/phase1-deny.yaml",
		"../../policies/phase1-allow.yaml",
		"../../policies/phase1-escalate.yaml",
	}
	seen := make(map[string]bool)
	for _, p := range patterns {
		base := filepath.Base(p)
		if seen[base] {
			continue
		}
		pf, err := policy.LoadFile(p)
		if err != nil {
			continue
		}
		seen[base] = true
		compiled, err := policy.CompileFile(pf)
		if err != nil {
			continue
		}
		allRules = append(allRules, compiled...)
	}
	return allRules
}
