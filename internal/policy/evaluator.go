package policy

import (
	"os"
	"sort"
	"strings"

	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// EvalMode controls which rule set the PolicyEvaluator uses.
type EvalMode int

const (
	ModeYAML   EvalMode = iota // use YAML-compiled rules (default)
	ModeHybrid                 // merge YAML rules with any manually registered rules
)

// ModeFromEnv reads AEGIS_POLICY_MODE env var.
// Returns ModeYAML for unknown/legacy values — YAML is now the sole source of truth.
func ModeFromEnv() EvalMode {
	switch strings.ToLower(os.Getenv("AEGIS_POLICY_MODE")) {
	case "hybrid":
		return ModeHybrid
	default:
		return ModeYAML // legacy → yaml, unset → yaml
	}
}

// PolicyEvaluator implements the RuleEvaluator interface (defined in pkg/aegis/evaluator.go).
// It supports two modes: yaml (default) and hybrid.
type PolicyEvaluator struct {
	mode EvalMode
	yaml []CompiledRule
}

// NewPolicyEvaluator creates a PolicyEvaluator. YAML is the default mode.
func NewPolicyEvaluator(mode EvalMode, yamlRules []CompiledRule) (*PolicyEvaluator, error) {
	return &PolicyEvaluator{
		mode: mode,
		yaml: yamlRules,
	}, nil
}

// Evaluate implements RuleEvaluator. Returns first matching rule and true, or zero and false.
func (e *PolicyEvaluator) Evaluate(b *signals.SignalBundle) (rules.Rule, bool) {
	switch e.mode {
	case ModeHybrid:
		return e.evaluateHybrid(b)
	default: // ModeYAML
		return e.evaluateYAML(b)
	}
}

func (e *PolicyEvaluator) evaluateYAML(b *signals.SignalBundle) (rules.Rule, bool) {
	result, matched := EvaluateCompiled(e.yaml, b)
	if !matched {
		return rules.Rule{}, false
	}
	return rules.Rule{
		Name:       result.Name,
		Action:     rules.Action(result.Action),
		Confidence: compiledConfidence(e.yaml, result.Name),
		Severity:   compiledSeverity(e.yaml, result.Name),
		Priority:   compiledPriority(e.yaml, result.Name),
	}, true
}

func (e *PolicyEvaluator) evaluateHybrid(b *signals.SignalBundle) (rules.Rule, bool) {
	type hybridEntry struct {
		priority int
		name     string
		fromYAML bool
		yamlRule CompiledRule
	}

	var entries []hybridEntry

	for _, yr := range e.yaml {
		yr := yr
		entries = append(entries, hybridEntry{
			priority: yr.Priority,
			name:     yr.Name,
			fromYAML: true,
			yamlRule: yr,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].priority < entries[j].priority
	})

	for _, entry := range entries {
		if entry.yamlRule.Predicate(b) {
			return rules.Rule{
				Name:       entry.yamlRule.Name,
				Priority:   entry.yamlRule.Priority,
				Action:     rules.Action(entry.yamlRule.Action),
				Severity:   entry.yamlRule.Severity,
				Confidence: entry.yamlRule.Confidence,
			}, true
		}
	}
	return rules.Rule{}, false
}

func compiledConfidence(compiledRules []CompiledRule, name string) float64 {
	for _, r := range compiledRules {
		if r.Name == name {
			return r.Confidence
		}
	}
	return 0
}

func compiledSeverity(compiledRules []CompiledRule, name string) string {
	for _, r := range compiledRules {
		if r.Name == name {
			return r.Severity
		}
	}
	return ""
}

func compiledPriority(compiledRules []CompiledRule, name string) int {
	for _, r := range compiledRules {
		if r.Name == name {
			return r.Priority
		}
	}
	return 0
}
