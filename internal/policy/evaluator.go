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
	ModeLegacy EvalMode = iota // use only legacy Go rules (default, safe)
	ModeYAML                   // use only YAML-compiled rules
	ModeHybrid                 // merge both; YAML takes precedence on name collision
)

// ModeFromEnv reads AEGIS_POLICY_MODE env var.
// Returns ModeLegacy for unknown values (safe default).
func ModeFromEnv() EvalMode {
	switch strings.ToLower(os.Getenv("AEGIS_POLICY_MODE")) {
	case "yaml":
		return ModeYAML
	case "hybrid":
		return ModeHybrid
	default:
		return ModeLegacy
	}
}

// PolicyEvaluator implements the RuleEvaluator interface (defined in pkg/aegis/evaluator.go).
// It supports three modes: legacy, yaml, and hybrid.
type PolicyEvaluator struct {
	mode   EvalMode
	yaml   []CompiledRule
	legacy []rules.Rule
}

// NewPolicyEvaluator creates a PolicyEvaluator.
// yamlRules may be nil in legacy mode.
func NewPolicyEvaluator(mode EvalMode, yamlRules []CompiledRule) (*PolicyEvaluator, error) {
	return &PolicyEvaluator{
		mode:   mode,
		yaml:   yamlRules,
		legacy: rules.Phase1Rules(),
	}, nil
}

// Evaluate implements RuleEvaluator. Returns first matching rule and true, or zero and false.
func (e *PolicyEvaluator) Evaluate(b *signals.SignalBundle) (rules.Rule, bool) {
	switch e.mode {
	case ModeYAML:
		return e.evaluateYAML(b)
	case ModeHybrid:
		return e.evaluateHybrid(b)
	default: // ModeLegacy
		return rules.Evaluate(e.legacy, b)
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
		legacyFn func(*signals.SignalBundle) bool
		meta     rules.Rule
	}

	seen := make(map[string]bool)
	var entries []hybridEntry

	for _, yr := range e.yaml {
		seen[yr.Name] = true
		yr := yr
		entries = append(entries, hybridEntry{
			priority: yr.Priority,
			name:     yr.Name,
			fromYAML: true,
			yamlRule: yr,
		})
	}

	for _, lr := range e.legacy {
		if seen[lr.Name] {
			continue
		}
		lr := lr
		entries = append(entries, hybridEntry{
			priority: lr.Priority,
			name:     lr.Name,
			fromYAML: false,
			legacyFn: lr.Condition,
			meta:     lr,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].priority < entries[j].priority
	})

	for _, entry := range entries {
		var matched bool
		if entry.fromYAML {
			matched = entry.yamlRule.Predicate(b)
		} else {
			matched = entry.legacyFn(b)
		}
		if matched {
			if entry.fromYAML {
				return rules.Rule{
					Name:       entry.yamlRule.Name,
					Priority:   entry.yamlRule.Priority,
					Action:     rules.Action(entry.yamlRule.Action),
					Severity:   entry.yamlRule.Severity,
					Confidence: entry.yamlRule.Confidence,
				}, true
			}
			return entry.meta, true
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
