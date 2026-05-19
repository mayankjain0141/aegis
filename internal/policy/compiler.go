package policy

import (
	"fmt"
	"strings"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// Predicate is a compiled condition — a function that evaluates a signal bundle.
type Predicate func(*signals.SignalBundle) bool

// CompiledRule is a rule with a compiled predicate.
type CompiledRule struct {
	Name       string
	Priority   int
	Action     string
	Severity   string
	Confidence float64
	Predicate  Predicate
}

// CompiledRuleResult is returned by EvaluateCompiled for parity testing.
type CompiledRuleResult struct {
	Name   string
	Action string
}

// Compile turns a Condition into a Predicate closure.
func Compile(cond Condition) (Predicate, error) {
	return compileCondition(cond)
}

// CompileRule compiles a full RuleDef into a CompiledRule.
func CompileRule(def RuleDef) (CompiledRule, error) {
	pred, err := compileCondition(def.Condition)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("rule %q: %w", def.Name, err)
	}
	return CompiledRule{
		Name:       def.Name,
		Priority:   def.Priority,
		Action:     def.Action,
		Severity:   def.Severity,
		Confidence: def.Confidence,
		Predicate:  pred,
	}, nil
}

// CompileFile compiles all rules in a PolicyFile.
func CompileFile(pf *PolicyFile) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(pf.Rules))
	for _, def := range pf.Rules {
		cr, err := CompileRule(def)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, cr)
	}
	return compiled, nil
}

// EvaluateCompiled runs compiled rules in priority order, returns first match.
func EvaluateCompiled(compiledRules []CompiledRule, b *signals.SignalBundle) (CompiledRuleResult, bool) {
	sorted := make([]CompiledRule, len(compiledRules))
	copy(sorted, compiledRules)
	sortByPriority(sorted)
	for _, r := range sorted {
		if r.Predicate(b) {
			return CompiledRuleResult{Name: r.Name, Action: r.Action}, true
		}
	}
	return CompiledRuleResult{}, false
}

func sortByPriority(compiledRules []CompiledRule) {
	for i := 1; i < len(compiledRules); i++ {
		for j := i; j > 0 && compiledRules[j].Priority < compiledRules[j-1].Priority; j-- {
			compiledRules[j], compiledRules[j-1] = compiledRules[j-1], compiledRules[j]
		}
	}
}

// compileCondition is the recursive core of the compiler.
func compileCondition(cond Condition) (Predicate, error) {
	var predicates []Predicate

	// AnyVerb
	if len(cond.AnyVerb) > 0 {
		verbs := cond.AnyVerb
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			return anyVerbMatch(b, verbs)
		})
	}

	// ToolCategory
	if cond.ToolCategory != nil {
		var cats []string
		switch v := cond.ToolCategory.(type) {
		case string:
			cats = []string{v}
		case []interface{}:
			for _, c := range v {
				if s, ok := c.(string); ok {
					cats = append(cats, s)
				}
			}
		case []string:
			cats = v
		}
		if len(cats) > 0 {
			predicates = append(predicates, func(b *signals.SignalBundle) bool {
				for _, cat := range cats {
					if b.ToolClass.Category == cat {
						return true
					}
				}
				return false
			})
		}
	}

	// Path conditions
	if cond.Path != nil {
		p := cond.Path
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			if p.HasCritical != nil && b.Path.HasCritical != *p.HasCritical {
				return false
			}
			if p.HasSensitive != nil && b.Path.HasSensitive != *p.HasSensitive {
				return false
			}
			if p.AllInProject != nil && b.Path.AllInProject != *p.AllInProject {
				return false
			}
			return true
		})
	}

	// Network conditions
	if cond.Network != nil {
		n := cond.Network
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			if n.ScoreGt != nil && b.Network.Score <= *n.ScoreGt {
				return false
			}
			if n.HasDataFlag != nil && b.Network.HasDataFlag != *n.HasDataFlag {
				return false
			}
			if n.HasStdinPipe != nil && b.Network.HasStdinPipe != *n.HasStdinPipe {
				return false
			}
			return true
		})
	}

	// DLP conditions
	if cond.DLP != nil {
		d := cond.DLP
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			if d.HasHit != nil && b.DLP.HasHit != *d.HasHit {
				return false
			}
			if d.AllTest != nil && b.DLP.AllTest != *d.AllTest {
				return false
			}
			return true
		})
	}

	// Evasion conditions
	if cond.Evasion != nil {
		ev := cond.Evasion
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			if ev.EncodingDetected != nil && b.Evasion.EncodingDetected != *ev.EncodingDetected {
				return false
			}
			if ev.ScoreGt != nil && b.Evasion.Score <= *ev.ScoreGt {
				return false
			}
			return true
		})
	}

	// VerbDanger thresholds
	if len(cond.VerbDanger) > 0 {
		thresholds := cond.VerbDanger
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			for verb, thresh := range thresholds {
				danger, ok := b.Command.VerbDanger[verb]
				if !ok {
					danger = 0
				}
				if !matchThreshold(danger, thresh) {
					return false
				}
			}
			return len(thresholds) > 0
		})
	}

	// Behavioral conditions require session history — evaluated separately by the behavioral
	// engine, not the per-call static evaluator. Always-false in Phase 1 context.
	if cond.Behavioral != nil {
		predicates = append(predicates, func(*signals.SignalBundle) bool { return false })
	}

	// Combinators
	if len(cond.And) > 0 {
		var subs []Predicate
		for _, sub := range cond.And {
			p, err := compileCondition(sub)
			if err != nil {
				return nil, err
			}
			subs = append(subs, p)
		}
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			for _, p := range subs {
				if !p(b) {
					return false
				}
			}
			return true
		})
	}

	if len(cond.Or) > 0 {
		var subs []Predicate
		for _, sub := range cond.Or {
			p, err := compileCondition(sub)
			if err != nil {
				return nil, err
			}
			subs = append(subs, p)
		}
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			for _, p := range subs {
				if p(b) {
					return true
				}
			}
			return false
		})
	}

	if cond.Not != nil {
		sub, err := compileCondition(*cond.Not)
		if err != nil {
			return nil, err
		}
		predicates = append(predicates, func(b *signals.SignalBundle) bool {
			return !sub(b)
		})
	}

	// Tier 2: Expr
	if cond.Expr != "" {
		pred, err := CompileExpr(cond.Expr)
		if err != nil {
			return nil, fmt.Errorf("compile expr: %w", err)
		}
		predicates = append(predicates, pred)
	}

	// Tier 3: Rego
	if cond.Rego != "" {
		query := cond.RegoRule
		if query == "" {
			query = "data.aegis.deny"
		}
		pred, err := CompileRego(cond.Rego, query)
		if err != nil {
			return nil, fmt.Errorf("compile rego condition: %w", err)
		}
		predicates = append(predicates, pred)
	}

	// Empty condition always-false
	if len(predicates) == 0 {
		return func(*signals.SignalBundle) bool { return false }, nil
	}

	// Single predicate — return directly
	if len(predicates) == 1 {
		return predicates[0], nil
	}

	// Multiple top-level conditions = implicit AND
	return func(b *signals.SignalBundle) bool {
		for _, p := range predicates {
			if !p(b) {
				return false
			}
		}
		return true
	}, nil
}

func anyVerbMatch(b *signals.SignalBundle, verbs []string) bool {
	if len(verbs) == 0 {
		return false
	}
	for _, v := range b.Command.Verbs {
		for _, want := range verbs {
			if strings.EqualFold(v, want) {
				return true
			}
		}
	}
	return false
}

func matchThreshold(val float64, t ThresholdCond) bool {
	if t.Gt != nil && !(val > *t.Gt) {
		return false
	}
	if t.Gte != nil && !(val >= *t.Gte) {
		return false
	}
	if t.Lt != nil && !(val < *t.Lt) {
		return false
	}
	if t.Lte != nil && !(val <= *t.Lte) {
		return false
	}
	return true
}
