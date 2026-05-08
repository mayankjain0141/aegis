package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// CompiledRule is a pre-compiled policy rule ready for evaluation.
type CompiledRule struct {
	Name         string
	ToolPattern  *regexp.Regexp
	ArgsPattern  *regexp.Regexp
	AgentPattern *regexp.Regexp
	Action       Action
	Severity     string
	RateLimit    *RateLimitConfig
}

// RateLimitConfig defines rate limiting parameters.
type RateLimitConfig struct {
	MaxPerMinute int `yaml:"max_per_minute"`
}

// StaticEvaluator evaluates rules top-to-bottom, first match wins.
type StaticEvaluator struct {
	rules    []CompiledRule
	version  string
	fallback Action
}

// NewStaticEvaluator creates an evaluator with the given compiled rules and version.
func NewStaticEvaluator(rules []CompiledRule, version string, fallback Action) *StaticEvaluator {
	return &StaticEvaluator{
		rules:    rules,
		version:  version,
		fallback: fallback,
	}
}

// Version returns the policy version string.
func (se *StaticEvaluator) Version() string {
	return se.version
}

// RuleCount returns the number of compiled rules.
func (se *StaticEvaluator) RuleCount() int {
	return len(se.rules)
}

// Evaluate checks the request against all rules in order; first full match wins.
func (se *StaticEvaluator) Evaluate(_ context.Context, req *ToolCallRequest) (*PolicyDecision, error) {
	if req == nil {
		return nil, fmt.Errorf("policy: nil request")
	}

	for i := range se.rules {
		rule := &se.rules[i]
		if !matchesRule(rule, req) {
			continue
		}

		if rule.RateLimit != nil {
			if !isRateLimited(rule.RateLimit, req) {
				continue
			}
		}

		return &PolicyDecision{
			Action:        rule.Action,
			PolicyName:    rule.Name,
			PolicyVersion: se.version,
			Severity:      rule.Severity,
			Reason:        fmt.Sprintf("matched rule %q", rule.Name),
		}, nil
	}

	return &PolicyDecision{
		Action:        se.fallback,
		PolicyName:    "",
		PolicyVersion: se.version,
		Severity:      "",
		Reason:        "no policy matched (default " + string(se.fallback) + ")",
	}, nil
}

func matchesRule(rule *CompiledRule, req *ToolCallRequest) bool {
	if rule.ToolPattern != nil && !rule.ToolPattern.MatchString(req.Tool) {
		return false
	}
	if rule.ArgsPattern != nil && !rule.ArgsPattern.MatchString(req.Arguments) {
		return false
	}
	if rule.AgentPattern != nil {
		if !rule.AgentPattern.MatchString(req.AgentID) {
			return false
		}
	}
	return true
}

func isRateLimited(rl *RateLimitConfig, req *ToolCallRequest) bool {
	if req.SessionCtx == nil {
		return false
	}
	return req.SessionCtx.CallsLastMinute > rl.MaxPerMinute
}

// CompileGlob converts a simple glob pattern to a regexp.
// "*" → match everything, "shell_*" → "^shell_.*$", literal strings → exact match.
func CompileGlob(pattern string) (*regexp.Regexp, error) {
	if pattern == "" || pattern == "*" {
		return nil, nil
	}
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return regexp.Compile("^" + regexp.QuoteMeta(pattern) + "$")
	}
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)
	return regexp.Compile("^" + escaped + "$")
}
