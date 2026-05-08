package policy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// policyFile represents the top-level YAML structure.
type policyFile struct {
	Version  string       `yaml:"version"`
	Policies []policyRule `yaml:"policies"`
}

type policyRule struct {
	Name      string         `yaml:"name"`
	Match     policyMatch    `yaml:"match"`
	Action    string         `yaml:"action"`
	Severity  string         `yaml:"severity"`
	RateLimit *RateLimitConfig `yaml:"rate_limit"`
}

type policyMatch struct {
	Tool        string `yaml:"tool"`
	ArgsPattern string `yaml:"args_pattern"`
	AgentID     string `yaml:"agent_id"`
}

// LoadFromFile parses a YAML policy file and returns a StaticEvaluator.
func LoadFromFile(path string) (*StaticEvaluator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read file: %w", err)
	}
	return parseYAML(data)
}

func parseYAML(data []byte) (*StaticEvaluator, error) {
	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse yaml: %w", err)
	}

	rules := make([]CompiledRule, 0, len(pf.Policies))
	for _, pr := range pf.Policies {
		cr, err := compileRule(pr)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", pr.Name, err)
		}
		rules = append(rules, cr)
	}

	return NewStaticEvaluator(rules, pf.Version, ActionDeny), nil
}

func compileRule(pr policyRule) (CompiledRule, error) {
	action, err := parseAction(pr.Action)
	if err != nil {
		return CompiledRule{}, err
	}

	toolPat, err := CompileGlob(pr.Match.Tool)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("tool pattern: %w", err)
	}

	var argsPat *regexp.Regexp
	if pr.Match.ArgsPattern != "" {
		argsPat, err = regexp.Compile(pr.Match.ArgsPattern)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("args_pattern: %w", err)
		}
	}

	agentPat, err := CompileGlob(pr.Match.AgentID)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("agent_id pattern: %w", err)
	}

	return CompiledRule{
		Name:         pr.Name,
		ToolPattern:  toolPat,
		ArgsPattern:  argsPat,
		AgentPattern: agentPat,
		Action:       action,
		Severity:     pr.Severity,
		RateLimit:    pr.RateLimit,
	}, nil
}

func parseAction(s string) (Action, error) {
	switch Action(s) {
	case ActionAllow, ActionDeny, ActionEscalateHuman, ActionThrottle:
		return Action(s), nil
	default:
		return "", fmt.Errorf("unknown action %q", s)
	}
}

// HotReloader manages atomic swapping of a StaticEvaluator on file changes.
type HotReloader struct {
	evaluator atomic.Pointer[StaticEvaluator]
}

// NewHotReloader creates a reloader seeded with the given evaluator.
func NewHotReloader(initial *StaticEvaluator) *HotReloader {
	hr := &HotReloader{}
	hr.evaluator.Store(initial)
	return hr
}

// Current returns the currently active evaluator.
func (hr *HotReloader) Current() *StaticEvaluator {
	return hr.evaluator.Load()
}

// Evaluate delegates to the current evaluator (implements PolicyEvaluator).
func (hr *HotReloader) Evaluate(ctx context.Context, req *ToolCallRequest) (*PolicyDecision, error) {
	return hr.evaluator.Load().Evaluate(ctx, req)
}

// WatchAndReload polls the policy file for changes and hot-reloads on modification.
// It uses polling (not fsnotify) to keep dependencies minimal.
func WatchAndReload(ctx context.Context, path string, reloader *HotReloader, logger *slog.Logger) error {
	var lastMod time.Time

	info, err := os.Stat(path)
	if err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				logger.Warn("policy: stat failed", "path", path, "error", err)
				continue
			}
			if !info.ModTime().After(lastMod) {
				continue
			}
			lastMod = info.ModTime()

			newEval, err := LoadFromFile(path)
			if err != nil {
				logger.Error("policy: reload failed, keeping old", "error", err)
				continue
			}

			old := reloader.Current()
			reloader.evaluator.Store(newEval)
			logger.Info("policy: reloaded",
				"old_version", old.Version(),
				"new_version", newEval.Version(),
				"rules", newEval.RuleCount(),
			)
		}
	}
}
