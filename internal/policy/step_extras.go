package policy

import (
	"context"
	"regexp"
	"strings"
)

// DLPStep scans raw arguments for leaked secrets/tokens.
// Token formats ARE a regex problem (fixed formats like AKIA..., sk-proj-..., ghp_...).
type DLPStep struct {
	patterns []dlpPattern
}

type dlpPattern struct {
	name string
	re   *regexp.Regexp
}

// NewDLPStep creates a DLP step with the default token patterns.
func NewDLPStep() *DLPStep {
	return &DLPStep{patterns: defaultDLPPatterns()}
}

func (s *DLPStep) Name() string { return "dlp" }

func (s *DLPStep) Evaluate(_ context.Context, req *EnrichedRequest) (*PolicyDecision, error) {
	for _, p := range s.patterns {
		if p.re.MatchString(req.Arguments) {
			return &PolicyDecision{
				Action:     ActionDeny,
				PolicyName: p.name,
				Severity:   "high",
				Reason:     "secret/token detected in arguments: " + p.name,
			}, nil
		}
	}
	return nil, nil
}

func defaultDLPPatterns() []dlpPattern {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"aws_access_key", `AKIA[0-9A-Z]{16}`},
		{"aws_secret_key", `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`},
		{"github_pat", `ghp_[A-Za-z0-9]{36}`},
		{"github_fine_grained", `github_pat_[A-Za-z0-9_]{82}`},
		{"gitlab_pat", `glpat-[A-Za-z0-9\-]{20}`},
		{"openai_key", `sk-proj-[A-Za-z0-9]{48}`},
		{"anthropic_key", `sk-ant-api03-[A-Za-z0-9\-]{93}`},
		{"stripe_live", `sk_live_[A-Za-z0-9]{24,}`},
		{"slack_bot_token", `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`},
		{"slack_app_token", `xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[a-z0-9]{64}`},
		{"sendgrid_key", `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`},
		{"google_api_key", `AIza[0-9A-Za-z\-_]{35}`},
		{"heroku_api_key", `[hH]eroku[a-zA-Z0-9]{25,}`},
		{"private_key_pem", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
	}

	var compiled []dlpPattern
	for _, p := range patterns {
		re, err := regexp.Compile(p.pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, dlpPattern{name: p.name, re: re})
	}
	return compiled
}

// RateLimitStep checks session-level call rate.
type RateLimitStep struct {
	MaxPerMinute int
}

func (s *RateLimitStep) Name() string { return "rate_limit" }

func (s *RateLimitStep) Evaluate(_ context.Context, req *EnrichedRequest) (*PolicyDecision, error) {
	if req.SessionCtx == nil {
		return nil, nil
	}
	if s.MaxPerMinute > 0 && req.SessionCtx.CallsLastMinute >= s.MaxPerMinute {
		return &PolicyDecision{
			Action:   ActionThrottle,
			Severity: "low",
			Reason:   "rate limit exceeded",
		}, nil
	}
	return nil, nil
}

// SelfProtectStep prevents agents from accessing Aegis internals.
type SelfProtectStep struct{}

func (s *SelfProtectStep) Name() string { return "self_protect" }

func (s *SelfProtectStep) Evaluate(_ context.Context, req *EnrichedRequest) (*PolicyDecision, error) {
	for _, path := range req.Paths {
		lower := strings.ToLower(path)
		if strings.Contains(lower, "aegis.sock") ||
			strings.Contains(lower, "aegis.yaml") ||
			strings.Contains(lower, "/policies/rego/") {
			return &PolicyDecision{
				Action:   ActionDeny,
				Severity: "critical",
				Reason:   "access to aegis internals blocked",
			}, nil
		}
	}
	return nil, nil
}
