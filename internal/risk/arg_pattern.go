package risk

import (
	"context"
	"regexp"
)

// ArgPatternSignal detects dangerous patterns in tool arguments via regex.
type ArgPatternSignal struct{}

type dangerPattern struct {
	re    *regexp.Regexp
	score float64
}

var patterns = []dangerPattern{
	// Destructive commands
	{re: regexp.MustCompile(`(?i)\brm\s+(-[a-z]*)?r[a-z]*f`), score: 0.9},
	{re: regexp.MustCompile(`(?i)\bDROP\b`), score: 0.8},
	{re: regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`), score: 0.8},
	{re: regexp.MustCompile(`(?i)\bshutdown\b`), score: 0.8},
	{re: regexp.MustCompile(`(?i)\breboot\b`), score: 0.7},
	{re: regexp.MustCompile(`(?i)\bmkfs\b`), score: 0.9},
	{re: regexp.MustCompile(`(?i)\bdd\s+if=`), score: 0.8},
	// Secrets access
	{re: regexp.MustCompile(`(?i)\.env\b`), score: 0.6},
	{re: regexp.MustCompile(`(?i)\bcredentials\b`), score: 0.6},
	{re: regexp.MustCompile(`(?i)\bprivate_key\b`), score: 0.7},
	{re: regexp.MustCompile(`(?i)\bid_rsa\b`), score: 0.7},
	{re: regexp.MustCompile(`/etc/shadow`), score: 0.8},
	{re: regexp.MustCompile(`/etc/passwd`), score: 0.6},
	// Exfiltration
	{re: regexp.MustCompile(`(?i)curl.*POST`), score: 0.6},
	{re: regexp.MustCompile(`(?i)wget.*\|.*sh`), score: 0.8},
	{re: regexp.MustCompile(`(?i)base64.*decode`), score: 0.5},
}

const maxArgScore = 0.9

func (a ArgPatternSignal) Name() string { return "arg_pattern" }

func (a ArgPatternSignal) Score(_ context.Context, _ string, args string, _ int) float64 {
	if args == "" {
		return 0
	}

	var total float64
	for _, p := range patterns {
		if p.re.MatchString(args) {
			total += p.score
		}
	}

	if total > maxArgScore {
		return maxArgScore
	}
	return total
}
