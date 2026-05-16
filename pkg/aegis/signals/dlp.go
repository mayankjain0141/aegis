package signals

import (
	"encoding/json"
	"regexp"
	"strings"
)

// DLPSignal is Signal 5: data loss prevention — credential/secret detection.
type DLPSignal struct {
	Hits    []DLPHit
	HasHit  bool
	AllTest bool // true if all hits are test/placeholder keys
	Score   float64
}

// DLPHit is a single credential match.
type DLPHit struct {
	Provider string
	Pattern  string
	IsTest   bool
}

type dlpPattern struct {
	provider    string
	pattern     *regexp.Regexp
	testPattern *regexp.Regexp
}

var dlpPatterns = []dlpPattern{
	{
		provider:    "aws",
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		testPattern: regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE|AKIA_PLACEHOLDER|AKIATEST|AKIAFAKEKEY`),
	},
	{
		provider: "github",
		pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	},
	{
		provider: "github",
		pattern:  regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),
	},
	{
		provider: "github",
		pattern:  regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{82}`),
	},
	{
		provider:    "stripe",
		pattern:     regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
		testPattern: regexp.MustCompile(`sk_test_`),
	},
	{
		provider:    "openai",
		pattern:     regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`),
		testPattern: regexp.MustCompile(`sk-test|sk-fake|sk-placeholder`),
	},
	{
		provider: "anthropic",
		pattern:  regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{40,}`),
	},
	{
		provider: "google",
		pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},
	{
		provider: "slack",
		pattern:  regexp.MustCompile(`xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`),
	},
	{
		provider: "slack",
		pattern:  regexp.MustCompile(`xoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+`),
	},
	{
		provider: "twilio",
		pattern:  regexp.MustCompile(`AC[a-z0-9]{32}`),
	},
	{
		provider: "sendgrid",
		pattern:  regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`),
	},
	{
		provider: "private_key",
		pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	},
}

// testMarkers are substrings that indicate a credential is fake/test.
var testMarkers = []string{
	"placeholder", "example", "test", "fake", "dummy", "sample",
	"your_", "_here", "xxx", "REPLACE_ME", "INSERT_", "<",
}

// ScanDLP scans all string values in tool arguments for credential patterns.
func ScanDLP(argsJSON string) DLPSignal {
	texts := extractAllStrings(argsJSON)
	combined := strings.Join(texts, " ")
	return scanText(combined)
}

func scanText(text string) DLPSignal {
	var sig DLPSignal

	for _, p := range dlpPatterns {
		matches := p.pattern.FindAllString(text, -1)
		for _, match := range matches {
			hit := DLPHit{
				Provider: p.provider,
				Pattern:  p.pattern.String(),
				IsTest:   isTestCredential(match, p.testPattern),
			}
			sig.Hits = append(sig.Hits, hit)
			sig.HasHit = true
		}
	}

	if sig.HasHit {
		sig.AllTest = true
		for _, h := range sig.Hits {
			if !h.IsTest {
				sig.AllTest = false
				break
			}
		}

		if sig.AllTest {
			sig.Score = 0.10
		} else {
			sig.Score = 0.90
		}
	}

	return sig
}

func isTestCredential(match string, testPattern *regexp.Regexp) bool {
	lower := strings.ToLower(match)
	if testPattern != nil && testPattern.MatchString(match) {
		return true
	}
	for _, marker := range testMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func extractAllStrings(argsJSON string) []string {
	// Unmarshal and recursively collect all string values
	var obj any
	if err := json.Unmarshal([]byte(argsJSON), &obj); err != nil {
		// Fall back to treating it as plain text
		return []string{argsJSON}
	}
	var results []string
	collectStrings(obj, &results)
	return results
}

func collectStrings(v any, out *[]string) {
	switch val := v.(type) {
	case string:
		*out = append(*out, val)
	case map[string]any:
		for _, child := range val {
			collectStrings(child, out)
		}
	case []any:
		for _, child := range val {
			collectStrings(child, out)
		}
	}
}
