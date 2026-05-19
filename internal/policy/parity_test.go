package policy_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// TestParity_5Rules verifies that 5 compiled YAML rules produce identical decisions
// to the legacy Go rules on every eval corpus case.
func TestParity_5Rules(t *testing.T) {
	yamlRules := `
rules:
  - name: system_control
    priority: 11
    action: deny
    severity: critical
    confidence: 0.99
    description: "Command attempts system control"
    condition:
      and:
        - any_verb: [shutdown, reboot, halt, poweroff]
        - tool_category: shell

  - name: secret_leakage
    priority: 15
    action: deny
    severity: high
    confidence: 0.95
    description: "Command contains sensitive credentials"
    condition:
      and:
        - dlp:
            has_hit: true
            all_test: false

  - name: remote_code_execution
    priority: 18
    action: deny
    severity: critical
    confidence: 0.95
    description: "Command downloads and executes remote code"
    condition:
      and:
        - evasion:
            encoding_detected: true
        - tool_category: shell

  - name: benign_read_only
    priority: 50
    action: allow
    severity: ""
    confidence: 0.99
    description: "Read-only operations within the project"
    condition:
      or:
        - and:
            - tool_category: file_read
            - path:
                all_in_project: true
        - and:
            - tool_category: search
            - path:
                all_in_project: true

  - name: raw_socket_open
    priority: 12
    action: deny
    severity: high
    confidence: 0.95
    description: "Command opens a raw network socket"
    condition:
      any_verb: [nc, ncat, socat, telnet]
`
	pf, err := policy.LoadString(yamlRules)
	if err != nil {
		t.Fatalf("load yaml rules: %v", err)
	}

	compiled, err := policy.CompileFile(pf)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	corpus := loadCorpus(t)
	if len(corpus) == 0 {
		t.Skip("no eval corpus cases found")
	}

	legacyRuleSet := filterLegacyRules([]string{"system_control", "secret_leakage", "remote_code_execution", "benign_read_only", "raw_socket_open"})

	var divergences []string
	for _, tc := range corpus {
		legacyRule, legacyMatched := rules.Evaluate(legacyRuleSet, tc.bundle)
		compiledRule, compiledMatched := policy.EvaluateCompiled(compiled, tc.bundle)

		if !legacyMatched && !compiledMatched {
			continue
		}

		if legacyMatched != compiledMatched ||
			(legacyMatched && compiledMatched && (legacyRule.Name != compiledRule.Name || string(legacyRule.Action) != compiledRule.Action)) {
			divergences = append(divergences, fmt.Sprintf(
				"[%s tool=%s] legacy=%s/%v compiled=%s/%v",
				tc.id, tc.tool,
				ruleName(legacyMatched, legacyRule), legacyMatched,
				compiledRuleName(compiledMatched, compiledRule), compiledMatched,
			))
		}
	}
	if len(divergences) > 0 {
		for _, d := range divergences {
			t.Error("DIVERGENCE:", d)
		}
		t.Fatalf("%d/%d cases diverged", len(divergences), len(corpus))
	}
	t.Logf("Parity OK: %d corpus cases checked, 0 divergences", len(corpus))
}

type corpusCase struct {
	id     string
	tool   string
	bundle *signals.SignalBundle
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	paths := []string{
		"../../testdata/eval/attacks-native.jsonl",
		"../../testdata/eval/benign.jsonl",
		"../../testdata/eval/edge-cases.jsonl",
	}
	var cases []corpusCase
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				continue
			}
			var raw struct {
				ID        string          `json:"id"`
				Tool      string          `json:"tool"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				continue
			}
			var argsMap map[string]any
			if err := json.Unmarshal(raw.Arguments, &argsMap); err != nil {
				var argsStr string
				if err2 := json.Unmarshal(raw.Arguments, &argsStr); err2 == nil {
					json.Unmarshal([]byte(argsStr), &argsMap) //nolint:errcheck
				}
			}
			if argsMap == nil {
				continue
			}
			argsJSON, _ := json.Marshal(argsMap)
			eng, _ := aegis.NewEngine()
			bundle := eng.ComputeSignals(raw.Tool, string(argsJSON), "/tmp")
			id := raw.ID
			if id == "" {
				id = fmt.Sprintf("line-%d", len(cases))
			}
			cases = append(cases, corpusCase{id: id, tool: raw.Tool, bundle: bundle})
		}
	}
	return cases
}

func filterLegacyRules(names []string) []rules.Rule {
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	var filtered []rules.Rule
	for _, r := range rules.Phase1Rules() {
		if nameSet[r.Name] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func ruleName(matched bool, r rules.Rule) string {
	if !matched {
		return "<no match>"
	}
	return r.Name
}

func compiledRuleName(matched bool, r policy.CompiledRuleResult) string {
	if !matched {
		return "<no match>"
	}
	return r.Name
}
