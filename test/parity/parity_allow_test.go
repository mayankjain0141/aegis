package parity_test

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

// TestParityAllow verifies that the YAML allow+escalate rules produce identical
// decisions to the legacy Go rules on every eval corpus case.
func TestParityAllow(t *testing.T) {
	allowFile, err := policy.LoadFile("../../policies/phase1-allow.yaml")
	if err != nil {
		t.Fatalf("load phase1-allow.yaml: %v", err)
	}
	escalateFile, err := policy.LoadFile("../../policies/phase1-escalate.yaml")
	if err != nil {
		t.Fatalf("load phase1-escalate.yaml: %v", err)
	}

	allDefs := append(allowFile.Rules, escalateFile.Rules...)
	compiled, err := policy.CompileFile(&policy.PolicyFile{Rules: allDefs})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	ruleNames := make([]string, 0, len(allDefs))
	for _, r := range allDefs {
		ruleNames = append(ruleNames, r.Name)
	}
	legacyRuleSet := filterAllowEscalateLegacyRules(ruleNames)

	corpus := loadAllowCorpus(t)
	if len(corpus) == 0 {
		t.Skip("no eval corpus cases found")
	}

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
				allowRuleName(legacyMatched, legacyRule), legacyMatched,
				allowCompiledRuleName(compiledMatched, compiledRule), compiledMatched,
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

type allowCorpusCase struct {
	id     string
	tool   string
	bundle *signals.SignalBundle
}

func loadAllowCorpus(t *testing.T) []allowCorpusCase {
	t.Helper()
	paths := []string{
		"../../testdata/eval/attacks-native.jsonl",
		"../../testdata/eval/benign.jsonl",
		"../../testdata/eval/edge-cases.jsonl",
	}
	var cases []allowCorpusCase
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
			cases = append(cases, allowCorpusCase{id: id, tool: raw.Tool, bundle: bundle})
		}
	}
	return cases
}

func filterAllowEscalateLegacyRules(names []string) []rules.Rule {
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

func allowRuleName(matched bool, r rules.Rule) string {
	if !matched {
		return "<no match>"
	}
	return r.Name
}

func allowCompiledRuleName(matched bool, r policy.CompiledRuleResult) string {
	if !matched {
		return "<no match>"
	}
	return r.Name
}
