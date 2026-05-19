package parity_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/mayjain/aegis/pkg/aegis/rules"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

var denyRuleNames = []string{
	"critical_path_destruction", "system_control", "raw_socket_open",
	"privilege_escalation", "critical_path_write", "secret_leakage",
	"sensitive_file_access", "data_exfiltration", "remote_code_execution",
	"suid_manipulation", "cron_persistence", "bashrc_persistence", "execute_from_tmp",
}

func TestParityDeny_AllRulesMatchLegacy(t *testing.T) {
	// Load YAML deny rules
	pf, err := policy.LoadFile("../../policies/phase1-deny.yaml")
	if err != nil {
		t.Fatalf("load deny yaml: %v", err)
	}
	compiled, err := policy.CompileFile(pf)
	if err != nil {
		t.Fatalf("compile deny rules: %v", err)
	}

	// Filter legacy to deny rules only
	legacyFiltered := filterByName(rules.Phase1Rules(), denyRuleNames)

	// Load corpus
	corpus := loadParityCorpus(t)
	if len(corpus) == 0 {
		t.Skip("no corpus cases")
	}

	divergences := 0
	for _, tc := range corpus {
		legacyRule, legacyOk := rules.Evaluate(legacyFiltered, tc)
		compiledResult, compiledOk := policy.EvaluateCompiled(compiled, tc)

		if legacyOk != compiledOk {
			t.Errorf("DIVERGE match: legacy=%v compiled=%v bundle=%+v", legacyOk, compiledOk, summarize(tc))
			divergences++
			continue
		}
		if legacyOk && compiledOk {
			if legacyRule.Name != compiledResult.Name || string(legacyRule.Action) != compiledResult.Action {
				t.Errorf("DIVERGE rule: legacy=%s/%s compiled=%s/%s bundle=%+v",
					legacyRule.Name, legacyRule.Action, compiledResult.Name, compiledResult.Action, summarize(tc))
				divergences++
			}
		}
	}
	if divergences == 0 {
		t.Logf("Parity OK: %d corpus cases, 0 divergences for deny rules", len(corpus))
	}
}

func filterByName(allRules []rules.Rule, names []string) []rules.Rule {
	set := make(map[string]bool)
	for _, n := range names {
		set[n] = true
	}
	var filtered []rules.Rule
	for _, r := range allRules {
		if set[r.Name] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func summarize(b *signals.SignalBundle) string {
	return fmt.Sprintf("cat=%s verbs=%v crit=%v sens=%v", b.ToolClass.Category, b.Command.Verbs, b.Path.HasCritical, b.Path.HasSensitive)
}

func loadParityCorpus(t *testing.T) []*signals.SignalBundle {
	t.Helper()
	eng, _ := aegis.NewEngine()
	var bundles []*signals.SignalBundle
	paths := []string{
		"../../testdata/eval/attacks-native.jsonl",
		"../../testdata/eval/benign.jsonl",
		"../../testdata/eval/edge-cases.jsonl",
	}
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
					json.Unmarshal([]byte(argsStr), &argsMap)
				}
			}
			if argsMap == nil {
				continue
			}
			argsJSON, _ := json.Marshal(argsMap)
			_ = context.Background()
			bundle := eng.ComputeSignals(raw.Tool, string(argsJSON), "/tmp")
			bundles = append(bundles, bundle)
		}
	}
	return bundles
}
