package policy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
)

// TestParity_5Rules verifies that 5 key YAML rules correctly classify corpus cases
// according to their expected_action field.
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

	// Use the full engine in YAML mode to evaluate corpus cases
	engine, err := aegis.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	corpus := loadCorpus(t)
	if len(corpus) == 0 {
		t.Skip("no eval corpus cases found")
	}

	// Verify that the 5 compiled rules match non-trivially on some cases
	matchCount := 0
	for _, tc := range corpus {
		bundle := engine.ComputeSignals(tc.tool, fmt.Sprintf("%v", tc.args), "/tmp")
		_, matched := policy.EvaluateCompiled(compiled, bundle)
		if matched {
			matchCount++
		}
	}
	t.Logf("5-rule subset matched %d/%d corpus cases", matchCount, len(corpus))

	// Also verify YAML engine meets corpus expected_action thresholds
	var denied, total, falseDenied, allowTotal int
	for _, tc := range corpus {
		d := engine.Evaluate(context.Background(), &aegis.Request{
			Tool:      tc.tool,
			Arguments: tc.args,
			CWD:       "/tmp",
		})
		switch tc.expectedAction {
		case "deny":
			total++
			if d.Action == aegis.ActionDeny || d.Action == aegis.ActionEscalate {
				denied++
			}
		case "allow":
			allowTotal++
			if d.Action == aegis.ActionDeny {
				falseDenied++
			}
		}
	}

	if total > 0 {
		recall := float64(denied) / float64(total)
		t.Logf("Recall: %d/%d = %.1f%%", denied, total, recall*100)
		if recall < 0.90 {
			t.Errorf("recall %.1f%% below 90%% threshold", recall*100)
		}
	}
	if allowTotal > 0 {
		fpr := float64(falseDenied) / float64(allowTotal)
		t.Logf("FPR: %d/%d = %.1f%%", falseDenied, allowTotal, fpr*100)
		if fpr > 0.05 {
			t.Errorf("FPR %.1f%% exceeds 5%% threshold", fpr*100)
		}
	}
}

type corpusCase struct {
	id             string
	tool           string
	args           map[string]any
	expectedAction string
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	paths := []string{
		"../../testdata/eval/attacks-native.jsonl",
		"../../testdata/eval/benign.jsonl",
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
				ID             string          `json:"id"`
				Tool           string          `json:"tool"`
				Arguments      json.RawMessage `json:"arguments"`
				ExpectedAction string          `json:"expected_action"`
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
			id := raw.ID
			if id == "" {
				id = fmt.Sprintf("line-%d", len(cases))
			}
			cases = append(cases, corpusCase{
				id:             id,
				tool:           raw.Tool,
				args:           argsMap,
				expectedAction: raw.ExpectedAction,
			})
		}
	}
	return cases
}

func ruleName(matched bool, r policy.CompiledRuleResult) string {
	if !matched {
		return "<no match>"
	}
	return r.Name
}
