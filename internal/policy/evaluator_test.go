package policy_test

import (
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

func TestPolicyEvaluator_LegacyMode(t *testing.T) {
	eval, err := policy.NewPolicyEvaluator(policy.ModeLegacy, nil)
	if err != nil {
		t.Fatalf("NewPolicyEvaluator: %v", err)
	}
	// system_control rule: shutdown with shell category should deny
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"shutdown"}
	bundle.ToolClass.Category = "shell"

	rule, matched := eval.Evaluate(bundle)
	if !matched {
		t.Fatal("legacy mode should match system_control rule")
	}
	if rule.Name != "system_control" {
		t.Errorf("expected system_control, got %q", rule.Name)
	}
	if string(rule.Action) != "deny" {
		t.Errorf("expected deny, got %q", rule.Action)
	}
}

func TestPolicyEvaluator_YAMLMode_RequiresRules(t *testing.T) {
	// YAML mode with nil compiled rules should return no match (no rules loaded)
	eval, err := policy.NewPolicyEvaluator(policy.ModeYAML, []policy.CompiledRule{})
	if err != nil {
		t.Fatalf("NewPolicyEvaluator: %v", err)
	}
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"shutdown"}
	bundle.ToolClass.Category = "shell"

	_, matched := eval.Evaluate(bundle)
	if matched {
		t.Error("YAML mode with empty rules should not match")
	}
}

func TestPolicyEvaluator_HybridMode(t *testing.T) {
	// Hybrid mode: YAML rules take precedence on name collision, legacy fills gaps
	yamlRules := `
rules:
  - name: raw_socket_open
    priority: 12
    action: deny
    severity: high
    confidence: 0.95
    description: "YAML version of raw_socket_open"
    condition:
      any_verb: [nc, ncat, socat, telnet]
`
	pf, _ := policy.LoadString(yamlRules)
	compiled, _ := policy.CompileFile(pf)

	eval, err := policy.NewPolicyEvaluator(policy.ModeHybrid, compiled)
	if err != nil {
		t.Fatalf("NewPolicyEvaluator: %v", err)
	}

	// nc should match via YAML rule (not legacy)
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"nc"}
	rule, matched := eval.Evaluate(bundle)
	if !matched {
		t.Fatal("hybrid mode should match raw_socket_open")
	}
	if rule.Name != "raw_socket_open" {
		t.Errorf("got %q, want raw_socket_open", rule.Name)
	}
}

func TestPolicyEvaluator_EnvVarSwitch(t *testing.T) {
	// AEGIS_POLICY_MODE env var controls mode
	os.Setenv("AEGIS_POLICY_MODE", "legacy")
	defer os.Unsetenv("AEGIS_POLICY_MODE")

	mode := policy.ModeFromEnv()
	if mode != policy.ModeLegacy {
		t.Errorf("expected ModeLegacy from env, got %v", mode)
	}

	os.Setenv("AEGIS_POLICY_MODE", "yaml")
	mode = policy.ModeFromEnv()
	if mode != policy.ModeYAML {
		t.Errorf("expected ModeYAML from env, got %v", mode)
	}
}
