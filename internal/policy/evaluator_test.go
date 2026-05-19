package policy_test

import (
	"os"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

func TestPolicyEvaluator_YAMLMode_SystemControl(t *testing.T) {
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
`
	pf, err := policy.LoadString(yamlRules)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	compiled, err := policy.CompileFile(pf)
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}

	eval, err := policy.NewPolicyEvaluator(policy.ModeYAML, compiled)
	if err != nil {
		t.Fatalf("NewPolicyEvaluator: %v", err)
	}
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"shutdown"}
	bundle.ToolClass.Category = "shell"

	rule, matched := eval.Evaluate(bundle)
	if !matched {
		t.Fatal("yaml mode should match system_control rule")
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
	// "legacy" env value now maps to ModeYAML (graceful downgrade)
	os.Setenv("AEGIS_POLICY_MODE", "legacy")
	defer os.Unsetenv("AEGIS_POLICY_MODE")

	mode := policy.ModeFromEnv()
	if mode != policy.ModeYAML {
		t.Errorf("expected ModeYAML for legacy env value (graceful downgrade), got %v", mode)
	}

	os.Setenv("AEGIS_POLICY_MODE", "yaml")
	mode = policy.ModeFromEnv()
	if mode != policy.ModeYAML {
		t.Errorf("expected ModeYAML from env, got %v", mode)
	}

	os.Setenv("AEGIS_POLICY_MODE", "hybrid")
	mode = policy.ModeFromEnv()
	if mode != policy.ModeHybrid {
		t.Errorf("expected ModeHybrid from env, got %v", mode)
	}
}
