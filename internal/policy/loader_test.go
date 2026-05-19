package policy_test

import (
	"strings"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
)

func TestLoad_WellFormed(t *testing.T) {
	yaml := `
rules:
  - name: system_control
    priority: 11
    action: deny
    severity: critical
    confidence: 0.99
    description: "Command attempts system control"
    condition:
      any_verb: [shutdown, reboot, halt, poweroff]
      tool_category: shell
`
	file, err := policy.LoadString(yaml)
	if err != nil {
		t.Fatalf("LoadString failed: %v", err)
	}
	if len(file.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(file.Rules))
	}
	r := file.Rules[0]
	if r.Name != "system_control" {
		t.Errorf("name: got %q, want system_control", r.Name)
	}
	if r.Action != "deny" {
		t.Errorf("action: got %q, want deny", r.Action)
	}
	if r.Priority != 11 {
		t.Errorf("priority: got %d, want 11", r.Priority)
	}
}

func TestLoad_MissingRequiredField_ReturnsError(t *testing.T) {
	yaml := `
rules:
  - name: bad_rule
    priority: 10
    # missing action
    condition:
      any_verb: [rm]
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for missing action, got nil")
	}
	if !strings.Contains(err.Error(), "action") {
		t.Errorf("error should mention 'action', got: %v", err)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	yaml := `
rules:
  - name: raw_socket_open
    priority: 12
    action: deny
    severity: high
    confidence: 0.95
    description: "Blocks raw socket commands"
    condition:
      any_verb: [nc, ncat, socat, telnet]
`
	file1, err := policy.LoadString(yaml)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	// Round-trip: the parsed struct should be re-serializable and re-parseable
	// (we just verify the data is intact)
	if file1.Rules[0].Condition.AnyVerb == nil {
		t.Error("AnyVerb condition should be populated")
	}
	if len(file1.Rules[0].Condition.AnyVerb) != 4 {
		t.Errorf("expected 4 verbs, got %d", len(file1.Rules[0].Condition.AnyVerb))
	}
}

func TestLoad_MultipleRules(t *testing.T) {
	yaml := `
rules:
  - name: deny_one
    priority: 10
    action: deny
    severity: critical
    confidence: 0.99
    description: "First rule"
    condition:
      any_verb: [rm]
  - name: allow_one
    priority: 50
    action: allow
    severity: ""
    confidence: 0.95
    description: "Second rule"
    condition:
      tool_category: file_read
`
	file, err := policy.LoadString(yaml)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	if len(file.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(file.Rules))
	}
}

func TestLoad_DuplicateRuleName_ReturnsError(t *testing.T) {
	yaml := `
rules:
  - name: dup
    priority: 10
    action: deny
    severity: critical
    confidence: 0.99
    description: "First"
    condition:
      any_verb: [rm]
  - name: dup
    priority: 20
    action: allow
    severity: ""
    confidence: 0.90
    description: "Second"
    condition:
      tool_category: file_read
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for duplicate name, got nil")
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("error should mention the duplicate name, got: %v", err)
	}
}
