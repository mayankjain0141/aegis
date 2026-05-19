package policy_test

import (
	"strings"
	"testing"

	"github.com/mayjain/aegis/internal/policy"
)

func TestValidate_UnknownField_Suggests(t *testing.T) {
	yaml := `
rules:
  - name: bad
    priority: 10
    action: deny
    severity: critical
    confidence: 0.99
    description: "Bad rule"
    condition:
      verbs: [rm, mkfs]
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for unknown field 'verbs'")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "verbs") {
		t.Errorf("error should mention 'verbs', got: %v", errStr)
	}
	if !strings.Contains(errStr, "any_verb") {
		t.Errorf("error should suggest 'any_verb', got: %v", errStr)
	}
}

func TestValidate_BadAction_ListsValid(t *testing.T) {
	yaml := `
rules:
  - name: bad
    priority: 10
    action: block
    severity: critical
    confidence: 0.99
    description: "Bad action"
    condition:
      any_verb: [rm]
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for invalid action 'block'")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "block") {
		t.Errorf("error should mention 'block', got: %v", errStr)
	}
	if !strings.Contains(errStr, "deny") || !strings.Contains(errStr, "allow") {
		t.Errorf("error should list valid actions (deny, allow, escalate), got: %v", errStr)
	}
}

func TestValidate_BareNumber_SuggestsOperator(t *testing.T) {
	// network.score: 0.5 should be { gt: 0.5 }
	yaml := `
rules:
  - name: bad
    priority: 91
    action: escalate
    severity: medium
    confidence: 0.70
    description: "Bad score"
    condition:
      network:
        score: 0.5
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for bare number in network score")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "gt") && !strings.Contains(errStr, "operator") {
		t.Errorf("error should suggest operator syntax, got: %v", errStr)
	}
}

func TestValidate_MissingDescription_ReturnsError(t *testing.T) {
	yaml := `
rules:
  - name: no_desc
    priority: 10
    action: deny
    severity: critical
    confidence: 0.99
    condition:
      any_verb: [rm]
`
	_, err := policy.LoadString(yaml)
	if err == nil {
		t.Fatal("expected error for missing description")
	}
}
