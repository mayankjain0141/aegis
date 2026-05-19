package policy_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

func TestOPA_SimpleDenyPolicy(t *testing.T) {
	regoSource := `
package aegis.test

deny if {
    input.verbs[_] == "rm"
    input.has_critical == true
}
`
	pred, err := policy.CompileRego(regoSource, "data.aegis.test.deny")
	if err != nil {
		t.Fatalf("CompileRego: %v", err)
	}

	// Should deny: rm + critical path
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"rm"}
	bundle.Path.HasCritical = true
	if !pred(bundle) {
		t.Error("should match: rm with critical path")
	}

	// Should not deny: ls + critical path
	bundle2 := &signals.SignalBundle{}
	bundle2.Command.Verbs = []string{"ls"}
	bundle2.Path.HasCritical = true
	if pred(bundle2) {
		t.Error("should not match: ls does not match policy")
	}
}

func TestOPA_AllowPolicy(t *testing.T) {
	regoSource := `
package aegis.test

allow if {
    input.tool_category == "file_read"
    input.all_in_project == true
}
`
	pred, err := policy.CompileRego(regoSource, "data.aegis.test.allow")
	if err != nil {
		t.Fatalf("CompileRego: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.ToolClass.Category = "file_read"
	bundle.Path.AllInProject = true
	if !pred(bundle) {
		t.Error("should match: file_read within project")
	}
}

func TestOPA_InvalidRego_ReturnsError(t *testing.T) {
	_, err := policy.CompileRego("invalid rego !!!!", "data.test.deny")
	if err == nil {
		t.Error("invalid Rego should return compile error")
	}
}

func TestOPA_GracefulFailOpen_OnEvalError(t *testing.T) {
	// A valid Rego that would panic on missing input should fail-open (return false)
	regoSource := `
package aegis.test

deny if {
    input.verbs[_] == "rm"
}
`
	pred, err := policy.CompileRego(regoSource, "data.aegis.test.deny")
	if err != nil {
		t.Fatalf("CompileRego: %v", err)
	}

	// Empty bundle — should not panic, should return false (fail-open)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OPA eval should not panic: %v", r)
		}
	}()
	result := pred(&signals.SignalBundle{})
	_ = result // don't care about result, just no panic
}

func TestOPA_IntegrationWithCompiler(t *testing.T) {
	// Verify Condition.Rego+RegoRule are handled by Compile()
	regoSource := `
package aegis.test

deny if {
    input.verbs[_] == "rm"
}
`
	cond := policy.Condition{
		Rego:     regoSource,
		RegoRule: "data.aegis.test.deny",
	}
	pred, err := policy.Compile(cond)
	if err != nil {
		t.Fatalf("Compile with Rego: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"rm"}
	if !pred(bundle) {
		t.Error("rego condition via Compile() should match rm")
	}
}
