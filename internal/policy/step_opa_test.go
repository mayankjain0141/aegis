package policy

import (
	"context"
	"testing"

	"github.com/mayjain/aegis/internal/extract"
)

func TestOPAStep_DenyDestructiveOnCriticalPath(t *testing.T) {
	step, err := NewOPAStep(DefaultRegoModule, nil)
	if err != nil {
		t.Fatalf("compile rego: %v", err)
	}

	req := &EnrichedRequest{
		Commands: []extract.Command{{Name: "rm", Args: []string{"-rf", "/etc"}}},
		Paths:    []string{"/etc"},
	}

	decision, err := step.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if decision.Action != ActionDeny {
		t.Errorf("expected deny, got %v", decision.Action)
	}
}

func TestOPAStep_AllowSafeCommand(t *testing.T) {
	step, err := NewOPAStep(DefaultRegoModule, nil)
	if err != nil {
		t.Fatalf("compile rego: %v", err)
	}

	req := &EnrichedRequest{
		Commands: []extract.Command{{Name: "ls", Args: []string{"-la", "/tmp"}}},
		Paths:    []string{"/tmp"},
	}

	decision, err := step.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// /tmp is not a critical path, so OPA should return nil (no opinion)
	if decision != nil {
		t.Errorf("expected nil (no opinion) for safe command, got %v", decision)
	}
}

func TestOPAStep_EscalateOnParseError(t *testing.T) {
	step, err := NewOPAStep(DefaultRegoModule, nil)
	if err != nil {
		t.Fatalf("compile rego: %v", err)
	}

	req := &EnrichedRequest{
		ParseErr: context.DeadlineExceeded,
	}

	decision, err := step.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision == nil {
		t.Fatal("expected decision for parse error, got nil")
	}
	if decision.Action != ActionEscalateHuman {
		t.Errorf("expected escalate_human, got %v", decision.Action)
	}
}

func TestPipeline_FirstDecisionWins(t *testing.T) {
	ext := extract.NewExtractor(nil)
	p := NewPipeline(ext, ActionDeny)

	denyStep, _ := NewOPAStep(DefaultRegoModule, nil)
	p.AddStep(denyStep)

	req := &ToolCallRequest{
		Tool:      "shell_exec",
		Arguments: `{"command": "rm -rf /etc"}`,
	}

	decision, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("pipeline evaluate: %v", err)
	}
	if decision == nil {
		t.Fatal("expected decision from pipeline")
	}
	if decision.Action != ActionDeny {
		t.Errorf("expected deny, got %v", decision.Action)
	}
}

func TestPipeline_FallbackOnNoOpinion(t *testing.T) {
	ext := extract.NewExtractor(nil)
	p := NewPipeline(ext, ActionDeny)

	// No steps added — should return nil (pass to next in chain)
	req := &ToolCallRequest{
		Tool:      "shell_exec",
		Arguments: `{"command": "echo hello"}`,
	}

	decision, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("pipeline evaluate: %v", err)
	}
	// With no steps, pipeline returns nil so chain continues to StaticEvaluator
	if decision != nil {
		t.Errorf("expected nil from empty pipeline, got %v", decision)
	}
}
