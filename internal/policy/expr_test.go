package policy_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

func TestExpr_SimpleVerbCheck(t *testing.T) {
	expr := `"crontab" in verbs`
	evaluator, err := policy.CompileExpr(expr)
	if err != nil {
		t.Fatalf("CompileExpr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"crontab"}
	if !evaluator(bundle) {
		t.Error("should match: crontab in verbs")
	}

	bundle2 := &signals.SignalBundle{}
	bundle2.Command.Verbs = []string{"git"}
	if evaluator(bundle2) {
		t.Error("should not match: git in verbs")
	}
}

func TestExpr_ToolCategoryCheck(t *testing.T) {
	expr := `tool_category == "shell"`
	evaluator, err := policy.CompileExpr(expr)
	if err != nil {
		t.Fatalf("CompileExpr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.ToolClass.Category = "shell"
	if !evaluator(bundle) {
		t.Error("should match: tool_category == shell")
	}

	bundle2 := &signals.SignalBundle{}
	bundle2.ToolClass.Category = "file_read"
	if evaluator(bundle2) {
		t.Error("should not match: tool_category == file_read")
	}
}

func TestExpr_NetworkScoreCheck(t *testing.T) {
	expr := `network_score > 0.5`
	evaluator, err := policy.CompileExpr(expr)
	if err != nil {
		t.Fatalf("CompileExpr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.Network.Score = 0.7
	if !evaluator(bundle) {
		t.Error("should match: network_score 0.7 > 0.5")
	}

	bundle2 := &signals.SignalBundle{}
	bundle2.Network.Score = 0.3
	if evaluator(bundle2) {
		t.Error("should not match: network_score 0.3 > 0.5")
	}
}

func TestExpr_DLPCheck(t *testing.T) {
	expr := `dlp_has_hit && !dlp_all_test`
	evaluator, err := policy.CompileExpr(expr)
	if err != nil {
		t.Fatalf("CompileExpr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.DLP.HasHit = true
	bundle.DLP.AllTest = false
	if !evaluator(bundle) {
		t.Error("should match: dlp hit, not all test")
	}

	bundle2 := &signals.SignalBundle{}
	bundle2.DLP.HasHit = true
	bundle2.DLP.AllTest = true
	if evaluator(bundle2) {
		t.Error("should not match: dlp all test")
	}
}

func TestExpr_MaxVerbDanger(t *testing.T) {
	expr := `max_verb_danger > 0.7`
	evaluator, err := policy.CompileExpr(expr)
	if err != nil {
		t.Fatalf("CompileExpr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.Command.MaxVerbDanger = 0.9
	if !evaluator(bundle) {
		t.Error("should match: max_verb_danger 0.9 > 0.7")
	}
}

func TestExpr_CompileError(t *testing.T) {
	_, err := policy.CompileExpr(`totally invalid ((( expression`)
	if err == nil {
		t.Error("should return error for invalid expression")
	}
}

func TestExpr_IntegrationWithCompiler(t *testing.T) {
	cond := policy.Condition{Expr: `"nc" in verbs`}
	pred, err := policy.Compile(cond)
	if err != nil {
		t.Fatalf("Compile with expr: %v", err)
	}

	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"nc"}
	if !pred(bundle) {
		t.Error("expr condition via Compile() should match nc in verbs")
	}
}

func BenchmarkExpr_SimpleExpr(b *testing.B) {
	evaluator, err := policy.CompileExpr(`"crontab" in verbs && tool_category == "shell"`)
	if err != nil {
		b.Fatalf("CompileExpr: %v", err)
	}
	bundle := &signals.SignalBundle{}
	bundle.Command.Verbs = []string{"crontab"}
	bundle.ToolClass.Category = "shell"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator(bundle)
	}
	// CI gate: must be < 10µs/op
}

func BenchmarkExpr_ComplexExpr(b *testing.B) {
	evaluator, err := policy.CompileExpr(`network_score > 0.5 && dlp_has_hit && max_verb_danger > 0.3`)
	if err != nil {
		b.Fatalf("CompileExpr: %v", err)
	}
	bundle := &signals.SignalBundle{}
	bundle.Network.Score = 0.7
	bundle.DLP.HasHit = true
	bundle.Command.MaxVerbDanger = 0.5

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator(bundle)
	}
}
