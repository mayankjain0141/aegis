package risk

import (
	"context"
	"testing"
)

func TestToolClassification_ReadOps_LowScore(t *testing.T) {
	sig := ToolClassificationSignal{}
	ctx := context.Background()
	for _, tool := range []string{"file_read", "list_files", "web_search"} {
		score := sig.Score(ctx, tool, "", 0)
		if score != 0.05 {
			t.Errorf("tool %s: got %f, want 0.05", tool, score)
		}
	}
}

func TestToolClassification_ShellExec_HighScore(t *testing.T) {
	sig := ToolClassificationSignal{}
	score := sig.Score(context.Background(), "shell_exec", "", 0)
	if score != 0.60 {
		t.Errorf("got %f, want 0.60", score)
	}
}

func TestToolClassification_UnknownTool_DefaultScore(t *testing.T) {
	sig := ToolClassificationSignal{}
	score := sig.Score(context.Background(), "totally_unknown_tool", "", 0)
	if score != 0.50 {
		t.Errorf("got %f, want 0.50", score)
	}
}

func TestArgPattern_RmRf_HighScore(t *testing.T) {
	sig := ArgPatternSignal{}
	score := sig.Score(context.Background(), "", "rm -rf /", 0)
	if score < 0.7 {
		t.Errorf("rm -rf should score high, got %f", score)
	}
}

func TestArgPattern_EnvAccess_HighScore(t *testing.T) {
	sig := ArgPatternSignal{}
	score := sig.Score(context.Background(), "", "cat .env", 0)
	if score < 0.5 {
		t.Errorf(".env access should score >= 0.5, got %f", score)
	}
}

func TestArgPattern_BenignArgs_ZeroScore(t *testing.T) {
	sig := ArgPatternSignal{}
	score := sig.Score(context.Background(), "", "ls -la /home/user", 0)
	if score != 0.0 {
		t.Errorf("benign args should score 0.0, got %f", score)
	}
}

func TestArgPattern_MultipleMatches_HigherScore(t *testing.T) {
	sig := ArgPatternSignal{}
	single := sig.Score(context.Background(), "", "cat .env", 0)
	multi := sig.Score(context.Background(), "", "cat .env && cat /etc/shadow", 0)
	if multi <= single {
		t.Errorf("multiple matches should score higher: single=%f, multi=%f", single, multi)
	}
}

func TestRateSignal_BelowThreshold_Zero(t *testing.T) {
	sig := RateSignal{}
	score := sig.Score(context.Background(), "", "", 5)
	if score != 0.0 {
		t.Errorf("got %f, want 0.0 for 5 calls/min", score)
	}
}

func TestRateSignal_AboveThreshold_High(t *testing.T) {
	sig := RateSignal{}
	score := sig.Score(context.Background(), "", "", 65)
	if score != 0.8 {
		t.Errorf("got %f, want 0.8 for 65 calls/min", score)
	}
}

func TestCompositeScorer_WeightedCombination(t *testing.T) {
	signals := []RiskSignal{
		ToolClassificationSignal{},
		RateSignal{},
	}
	weights := map[string]float64{
		"tool_class": 2.0,
		"rate":       1.0,
	}
	cs := NewCompositeScorer(signals, weights)
	score := cs.Score(context.Background(), "shell_exec", "", 5)
	// tool_class=0.60*2 + rate=0.0*1 = 1.2; total_weight=3; result=0.4
	expected := 0.4
	if !approxEqual(score, expected) {
		t.Errorf("got %f, want %f", score, expected)
	}
}

func TestCompositeScorer_ClampedTo01(t *testing.T) {
	// Use a signal that returns >1 when weighted — shouldn't be possible with
	// our signals, so use a fake one.
	signals := []RiskSignal{fakeSignal{score: 1.5}}
	cs := NewCompositeScorer(signals, nil)
	score := cs.Score(context.Background(), "", "", 0)
	if score != 1.0 {
		t.Errorf("got %f, want 1.0 (clamped)", score)
	}
}

func TestCompositeScorer_DefaultWeights(t *testing.T) {
	signals := []RiskSignal{
		ToolClassificationSignal{},
		RateSignal{},
	}
	cs := NewCompositeScorer(signals, nil)
	score := cs.Score(context.Background(), "file_read", "", 65)
	// tool_class=0.05*1 + rate=0.8*1 = 0.85; total_weight=2; result=0.425
	expected := 0.425
	if !approxEqual(score, expected) {
		t.Errorf("got %f, want %f", score, expected)
	}
}

type fakeSignal struct{ score float64 }

func (f fakeSignal) Name() string { return "fake" }
func (f fakeSignal) Score(_ context.Context, _ string, _ string, _ int) float64 {
	return f.score
}

func approxEqual(a, b float64) bool {
	const eps = 1e-9
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < eps
}
