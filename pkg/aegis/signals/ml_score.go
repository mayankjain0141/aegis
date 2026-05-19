package signals

import (
	"math"
	"strings"
)

// MLScorer scores shell commands for maliciousness using a heuristic feature table.
type MLScorer struct {
	available bool
}

// NewMLScorer creates a scorer. modelPath is reserved for future ONNX loading.
func NewMLScorer(modelPath string) *MLScorer {
	return &MLScorer{available: true}
}

// Available returns true if the scorer is ready.
func (s *MLScorer) Available() bool { return s.available }

// Score returns a maliciousness score [0.0, 1.0] for the given command string.
func (s *MLScorer) Score(cmd string) float64 {
	if !s.available {
		return 0.0
	}
	return scoreCommand(cmd)
}

func scoreCommand(cmd string) float64 {
	lower := strings.ToLower(cmd)
	score := 0.0

	if containsAny(lower, []string{"| bash", "| sh", "|bash", "|sh", "| python", "|python"}) {
		score += 0.7
	}
	if containsAny(lower, []string{"nc -e", "ncat -e", "/dev/tcp/", "bash -i", "socat exec"}) {
		score += 0.8
	}
	if containsAny(lower, []string{"exec(", "eval(", "system(", "os.system", "__import__", "base64 -d"}) {
		score += 0.5
	}
	if containsAny(lower, []string{"perl -e", "python -c", "python3 -c", "ruby -e", "node -e"}) {
		score += 0.75
	}
	hasFetch := containsAny(lower, []string{"curl ", "wget ", "fetch "})
	hasExec := containsAny(lower, []string{"bash", " sh ", " sh\n", "| sh", "|sh", "exec", "python", "perl"})
	if hasFetch && hasExec {
		score += 0.4
	}
	benignPrefixes := []string{"git ", "go ", "npm ", "yarn ", "make ", "ls ", "cat ", "mkdir ", "touch "}
	for _, p := range benignPrefixes {
		if strings.HasPrefix(lower, p) {
			score -= 0.3
			break
		}
	}
	return math.Max(0.0, math.Min(1.0, score))
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
