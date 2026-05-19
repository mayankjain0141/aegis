package signals

import (
	"math"
	"strings"

	"github.com/dmitryikh/leaves"
)

// featureCount is the fixed dimension of the one-hot feature vector fed to the model.
// Changing this requires retraining the model.
const featureCount = 64

// tokenVocab is the ordered vocabulary for one-hot encoding.
// Tokens at index i map to feature i in the vector.
// Tokens beyond index featureCount-2 are ignored; index featureCount-1 is
// a catch-all "has_unknown_token" bit.
var tokenVocab = []string{
	// pipe-to-shell patterns
	"| bash", "| sh", "|bash", "|sh", "| python", "|python",
	// reverse shell primitives
	"nc -e", "ncat -e", "/dev/tcp/", "bash -i", "socat exec",
	// inline eval
	"exec(", "eval(", "system(", "os.system", "__import__", "base64 -d",
	// interpreter -c patterns
	"perl -e", "python -c", "python3 -c", "ruby -e", "node -e",
	// download helpers
	"curl ", "wget ", "fetch ",
	// execution helpers
	"bash ", " sh ", "| sh", "|sh", "exec ",
	// privilege escalation
	"sudo ", "su -", "chmod +s", "chmod 4",
	// persistence patterns
	"crontab", ".bashrc", ".profile", "/etc/cron",
	// obfuscation
	"base64", "xxd", "hex", "\\x", "eval $",
	// data exfiltration patterns
	"> /dev/tcp", "> /dev/udp", "curl -d", "wget --post",
	// process injection
	"/proc/", "ptrace", "LD_PRELOAD",
	// benign prefixes (negative signal)
	"git ", "go ", "npm ", "yarn ", "make ",
	"ls ", "cat ", "mkdir ", "touch ", "grep ",
	"echo ", "cd ", "pwd ", "which ", "find ",
}

// MLScorer scores shell commands for maliciousness.
// When a LightGBM/XGBoost model file is provided and loads successfully,
// it uses leaves for inference. Otherwise it falls back to the heuristic scorer.
type MLScorer struct {
	available bool
	model     *leaves.Ensemble // nil when using heuristic fallback
}

// NewMLScorer creates a scorer. If modelPath is non-empty and refers to a
// valid LightGBM text model file, the scorer uses leaves for inference.
// On any load error it silently falls back to the heuristic — callers need
// not handle errors.
func NewMLScorer(modelPath string) *MLScorer {
	if modelPath != "" {
		if m, err := leaves.LGEnsembleFromFile(modelPath, true); err == nil {
			return &MLScorer{available: true, model: m}
		}
	}
	return &MLScorer{available: true}
}

// Available returns true if the scorer is ready to score.
func (s *MLScorer) Available() bool { return s.available }

// Score returns a maliciousness score in [0.0, 1.0] for the given command string.
// When a model is loaded it predicts from a tokenized feature vector;
// otherwise it uses the built-in heuristic.
func (s *MLScorer) Score(cmd string) float64 {
	if !s.available {
		return 0.0
	}
	if s.model != nil {
		fvals := tokenize(cmd)
		raw := s.model.PredictSingle(fvals, 0)
		// LightGBM binary classification outputs a raw log-odds value;
		// convert to probability with sigmoid.
		return sigmoid(raw)
	}
	return scoreHeuristic(cmd)
}

// tokenize converts a command string into a fixed-length feature vector
// suitable for input to the gradient-boosted tree model.
// Each element is 1.0 if the corresponding token is present in the command,
// 0.0 otherwise. The last element is a catch-all for any unrecognised token.
func tokenize(cmd string) []float64 {
	lower := strings.ToLower(cmd)
	fvals := make([]float64, featureCount)

	knownTokens := len(tokenVocab)
	if knownTokens > featureCount-1 {
		knownTokens = featureCount - 1
	}

	hasUnknown := false
	words := strings.Fields(lower)
	wordSet := make(map[string]bool, len(words))
	for _, w := range words {
		wordSet[w] = true
	}

	for i := 0; i < knownTokens; i++ {
		tok := tokenVocab[i]
		if strings.Contains(lower, tok) {
			fvals[i] = 1.0
		}
	}

	// Mark catch-all if any word is not a substring of any known token.
	for w := range wordSet {
		found := false
		for _, tok := range tokenVocab[:knownTokens] {
			if strings.Contains(tok, w) || strings.Contains(w, tok) {
				found = true
				break
			}
		}
		if !found {
			hasUnknown = true
			break
		}
	}
	if hasUnknown {
		fvals[featureCount-1] = 1.0
	}

	return fvals
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// scoreHeuristic is the original pattern-based scorer used when no model is loaded.
func scoreHeuristic(cmd string) float64 {
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
