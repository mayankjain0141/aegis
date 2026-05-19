package signals

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
)

// xgbTree is a single decision tree from the XGBoost JSON model.
type xgbTree struct {
	LeftChildren    []int     `json:"left_children"`
	RightChildren   []int     `json:"right_children"`
	SplitIndices    []int     `json:"split_indices"`
	SplitConditions []float64 `json:"split_conditions"`
	DefaultLeft     []int     `json:"default_left"`
}

// xgbModel is the parsed top-level XGBoost JSON structure.
type xgbModel struct {
	Trees      []xgbTree
	NFeatures  int
	BaseMargin float64
}

// xgbModelJSON mirrors the JSON structure from quasarnix.json.
type xgbModelJSON struct {
	Learner struct {
		LearnerModelParam struct {
			NumFeature string `json:"num_feature"`
			BaseScore  string `json:"base_score"`
		} `json:"learner_model_param"`
		GradientBooster struct {
			Model struct {
				Trees []xgbTree `json:"trees"`
			} `json:"model"`
		} `json:"gradient_booster"`
	} `json:"learner"`
}

// MLScorer scores shell commands for maliciousness using the QuasarNix XGBoost model.
// Falls back to a heuristic when model files are not available.
type MLScorer struct {
	available    bool
	UseHeuristic bool
	model        *xgbModel
	vocab        map[string]int
}

// scorerCache is a package-level singleton so the model is loaded once.
var (
	defaultScorer     *MLScorer
	defaultScorerOnce sync.Once
)

// NewMLScorer creates an MLScorer. modelPath and vocabPath may be "" to use defaults.
// Falls back to heuristic scoring when model files are absent.
func NewMLScorer(modelPath, vocabPath string) *MLScorer {
	if modelPath == "" || vocabPath == "" {
		// Try default paths relative to common working directories.
		candidates := []struct{ model, vocab string }{
			{
				"pkg/aegis/signals/models/quasarnix.json",
				"pkg/aegis/signals/models/quasarnix_vocab.json",
			},
			{
				"../../pkg/aegis/signals/models/quasarnix.json",
				"../../pkg/aegis/signals/models/quasarnix_vocab.json",
			},
			{
				"models/quasarnix.json",
				"models/quasarnix_vocab.json",
			},
		}
		for _, c := range candidates {
			if _, err := os.Stat(c.model); err == nil {
				if _, err := os.Stat(c.vocab); err == nil {
					modelPath = c.model
					vocabPath = c.vocab
					break
				}
			}
		}
	}

	if modelPath == "" || vocabPath == "" {
		// No model files found — use heuristic.
		return &MLScorer{available: true, UseHeuristic: true}
	}

	model, err := loadXGBModel(modelPath)
	if err != nil {
		return &MLScorer{available: true, UseHeuristic: true}
	}
	vocab, err := LoadVocab(vocabPath)
	if err != nil {
		return &MLScorer{available: true, UseHeuristic: true}
	}

	return &MLScorer{
		available:    true,
		UseHeuristic: false,
		model:        model,
		vocab:        vocab,
	}
}

// Available returns true when the scorer is ready.
func (s *MLScorer) Available() bool { return s.available }

// Score returns a maliciousness score [0.0, 1.0] for the given command string.
func (s *MLScorer) Score(cmd string) float64 {
	if !s.available {
		return 0.0
	}
	if s.UseHeuristic {
		return scoreCommand(cmd)
	}
	return s.scoreWithModel(cmd)
}

func (s *MLScorer) scoreWithModel(cmd string) float64 {
	features := s.encode(cmd)

	margin := s.model.BaseMargin
	for i := range s.model.Trees {
		margin += predictTree(&s.model.Trees[i], features)
	}
	return 1.0 / (1.0 + math.Exp(-margin)) // sigmoid
}

// encode converts a command string to a one-hot feature vector using char n-grams.
// Absent tokens are represented as NaN (goes RIGHT in XGBoost tree traversal).
func (s *MLScorer) encode(cmd string) []float64 {
	features := make([]float64, s.model.NFeatures)
	for i := range features {
		features[i] = math.NaN() // absent = NaN (goes RIGHT in tree)
	}
	for _, tok := range tokenizeNgram(cmd) {
		if idx, ok := s.vocab[tok]; ok && idx < len(features) {
			features[idx] = 1.0
		}
	}
	return features
}

// predictTree traverses a single XGBoost decision tree.
func predictTree(tree *xgbTree, features []float64) float64 {
	node := 0
	for tree.LeftChildren[node] != -1 { // not a leaf
		fidx := tree.SplitIndices[node]
		val := features[fidx]
		var goLeft bool
		if math.IsNaN(val) {
			goLeft = tree.DefaultLeft[node] == 1
		} else {
			goLeft = val < tree.SplitConditions[node]
		}
		if goLeft {
			node = tree.LeftChildren[node]
		} else {
			node = tree.RightChildren[node]
		}
	}
	return tree.SplitConditions[node] // leaf value
}

// tokenizeNgram generates deduplicated character n-grams of length 1–3 from cmd.
func tokenizeNgram(cmd string) []string {
	seen := make(map[string]bool)
	var tokens []string
	for i := range cmd {
		for l := 1; l <= 3; l++ {
			end := i + l
			if end > len(cmd) {
				break
			}
			tok := cmd[i:end]
			if !seen[tok] {
				seen[tok] = true
				tokens = append(tokens, tok)
			}
		}
	}
	return tokens
}

// LoadVocab reads the vocab JSON file: map[string]int (token → feature index).
func LoadVocab(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vocab %s: %w", path, err)
	}
	var vocab map[string]int
	if err := json.Unmarshal(data, &vocab); err != nil {
		return nil, fmt.Errorf("parse vocab: %w", err)
	}
	if len(vocab) == 0 {
		return nil, fmt.Errorf("vocab is empty")
	}
	return vocab, nil
}

// loadXGBModel reads and parses the XGBoost JSON model.
func loadXGBModel(path string) (*xgbModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read model %s: %w", path, err)
	}
	var raw xgbModelJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse model JSON: %w", err)
	}

	// Parse num_feature (stored as string "4096").
	var nFeatures int
	fmt.Sscanf(raw.Learner.LearnerModelParam.NumFeature, "%d", &nFeatures)
	if nFeatures == 0 {
		return nil, fmt.Errorf("model has 0 features")
	}

	// Parse base_score (stored as "[4.999895E-1]" — strip brackets).
	baseScoreStr := strings.Trim(raw.Learner.LearnerModelParam.BaseScore, "[]")
	var baseScore float64
	fmt.Sscanf(baseScoreStr, "%f", &baseScore)
	if baseScore <= 0 || baseScore >= 1 {
		baseScore = 0.5 // safe default
	}
	baseMargin := math.Log(baseScore / (1 - baseScore)) // logit transform

	trees := raw.Learner.GradientBooster.Model.Trees
	if len(trees) == 0 {
		return nil, fmt.Errorf("model has no trees")
	}

	return &xgbModel{
		Trees:      trees,
		NFeatures:  nFeatures,
		BaseMargin: baseMargin,
	}, nil
}

// scoreCommand is the heuristic fallback when no model is loaded.
// Kept for graceful degradation when model files are unavailable.
func scoreCommand(cmd string) float64 {
	lower := strings.ToLower(cmd)
	score := 0.0

	if matchesAny(lower, []string{"| bash", "| sh", "|bash", "|sh", "| python", "|python", "curl", "wget"}) {
		if matchesAny(lower, []string{"| bash", "|bash", "| sh", "|sh", "| python", "|python"}) {
			score += 0.7
		}
	}
	if matchesAny(lower, []string{"nc -e", "nc -l", "ncat -e", "/dev/tcp/", "bash -i", "socat.*exec"}) {
		score += 0.8
	}
	if matchesAny(lower, []string{"exec(", "eval(", "system(", "os.system", "subprocess", "__import__", "base64.decode", "base64 -d"}) {
		score += 0.5
	}
	hasFetch := containsAny(lower, []string{"curl ", "wget ", "fetch "})
	hasExec := containsAny(lower, []string{"bash", "sh", "exec", "python", "perl", "ruby"})
	if hasFetch && hasExec {
		score += 0.4
	}
	if matchesAny(lower, []string{"perl -e", "python -c", "python3 -c", "ruby -e", "node -e"}) {
		score += 0.4
	}
	benignVerbs := []string{"git ", "go ", "npm ", "yarn ", "make ", "ls ", "cat ", "cd ", "mkdir ", "touch "}
	for _, v := range benignVerbs {
		if strings.HasPrefix(lower, v) || strings.Contains(lower, " && "+v) {
			score -= 0.3
			break
		}
	}
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
