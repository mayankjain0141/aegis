package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mayjain/aegis/internal/policy"
)

type TestCase struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Tool           string `json:"tool"`
	Arguments      string `json:"arguments"`
	ExpectedAction string `json:"expected_action"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Difficulty     string `json:"difficulty"`
}

type CaseResult struct {
	TestCase
	GotAction string
	Latency   time.Duration
	IsTP      bool
	IsFP      bool
	IsFN      bool
	IsTN      bool
}

type BenchResult struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`

	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	FPRate    float64 `json:"fp_rate"`

	TotalCases   int           `json:"total_cases"`
	AvgLatency   time.Duration `json:"avg_latency_ns"`
	TotalLatency time.Duration `json:"total_latency_ns"`

	FalseNegatives []CaseResult          `json:"false_negatives,omitempty"`
	FalsePositives []CaseResult          `json:"false_positives,omitempty"`
	Categories     map[string]*CatResult `json:"categories"`
}

type CatResult struct {
	Total   int     `json:"total"`
	Correct int     `json:"correct"`
	Rate    float64 `json:"rate"`
}

func main() {
	corpus := flag.String("corpus", "testdata/eval/", "directory containing .jsonl test files")
	category := flag.String("category", "", "filter to a single category")
	verbose := flag.Bool("verbose", false, "show per-case results")
	jsonOut := flag.Bool("json", false, "output as JSON")
	threshold := flag.Float64("threshold", 0.9, "minimum recall to pass (exit 0)")
	flag.Parse()

	cases, err := loadCorpus(*corpus, *category)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading corpus: %v\n", err)
		os.Exit(2)
	}
	if len(cases) == 0 {
		fmt.Fprintf(os.Stderr, "no test cases found in %s\n", *corpus)
		os.Exit(2)
	}

	p := buildPipeline()
	results := evaluate(p, cases)
	bench := computeMetrics(results)

	if *jsonOut {
		printJSON(bench)
	} else {
		printTable(bench, *verbose)
	}

	if bench.Recall < *threshold {
		os.Exit(1)
	}
}

func buildPipeline() *policy.Pipeline {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return policy.BuildDefaultPipeline("policies/data/commands.yaml", logger)
}

func loadCorpus(dir, categoryFilter string) ([]TestCase, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading corpus directory %q: %w", dir, err)
	}

	var cases []TestCase
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fileCases, err := loadJSONLFile(path)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		cases = append(cases, fileCases...)
	}

	if categoryFilter != "" {
		var filtered []TestCase
		for _, tc := range cases {
			if tc.Category == categoryFilter {
				filtered = append(filtered, tc)
			}
		}
		cases = filtered
	}

	return cases, nil
}

func loadJSONLFile(path string) ([]TestCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cases []TestCase
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var tc TestCase
		if err := json.Unmarshal([]byte(line), &tc); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		cases = append(cases, tc)
	}
	return cases, scanner.Err()
}

func evaluate(p *policy.Pipeline, cases []TestCase) []CaseResult {
	results := make([]CaseResult, 0, len(cases))
	for _, tc := range cases {
		req := &policy.ToolCallRequest{
			Tool:      tc.Tool,
			Arguments: tc.Arguments,
			AgentID:   "eval-bench",
		}

		start := time.Now()
		decision, _ := p.Evaluate(context.Background(), req)
		elapsed := time.Since(start)

		gotAction := "allow"
		if decision != nil {
			gotAction = string(decision.Action)
		}

		r := CaseResult{
			TestCase:  tc,
			GotAction: gotAction,
			Latency:   elapsed,
		}

		expectBlocked := isBlockedAction(tc.ExpectedAction)
		actuallyBlocked := isBlockedAction(gotAction)

		switch {
		case expectBlocked && actuallyBlocked:
			r.IsTP = true
		case !expectBlocked && actuallyBlocked:
			r.IsFP = true
		case expectBlocked && !actuallyBlocked:
			r.IsFN = true
		case !expectBlocked && !actuallyBlocked:
			r.IsTN = true
		}

		results = append(results, r)
	}
	return results
}

func isBlockedAction(action string) bool {
	switch action {
	case "deny", "escalate_human", "throttle":
		return true
	default:
		return false
	}
}

func computeMetrics(results []CaseResult) *BenchResult {
	b := &BenchResult{
		Categories: make(map[string]*CatResult),
	}

	var totalLatency time.Duration
	for _, r := range results {
		totalLatency += r.Latency

		switch {
		case r.IsTP:
			b.TP++
		case r.IsFP:
			b.FP++
		case r.IsFN:
			b.FN++
		case r.IsTN:
			b.TN++
		}

		if r.IsFN {
			b.FalseNegatives = append(b.FalseNegatives, r)
		}
		if r.IsFP {
			b.FalsePositives = append(b.FalsePositives, r)
		}

		cat, ok := b.Categories[r.Category]
		if !ok {
			cat = &CatResult{}
			b.Categories[r.Category] = cat
		}
		cat.Total++
		if r.IsTP || r.IsTN {
			cat.Correct++
		}
	}

	b.TotalCases = len(results)
	b.TotalLatency = totalLatency
	if b.TotalCases > 0 {
		b.AvgLatency = totalLatency / time.Duration(b.TotalCases)
	}

	if b.TP+b.FP > 0 {
		b.Precision = float64(b.TP) / float64(b.TP+b.FP)
	}
	if b.TP+b.FN > 0 {
		b.Recall = float64(b.TP) / float64(b.TP+b.FN)
	}
	if b.Precision+b.Recall > 0 {
		b.F1 = 2 * b.Precision * b.Recall / (b.Precision + b.Recall)
	}
	if b.FP+b.TN > 0 {
		b.FPRate = float64(b.FP) / float64(b.FP+b.TN)
	}

	for _, cat := range b.Categories {
		if cat.Total > 0 {
			cat.Rate = float64(cat.Correct) / float64(cat.Total)
		}
	}

	return b
}

func printJSON(b *BenchResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(b)
}

func printTable(b *BenchResult, verbose bool) {
	line := "══════════════════════════════════════════════════════════════"

	fmt.Println()
	fmt.Println("  " + line)
	fmt.Println("    Aegis Eval Bench Results")
	fmt.Println("  " + line)
	fmt.Println()
	fmt.Println("                         Predicted BLOCK    Predicted ALLOW")
	fmt.Printf("    Actually Malicious      TP: %-12d FN: %d\n", b.TP, b.FN)
	fmt.Printf("    Actually Benign         FP: %-12d TN: %d\n", b.FP, b.TN)
	fmt.Println()
	fmt.Println("  " + line)

	fmt.Printf("    Precision:  %5.1f%%  (%d/%d)\n", b.Precision*100, b.TP, b.TP+b.FP)
	fmt.Printf("    Recall:     %5.1f%%  (%d/%d)\n", b.Recall*100, b.TP, b.TP+b.FN)
	fmt.Printf("    F1 Score:   %5.1f%%\n", b.F1*100)
	fmt.Printf("    FP Rate:    %5.1f%%  (%d/%d)\n", b.FPRate*100, b.FP, b.FP+b.TN)
	fmt.Printf("    Avg Latency: %s\n", formatDuration(b.AvgLatency))
	fmt.Println("  " + line)

	if len(b.FalseNegatives) > 0 {
		fmt.Println()
		fmt.Println("    FALSE NEGATIVES (attacks that slipped through):")
		for _, r := range b.FalseNegatives {
			fmt.Printf("      %-28s [%-20s] %s\n",
				truncate(r.ID, 28), r.Category, truncate(r.Description, 40))
		}
	}

	if len(b.FalsePositives) > 0 {
		fmt.Println()
		fmt.Println("    FALSE POSITIVES (legit operations blocked):")
		for _, r := range b.FalsePositives {
			fmt.Printf("      %-28s [%-20s] %s\n",
				truncate(r.ID, 28), r.Category, truncate(r.Description, 40))
		}
	}

	fmt.Println()
	fmt.Println("  " + line)
	fmt.Println("    Category Breakdown:")

	cats := sortedCategories(b.Categories)
	for _, name := range cats {
		cat := b.Categories[name]
		missed := cat.Total - cat.Correct
		suffix := ""
		if missed > 0 {
			suffix = fmt.Sprintf("  ← %d missed", missed)
		}
		fmt.Printf("      %-22s %3d/%-3d (%5.1f%%)%s\n",
			name, cat.Correct, cat.Total, cat.Rate*100, suffix)
	}
	fmt.Println("  " + line)
	fmt.Println()

	if verbose {
		printVerbose(b)
	}
}

func printVerbose(b *BenchResult) {
	fmt.Println("    Detailed Results (all cases):")
	fmt.Println()

	allResults := make([]CaseResult, 0)
	allResults = append(allResults, b.FalseNegatives...)
	allResults = append(allResults, b.FalsePositives...)

	for _, r := range allResults {
		marker := ""
		switch {
		case r.IsFN:
			marker = "\033[91mFN\033[0m"
		case r.IsFP:
			marker = "\033[93mFP\033[0m"
		}
		fmt.Printf("      [%s] %-30s expected=%-14s got=%-14s %s\n",
			marker, truncate(r.ID, 30), r.ExpectedAction, r.GotAction,
			formatDuration(r.Latency))
	}
	fmt.Println()
}

func sortedCategories(cats map[string]*CatResult) []string {
	names := make([]string, 0, len(cats))
	for name := range cats {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		ri := cats[names[i]].Rate
		rj := cats[names[j]].Rate
		if math.Abs(ri-rj) < 0.001 {
			return names[i] < names[j]
		}
		return ri > rj
	})
	return names
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
}
