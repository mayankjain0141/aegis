package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
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
	CWD            string `json:"cwd"`
}

type CaseResult struct {
	TestCase
	GotAction string
	GotRule   string
	Latency   time.Duration
	IsTP      bool
	IsFP      bool
	IsFN      bool
	IsTN      bool
}

type RuleMetrics struct {
	Name string
	TP   int
	FP   int
	TN   int
	FN   int
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
	P99Latency   time.Duration `json:"p99_latency_ns"`

	FalseNegatives []CaseResult          `json:"false_negatives,omitempty"`
	FalsePositives []CaseResult          `json:"false_positives,omitempty"`
	Categories     map[string]*CatResult `json:"categories"`
	Rules          map[string]*RuleMetrics `json:"rules,omitempty"`
	FileMetrics    map[string]*FileMetrics `json:"files,omitempty"`
}

type CatResult struct {
	Total   int     `json:"total"`
	Correct int     `json:"correct"`
	Rate    float64 `json:"rate"`
}

type FileMetrics struct {
	File      string  `json:"file"`
	Total     int     `json:"total"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	TN        int     `json:"tn"`
	Recall    float64 `json:"recall"`
	FPRate    float64 `json:"fp_rate"`
}

// BaselineMetrics is saved/loaded for regression comparison.
type BaselineMetrics struct {
	Recall    float64            `json:"recall"`
	FPRate    float64            `json:"fp_rate"`
	RuleFP    map[string]int     `json:"rule_fp"`
	Timestamp string             `json:"timestamp"`
}

func main() {
	corpus := flag.String("corpus", "testdata/eval/", "directory containing .jsonl test files")
	category := flag.String("category", "", "filter to a single category")
	verbose := flag.Bool("verbose", false, "show per-case results")
	jsonOut := flag.Bool("json", false, "output as JSON")
	threshold := flag.Float64("threshold", 0.9, "minimum recall to pass (exit 0)")
	baseline := flag.String("baseline", "", "baseline JSON file for regression comparison")
	saveBaseline := flag.String("save-baseline", "", "save current metrics as baseline to this file")
	flag.Parse()

	cases, fileMap, err := loadCorpus(*corpus, *category)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading corpus: %v\n", err)
		os.Exit(2)
	}
	if len(cases) == 0 {
		fmt.Fprintf(os.Stderr, "no test cases found in %s\n", *corpus)
		os.Exit(2)
	}

	engine, err := aegis.NewEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating engine: %v\n", err)
		os.Exit(2)
	}

	results, latencies := evaluate(engine, cases, fileMap)
	bench := computeMetrics(results, latencies, fileMap)

	if *jsonOut {
		printJSON(bench)
	} else {
		printTable(bench, *verbose)
	}

	if *saveBaseline != "" {
		if err := saveBaselineFile(*saveBaseline, bench); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to save baseline: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "baseline saved to %s\n", *saveBaseline)
		}
	}

	exitCode := 0

	if *baseline != "" {
		if regressions := checkRegression(*baseline, bench); len(regressions) > 0 {
			fmt.Fprintln(os.Stderr, "\nREGRESSION DETECTED:")
			for _, r := range regressions {
				fmt.Fprintln(os.Stderr, " ", r)
			}
			exitCode = 1
		} else {
			fmt.Fprintln(os.Stderr, "No regressions detected vs baseline.")
		}
	}

	if bench.Recall < *threshold {
		exitCode = 1
	}

	os.Exit(exitCode)
}

type fileEntry struct {
	filename string
}

func loadCorpus(dir, categoryFilter string) ([]TestCase, map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading corpus directory %q: %w", dir, err)
	}

	var cases []TestCase
	fileMap := make(map[string]string) // caseID -> filename

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fileCases, err := loadJSONLFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		for _, tc := range fileCases {
			fileMap[tc.ID] = entry.Name()
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

	return cases, fileMap, nil
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

func evaluate(engine *aegis.Engine, cases []TestCase, fileMap map[string]string) ([]CaseResult, []time.Duration) {
	results := make([]CaseResult, 0, len(cases))
	latencies := make([]time.Duration, 0, len(cases))

	ctx := context.Background()

	for _, tc := range cases {
		cwd := tc.CWD
		if cwd == "" {
			cwd = "/home/dev/project"
		}

		start := time.Now()
		decision := engine.EvaluateJSON(ctx, tc.Tool, tc.Arguments, cwd)
		elapsed := time.Since(start)

		gotAction := "allow"
		gotRule := ""
		if decision != nil {
			gotAction = string(decision.Action)
			gotRule = decision.Rule
		}

		// Normalize: escalate counts as deny for eval purposes
		if gotAction == "escalate" || gotAction == "throttle" {
			gotAction = "deny"
		}

		r := CaseResult{
			TestCase:  tc,
			GotAction: gotAction,
			GotRule:   gotRule,
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
		latencies = append(latencies, elapsed)
	}
	return results, latencies
}

func isBlockedAction(action string) bool {
	switch action {
	case "deny", "escalate", "escalate_human", "throttle":
		return true
	default:
		return false
	}
}

func computeMetrics(results []CaseResult, latencies []time.Duration, fileMap map[string]string) *BenchResult {
	b := &BenchResult{
		Categories:  make(map[string]*CatResult),
		Rules:       make(map[string]*RuleMetrics),
		FileMetrics: make(map[string]*FileMetrics),
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

		// Category breakdown
		cat, ok := b.Categories[r.Category]
		if !ok {
			cat = &CatResult{}
			b.Categories[r.Category] = cat
		}
		cat.Total++
		if r.IsTP || r.IsTN {
			cat.Correct++
		}

		// Per-rule metrics
		if r.GotRule != "" {
			rm, ok := b.Rules[r.GotRule]
			if !ok {
				rm = &RuleMetrics{Name: r.GotRule}
				b.Rules[r.GotRule] = rm
			}
			switch {
			case r.IsTP:
				rm.TP++
			case r.IsFP:
				rm.FP++
			case r.IsFN:
				rm.FN++
			case r.IsTN:
				rm.TN++
			}
		}

		// Per-file metrics
		filename := fileMap[r.ID]
		if filename == "" {
			filename = "unknown"
		}
		fm, ok := b.FileMetrics[filename]
		if !ok {
			fm = &FileMetrics{File: filename}
			b.FileMetrics[filename] = fm
		}
		fm.Total++
		switch {
		case r.IsTP:
			fm.TP++
		case r.IsFP:
			fm.FP++
		case r.IsFN:
			fm.FN++
		case r.IsTN:
			fm.TN++
		}
	}

	b.TotalCases = len(results)
	b.TotalLatency = totalLatency
	if b.TotalCases > 0 {
		b.AvgLatency = totalLatency / time.Duration(b.TotalCases)
	}

	// Compute p99 latency
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if len(sorted) > 0 {
		p99idx := int(math.Floor(float64(len(sorted)) * 0.99))
		if p99idx >= len(sorted) {
			p99idx = len(sorted) - 1
		}
		b.P99Latency = sorted[p99idx]
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
	for _, fm := range b.FileMetrics {
		if fm.TP+fm.FN > 0 {
			fm.Recall = float64(fm.TP) / float64(fm.TP+fm.FN)
		}
		if fm.FP+fm.TN > 0 {
			fm.FPRate = float64(fm.FP) / float64(fm.FP+fm.TN)
		}
	}

	return b
}

func printJSON(b *BenchResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(b) //nolint:errcheck
}

func printTable(b *BenchResult, verbose bool) {
	line := "══════════════════════════════════════════════════════════════"

	fmt.Println()
	fmt.Println("  " + line)
	fmt.Println("    Aegis V2 Eval Bench")
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
	fmt.Printf("    Avg Latency: %s   p99: %s\n", formatDuration(b.AvgLatency), formatDuration(b.P99Latency))
	fmt.Println("  " + line)

	if len(b.FalseNegatives) > 0 {
		fmt.Println()
		fmt.Println("    FALSE NEGATIVES (attacks that slipped through):")
		for _, r := range b.FalseNegatives {
			fmt.Printf("      %-32s [%-20s] rule=%s  %s\n",
				truncate(r.ID, 32), r.Category, r.GotRule, truncate(r.Description, 35))
		}
	}

	if len(b.FalsePositives) > 0 {
		fmt.Println()
		fmt.Println("    FALSE POSITIVES (legit operations blocked):")
		for _, r := range b.FalsePositives {
			fmt.Printf("      %-32s [%-20s] rule=%s  %s\n",
				truncate(r.ID, 32), r.Category, r.GotRule, truncate(r.Description, 35))
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
		fmt.Printf("      %-28s %3d/%-3d (%5.1f%%)%s\n",
			name, cat.Correct, cat.Total, cat.Rate*100, suffix)
	}

	fmt.Println()
	fmt.Println("  " + line)
	fmt.Println("    Per-File Metrics:")
	printFileMetrics(b.FileMetrics)

	fmt.Println("  " + line)
	fmt.Println()
}

func printFileMetrics(files map[string]*FileMetrics) {
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		fm := files[name]
		attacks := fm.TP + fm.FN
		benign := fm.FP + fm.TN
		if attacks > 0 {
			fmt.Printf("      %-40s recall=%5.1f%%  fpr=%5.1f%%\n",
				name, fm.Recall*100, fm.FPRate*100)
		} else {
			fmt.Printf("      %-40s (benign file, %d cases, FP=%d)\n",
				name, benign, fm.FP)
		}
	}
}

func saveBaselineFile(path string, b *BenchResult) error {
	ruleFP := make(map[string]int)
	for name, rm := range b.Rules {
		ruleFP[name] = rm.FP
	}
	baseline := BaselineMetrics{
		Recall:    b.Recall,
		FPRate:    b.FPRate,
		RuleFP:    ruleFP,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func checkRegression(path string, current *BenchResult) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read baseline %s: %v", path, err)}
	}
	var baseline BaselineMetrics
	if err := json.Unmarshal(data, &baseline); err != nil {
		return []string{fmt.Sprintf("cannot parse baseline: %v", err)}
	}

	var regressions []string

	if current.Recall < baseline.Recall-0.01 {
		regressions = append(regressions, fmt.Sprintf(
			"Recall degraded: %.3f → %.3f (baseline: %s)", baseline.Recall, current.Recall, baseline.Timestamp))
	}
	if current.FPRate > baseline.FPRate+0.01 {
		regressions = append(regressions, fmt.Sprintf(
			"FPRate increased: %.3f → %.3f", baseline.FPRate, current.FPRate))
	}

	// Check per-rule FP regressions
	for ruleName, baselineFP := range baseline.RuleFP {
		if baselineFP == 0 {
			if rm, ok := current.Rules[ruleName]; ok && rm.FP > 0 {
				regressions = append(regressions, fmt.Sprintf(
					"Rule %s had 0 FP in baseline, now has %d FP", ruleName, rm.FP))
			}
		}
	}

	return regressions
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
