package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mayjain/aegis/internal/policy"
)

func runExplain(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aegis explain <rule-name>")
		os.Exit(1)
	}
	target := args[0]

	allRules, allNames := loadAllPolicyRules()

	for _, r := range allRules {
		if r.Name == target {
			printRuleExplanation(r)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Rule %q not found.\n", target)
	if len(allNames) > 0 {
		sort.Strings(allNames)
		fmt.Fprintf(os.Stderr, "Known rules:\n")
		for _, n := range allNames {
			fmt.Fprintf(os.Stderr, "  %s\n", n)
		}
	}
	os.Exit(1)
}

func printRuleExplanation(r policy.RuleDef) {
	confidence := int(r.Confidence * 100)
	fmt.Printf("Rule: %s\n", r.Name)
	fmt.Printf("Priority: %d | Action: %s | Severity: %s | Confidence: %d%%\n",
		r.Priority, r.Action, r.Severity, confidence)
	fmt.Println()

	if r.Description != "" {
		fmt.Println("Description:")
		for _, line := range strings.Split(strings.TrimSpace(r.Description), "\n") {
			fmt.Printf("  %s\n", strings.TrimSpace(line))
		}
		fmt.Println()
	}

	if r.Remediation != "" {
		fmt.Println("Remediation:")
		for _, line := range strings.Split(strings.TrimSpace(r.Remediation), "\n") {
			fmt.Printf("  %s\n", strings.TrimSpace(line))
		}
		fmt.Println()
	}

	if len(r.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(r.Tags, ", "))
	}
}

func loadAllPolicyRules() ([]policy.RuleDef, []string) {
	dirs := []string{"policies", "../../policies"}
	patterns := []string{"*.yaml"}

	var allRules []policy.RuleDef
	var allNames []string
	seen := make(map[string]bool)

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		for _, pat := range patterns {
			files, _ := filepath.Glob(filepath.Join(dir, pat))
			for _, f := range files {
				base := filepath.Base(f)
				if seen[base] {
					continue
				}
				pf, err := policy.LoadFile(f)
				if err != nil {
					continue
				}
				seen[base] = true
				for _, r := range pf.Rules {
					allRules = append(allRules, r)
					allNames = append(allNames, r.Name)
				}
			}
		}
		break // use first dir that exists
	}
	return allRules, allNames
}
