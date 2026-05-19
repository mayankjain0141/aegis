package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mayjain/aegis/internal/policy"
)

func runValidate(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aegis validate <path>")
		os.Exit(1)
	}

	target := args[0]
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: %v\n", err)
		os.Exit(1)
	}

	var files []string
	if info.IsDir() {
		entries, err := filepath.Glob(filepath.Join(target, "*.yaml"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aegis: glob: %v\n", err)
			os.Exit(1)
		}
		files = entries
	} else {
		files = []string{target}
	}

	if len(files) == 0 {
		fmt.Println("No YAML files found.")
		return
	}

	okCount := 0
	errCount := 0
	for _, f := range files {
		pf, err := policy.LoadFile(f)
		if err != nil {
			// Strip redundant path prefix from error message
			msg := err.Error()
			prefix := "policy " + f + ": "
			msg = strings.TrimPrefix(msg, prefix)
			fmt.Printf("x %s: %s\n", f, msg)
			errCount++
		} else {
			ruleWord := "rules"
			if len(pf.Rules) == 1 {
				ruleWord = "rule"
			}
			fmt.Printf("✓ %s (%d %s, no errors)\n", f, len(pf.Rules), ruleWord)
			okCount++
		}
	}

	fmt.Println()
	if errCount == 0 {
		fmt.Printf("%d file(s) OK\n", okCount)
	} else {
		fmt.Printf("%d file(s) OK, %d error(s)\n", okCount, errCount)
		os.Exit(1)
	}
}
