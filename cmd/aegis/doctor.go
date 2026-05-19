package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mayjain/aegis/internal/policy"
)

func runDoctor(args []string) {
	fmt.Println("Aegis Doctor")
	fmt.Println("============")

	// Binary path
	self, err := os.Executable()
	if err != nil {
		self = "(unknown)"
	}
	fmt.Printf("✓ CLI binary: %s (v2.0.0)\n", self)

	// Daemon
	if isDaemonRunning() {
		fmt.Printf("✓ Daemon: running (socket %s)\n", daemonSocketPath)
	} else {
		fmt.Println("✓ Daemon: not running (stateless mode OK)")
	}

	// Allowlist
	allowlistPath := ".aegis/allowlist.yaml"
	if info, err := os.Stat(allowlistPath); err == nil && !info.IsDir() {
		entryCount := countAllowlistEntries(allowlistPath)
		fmt.Printf("✓ Allowlist: %s found (%d entries)\n", allowlistPath, entryCount)
	} else {
		home := os.Getenv("HOME")
		globalAllowlist := filepath.Join(home, ".aegis", "allowlist.yaml")
		if _, err := os.Stat(globalAllowlist); err == nil {
			entryCount := countAllowlistEntries(globalAllowlist)
			fmt.Printf("✓ Allowlist: %s found (%d entries)\n", globalAllowlist, entryCount)
		} else {
			fmt.Println("⚠ Allowlist: .aegis/allowlist.yaml not found (run: aegis init)")
		}
	}

	// Policies directory
	policiesDir := "policies"
	if _, err := os.Stat(policiesDir); err == nil {
		files, _ := filepath.Glob(filepath.Join(policiesDir, "*.yaml"))
		totalRules := 0
		for _, f := range files {
			if pf, err := policy.LoadFile(f); err == nil {
				totalRules += len(pf.Rules)
			}
		}
		fmt.Printf("✓ Policies: %s found (%d files, %d rules)\n", policiesDir, len(files), totalRules)
	} else {
		fmt.Println("⚠ Policies: policies/ directory not found")
	}

	// WAL / audit log
	logPath := resolveAuditLogPath()
	if info, err := os.Stat(logPath); err == nil {
		sizeMB := float64(info.Size()) / (1024 * 1024)
		if sizeMB > 10 {
			fmt.Printf("⚠ WAL: %s (%.1f MB — consider rotation)\n", logPath, sizeMB)
		} else {
			fmt.Printf("✓ WAL: %s (%.1f MB)\n", logPath, sizeMB)
		}
	} else {
		fmt.Printf("✓ WAL: %s (not yet created)\n", logPath)
	}

	// AEGIS_MODE
	mode := os.Getenv("AEGIS_MODE")
	if mode == "" {
		fmt.Println("✓ AEGIS_MODE: not set (default: enforce)")
	} else {
		fmt.Printf("✓ AEGIS_MODE: %s\n", mode)
	}
}

func countAllowlistEntries(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	// Count non-empty, non-comment lines that look like list items
	count := 0
	for _, line := range splitLines(string(data)) {
		trimmed := trimSpace(line)
		if len(trimmed) > 1 && trimmed[0] == '-' {
			count++
		}
	}
	return count
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
