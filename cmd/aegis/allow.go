package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mayjain/aegis/pkg/aegis/telemetry"
)

func runAllow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aegis allow last")
		os.Exit(1)
	}

	switch args[0] {
	case "last":
		runAllowLast()
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown allow subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: aegis allow last")
		os.Exit(1)
	}
}

func runAllowLast() {
	logPath := resolveAuditLogPath()
	events, err := telemetry.ReadAll(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: no audit log at %s\n  Run aegis with AEGIS_MODE=audit to collect data.\n", logPath)
		os.Exit(1)
	}

	// Find most recent deny
	var last *telemetry.Event
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == "deny" || events[i].Action == "escalate" {
			e := events[i]
			last = &e
			break
		}
	}

	if last == nil {
		fmt.Println("No denied actions found in the audit log.")
		return
	}

	ago := time.Since(last.Time).Round(time.Second)
	agoStr := formatDuration(ago)

	fmt.Printf("Last denied action (%s ago):\n", agoStr)
	fmt.Printf("  Rule:    %s\n", last.Rule)
	fmt.Printf("  Tool:    %s\n", last.Tool)
	if last.ArgSummary != "" {
		fmt.Printf("  Command: %s\n", last.ArgSummary)
	}
	fmt.Println()

	pattern := last.ArgSummary
	if pattern == "" {
		pattern = last.Tool + " ..."
	}

	fmt.Println("Allowlist YAML entry (add to .aegis/allowlist.yaml):")
	fmt.Println("---")
	fmt.Println("commands:")
	fmt.Printf("  - pattern: %q\n", pattern)
	fmt.Println(`    reason: "TODO: explain why this is safe"`)
}

func resolveAuditLogPath() string {
	cfg, _ := loadConfig()
	logPath := cfg.Logging.AuditLog
	if logPath == "" {
		logPath = filepath.Join(os.Getenv("HOME"), ".aegis", "audit.log")
	}
	if strings.HasPrefix(logPath, "~/") {
		logPath = filepath.Join(os.Getenv("HOME"), logPath[2:])
	}
	return logPath
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
