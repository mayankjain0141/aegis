// aegis is the Aegis CLI — install hooks, manage config, view audit reports.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	case "config":
		cmdConfig(os.Args[2:])
	case "audit-report":
		cmdAuditReport()
	case "daemon":
		cmdDaemon(os.Args[2:])
	case "version":
		fmt.Println("aegis v2.0.0")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`aegis — AI agent security policy engine

Usage:
  aegis init              Install hooks.json and create default config
  aegis config get <key>  Show a config value
  aegis config set <key> <value>  Update a config value
  aegis config show       Show full config
  aegis audit-report      Show what would be blocked (audit mode summary)
  aegis daemon start      Start the session state daemon
  aegis daemon stop       Stop the daemon
  aegis daemon status     Show daemon status
  aegis version           Print version

Environment:
  AEGIS_MODE=audit        Log decisions but allow everything
  AEGIS_MODE=off          Disable all evaluation
`)
}

// ── aegis init ────────────────────────────────────────────────────────────────

func cmdInit() {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	fmt.Println("Initializing aegis...")

	// Create .aegis/ directory
	aegisDir := filepath.Join(cwd, ".aegis")
	if err := os.MkdirAll(aegisDir, 0o755); err != nil {
		fatalf("mkdir .aegis: %v", err)
	}

	// Create .cursor/hooks/ directory
	hooksDir := filepath.Join(cwd, ".cursor", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		fatalf("mkdir .cursor/hooks: %v", err)
	}

	// Merge hooks.json (never overwrite existing hooks)
	mergeHooksJSON(cwd)

	// Create config if not exists
	configPath := filepath.Join(aegisDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		writeDefaultConfig(configPath)
		fmt.Printf("  Created %s\n", configPath)
	} else {
		fmt.Printf("  Config already exists: %s (skipping)\n", configPath)
	}

	// Create allowlist if not exists
	allowlistPath := filepath.Join(aegisDir, "allowlist.yaml")
	if _, err := os.Stat(allowlistPath); os.IsNotExist(err) {
		writeDefaultAllowlist(allowlistPath)
		fmt.Printf("  Created %s\n", allowlistPath)
	} else {
		fmt.Printf("  Allowlist already exists: %s (skipping)\n", allowlistPath)
	}

	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Build the hook binary:  go build -o .cursor/hooks/aegis ./cmd/hook/")
	fmt.Println("  2. Start in audit mode first to see what would be blocked")
	fmt.Println("  3. Review: aegis audit-report")
	fmt.Println("  4. Switch to enforce mode in .aegis/config.yaml when ready")
}

func mergeHooksJSON(cwd string) {
	path := filepath.Join(cwd, ".cursor", "hooks.json")

	aegisHooks := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"beforeShellExecution": []any{
				map[string]any{"command": ".cursor/hooks/aegis", "failClosed": true, "timeout": 5},
			},
			"preToolUse": []any{
				map[string]any{"command": ".cursor/hooks/aegis", "matcher": "Write|Delete|StrReplace|Edit", "failClosed": true, "timeout": 5},
			},
			"beforeMCPExecution": []any{
				map[string]any{"command": ".cursor/hooks/aegis", "failClosed": true, "timeout": 5},
			},
		},
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create fresh
		data, _ := json.MarshalIndent(aegisHooks, "", "  ")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			fatalf("write hooks.json: %v", err)
		}
		fmt.Printf("  Created %s\n", path)
		return
	}

	// Merge into existing
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("  Warning: cannot read existing hooks.json: %v\n", err)
		return
	}
	var existing map[string]any
	if err := json.Unmarshal(data, &existing); err != nil {
		fmt.Printf("  Warning: cannot parse existing hooks.json: %v\n", err)
		return
	}

	// Check if aegis already configured
	hooks, _ := existing["hooks"].(map[string]any)
	for _, hookList := range hooks {
		entries, _ := hookList.([]any)
		for _, e := range entries {
			m, _ := e.(map[string]any)
			if cmd, _ := m["command"].(string); strings.HasSuffix(cmd, "aegis") {
				fmt.Printf("  hooks.json already has aegis hooks (skipping)\n")
				return
			}
		}
	}

	// Merge hooks
	if hooks == nil {
		hooks = make(map[string]any)
		existing["hooks"] = hooks
	}
	aegisHookMap, _ := aegisHooks["hooks"].(map[string]any)
	for k, v := range aegisHookMap {
		if _, ok := hooks[k]; !ok {
			hooks[k] = v
		} else {
			existing_list, _ := hooks[k].([]any)
			new_list, _ := v.([]any)
			hooks[k] = append(existing_list, new_list...)
		}
	}

	merged, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(path, append(merged, '\n'), 0o644); err != nil {
		fatalf("write merged hooks.json: %v", err)
	}
	fmt.Printf("  Merged aegis hooks into %s\n", path)
}

func writeDefaultConfig(path string) {
	content := `# Aegis configuration
# mode: enforce | audit | off
mode: audit

# sensitivity: strict | balanced | permissive
sensitivity: balanced

# Phase 3 LLM classifier (opt-in)
phase3:
  enabled: false
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
  budget_per_day: 100

logging:
  audit_log: ~/.aegis/audit.log
  max_size_mb: 50
  max_files: 3
`
	os.WriteFile(path, []byte(content), 0o644) //nolint:errcheck
}

func writeDefaultAllowlist(path string) {
	content := `# Aegis allowlist — project-specific exceptions
# Committed to repo; shared with team.

# Allowed external hosts
hosts: []
#  - "staging.company.com"
#  - "registry.internal"

# Allowed command glob patterns
commands: []
#  - "docker push registry.internal/*"

# Paths that are safe to read in this project (override sensitive detection)
paths_safe: []
#  - ".env"
#  - ".env.local"
`
	os.WriteFile(path, []byte(content), 0o644) //nolint:errcheck
}

// ── aegis config ──────────────────────────────────────────────────────────────

type Config struct {
	Mode        string `yaml:"mode"`
	Sensitivity string `yaml:"sensitivity"`
	Phase3      struct {
		Enabled      bool   `yaml:"enabled"`
		Model        string `yaml:"model"`
		APIKeyEnv    string `yaml:"api_key_env"`
		BudgetPerDay int    `yaml:"budget_per_day"`
	} `yaml:"phase3"`
	Logging struct {
		AuditLog   string `yaml:"audit_log"`
		MaxSizeMB  int    `yaml:"max_size_mb"`
		MaxFiles   int    `yaml:"max_files"`
	} `yaml:"logging"`
}

func loadConfig() (*Config, string) {
	candidates := []string{
		".aegis/config.yaml",
		filepath.Join(os.Getenv("HOME"), ".aegis", "config.yaml"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		// Defaults
		if cfg.Mode == "" {
			cfg.Mode = "audit"
		}
		if cfg.Sensitivity == "" {
			cfg.Sensitivity = "balanced"
		}
		return &cfg, path
	}
	return &Config{Mode: "audit", Sensitivity: "balanced"}, ""
}

func cmdConfig(args []string) {
	cfg, path := loadConfig()

	if len(args) == 0 || args[0] == "show" {
		cmdConfigShow(cfg, path)
		return
	}

	switch args[0] {
	case "get":
		if len(args) < 2 {
			fatalf("usage: aegis config get <key>")
		}
		switch args[1] {
		case "mode":
			fmt.Println(cfg.Mode)
		case "sensitivity":
			fmt.Println(cfg.Sensitivity)
		default:
			fatalf("unknown config key: %s", args[1])
		}
	case "show":
		cmdConfigShow(cfg, path)
	default:
		fatalf("unknown config subcommand: %s", args[0])
	}
}

func cmdConfigShow(cfg *Config, path string) {
	if path != "" {
		fmt.Printf("Config file: %s\n\n", path)
	} else {
		fmt.Println("Config file: (none found, using defaults)\n")
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "mode\t%s\n", cfg.Mode)
	fmt.Fprintf(w, "sensitivity\t%s\n", cfg.Sensitivity)
	fmt.Fprintf(w, "phase3.enabled\t%v\n", cfg.Phase3.Enabled)
	fmt.Fprintf(w, "logging.audit_log\t%s\n", cfg.Logging.AuditLog)
	w.Flush()
}

// ── aegis audit-report ────────────────────────────────────────────────────────

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Tool   string    `json:"tool"`
	Rule   string    `json:"rule"`
	Action string    `json:"action"`
	Args   string    `json:"args,omitempty"`
}

func cmdAuditReport() {
	cfg, _ := loadConfig()
	logPath := cfg.Logging.AuditLog
	if logPath == "" {
		logPath = filepath.Join(os.Getenv("HOME"), ".aegis", "audit.log")
	}
	// Expand ~
	if strings.HasPrefix(logPath, "~/") {
		logPath = filepath.Join(os.Getenv("HOME"), logPath[2:])
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No audit log found at %s\n", logPath)
		fmt.Fprintf(os.Stderr, "Run with AEGIS_MODE=audit to collect data first.\n")
		os.Exit(1)
	}

	var entries []AuditEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return
	}

	// Count by rule
	ruleCounts := make(map[string]int)
	for _, e := range entries {
		if e.Action == "deny" || e.Action == "escalate" {
			ruleCounts[e.Rule]++
		}
	}

	fmt.Printf("Audit Report — %d events, %d would-be-blocked\n\n", len(entries), len(entries)-countAction(entries, "allow"))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Rule\tCount\tAction\n")
	fmt.Fprintf(w, "────\t─────\t──────\n")
	for rule, count := range ruleCounts {
		fmt.Fprintf(w, "%s\t%d\tdeny\n", rule, count)
	}
	w.Flush()

	fmt.Println("\nRecent blocked events:")
	shown := 0
	for i := len(entries) - 1; i >= 0 && shown < 10; i-- {
		e := entries[i]
		if e.Action == "deny" || e.Action == "escalate" {
			fmt.Printf("  %s  [%s]  %s\n", e.Time.Format("15:04:05"), e.Rule, e.Tool)
			shown++
		}
	}

	fmt.Println("\nTo add exceptions, edit .aegis/allowlist.yaml")
	fmt.Println("To enforce, set mode: enforce in .aegis/config.yaml")
}

func countAction(entries []AuditEntry, action string) int {
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// ── aegis daemon ──────────────────────────────────────────────────────────────

const daemonPIDFile = "/tmp/aegis-daemon.pid"
const daemonSocketPath = "/tmp/aegis-daemon.sock"

func cmdDaemon(args []string) {
	if len(args) == 0 {
		fatalf("usage: aegis daemon <start|stop|status>")
	}
	switch args[0] {
	case "start":
		fmt.Println("Starting aegis daemon...")
		fmt.Printf("Socket: %s\n", daemonSocketPath)
		fmt.Println("Run the daemon binary directly: go run ./cmd/daemon/")
	case "stop":
		data, err := os.ReadFile(daemonPIDFile)
		if err != nil {
			fmt.Println("Daemon not running (no PID file)")
			return
		}
		fmt.Printf("Sending SIGTERM to PID %s\n", strings.TrimSpace(string(data)))
		os.Remove(daemonPIDFile) //nolint:errcheck
	case "status":
		if _, err := os.Stat(daemonPIDFile); err != nil {
			fmt.Println("Status: not running")
		} else {
			data, _ := os.ReadFile(daemonPIDFile)
			fmt.Printf("Status: running (PID %s)\n", strings.TrimSpace(string(data)))
		}
	default:
		fatalf("unknown daemon subcommand: %s", args[0])
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis: "+format+"\n", args...)
	os.Exit(1)
}
