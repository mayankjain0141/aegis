package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mayjain/aegis/pkg/aegis"
)

func runSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	tool := fs.String("tool", "Shell", "tool name (e.g. Shell, Write, Read)")
	command := fs.String("command", "", "command or argument to simulate")
	cwd := fs.String("cwd", "", "working directory (default: current)")
	fs.Parse(args) //nolint:errcheck

	if *command == "" {
		fmt.Fprintln(os.Stderr, "usage: aegis simulate --tool <tool> --command <cmd> [--cwd <cwd>]")
		os.Exit(1)
	}

	if *cwd == "" {
		*cwd, _ = os.Getwd()
	}

	engine, err := aegis.NewEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis: engine init: %v\n", err)
		os.Exit(1)
	}

	req := &aegis.Request{
		Tool:      *tool,
		Arguments: map[string]any{"command": *command},
		CWD:       *cwd,
	}

	decision := engine.Evaluate(context.Background(), req)
	signals := engine.ComputeSignals(*tool, *command, *cwd)

	fmt.Printf("Tool: %s\n", *tool)
	fmt.Printf("Command: %s\n", *command)
	fmt.Println()
	fmt.Printf("Decision: %s\n", strings.ToUpper(string(decision.Action)))
	if decision.Rule != "" {
		fmt.Printf("Rule: %s\n", decision.Rule)
	}
	if decision.Severity != "" || decision.Confidence > 0 {
		fmt.Printf("Severity: %s | Confidence: %d%%\n",
			decision.Severity, int(decision.Confidence*100))
	}

	fmt.Println()
	fmt.Println("Signals:")

	type kv struct {
		key string
		val string
	}
	var rows []kv

	if signals.Path.HasCritical {
		rows = append(rows, kv{"has_critical", fmt.Sprintf("true (path risk: %.2f)", signals.Path.MaxPathRisk)})
	}
	if signals.Path.HasSensitive {
		rows = append(rows, kv{"has_sensitive", "true"})
	}

	if len(signals.Command.VerbDanger) > 0 {
		// Show sorted verb danger
		verbs := make([]string, 0, len(signals.Command.VerbDanger))
		for v := range signals.Command.VerbDanger {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		parts := make([]string, 0, len(verbs))
		for _, v := range verbs {
			parts = append(parts, fmt.Sprintf("%s=%.2f", v, signals.Command.VerbDanger[v]))
		}
		rows = append(rows, kv{"verb_danger", strings.Join(parts, ", ")})
	}

	if signals.Network.Score > 0 {
		rows = append(rows, kv{"network_score", fmt.Sprintf("%.2f", signals.Network.Score)})
	}
	if signals.DLP.HasHit {
		rows = append(rows, kv{"dlp_hit", "true"})
	}
	if signals.Evasion.Score > 0 {
		rows = append(rows, kv{"evasion_score", fmt.Sprintf("%.2f", signals.Evasion.Score)})
	}
	if signals.MLScore > 0 {
		rows = append(rows, kv{"ml_score", fmt.Sprintf("%.2f", signals.MLScore)})
	}
	rows = append(rows, kv{"composite_score", fmt.Sprintf("%.2f", decision.CompositeScore)})

	for _, row := range rows {
		fmt.Printf("  %-20s %s\n", row.key+":", row.val)
	}
}
