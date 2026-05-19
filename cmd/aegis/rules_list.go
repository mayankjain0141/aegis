package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
)

func runRules(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aegis rules list [--action deny|allow|escalate]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runRulesList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown rules subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: aegis rules list [--action deny|allow|escalate]")
		os.Exit(1)
	}
}

func runRulesList(args []string) {
	fs := flag.NewFlagSet("rules list", flag.ExitOnError)
	actionFilter := fs.String("action", "", "filter by action (deny|allow|escalate|throttle)")
	fs.Parse(args) //nolint:errcheck

	allRules, _ := loadAllPolicyRules()

	if len(allRules) == 0 {
		fmt.Println("No policy rules found. Run from the aegis project root or a project with a policies/ directory.")
		return
	}

	sort.Slice(allRules, func(i, j int) bool {
		return allRules[i].Priority < allRules[j].Priority
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Priority\tRule\tAction\tSeverity\tConfidence\n")
	fmt.Fprintf(w, "--------\t--------------------------\t--------\t---------\t----------\n")

	for _, r := range allRules {
		if *actionFilter != "" && r.Action != *actionFilter {
			continue
		}
		severity := r.Severity
		if severity == "" {
			severity = "-"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d%%\n",
			r.Priority, r.Name, r.Action, severity, int(r.Confidence*100))
	}
	w.Flush()
}
