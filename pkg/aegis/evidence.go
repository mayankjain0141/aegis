package aegis

import (
	"fmt"
	"strings"
	"time"
)

// Evidence records a single observation that contributed to a decision.
type Evidence struct {
	What string
	When time.Time
}

// FormatEvidence renders a slice of Evidence as a human-readable tree.
func FormatEvidence(ev []Evidence) string {
	if len(ev) == 0 {
		return "Decision evidence: (none)"
	}
	now := time.Now()
	var sb strings.Builder
	sb.WriteString("Decision evidence:\n")
	for _, e := range ev {
		ago := now.Sub(e.When)
		sb.WriteString(fmt.Sprintf("  • %s (%s ago)\n", e.What, fmtDuration(ago)))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
