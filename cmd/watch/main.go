package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	colorReset   = "\033[0m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorCyan    = "\033[36m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
	colorMagenta = "\033[35m"
	colorBgRed   = "\033[41m"
	colorWhite   = "\033[97m"
)

type traceEvent struct {
	ID            string  `json:"id"`
	AgentID       string  `json:"agent_id"`
	Timestamp     string  `json:"timestamp"`
	Tool          string  `json:"tool"`
	RiskScore     float64 `json:"risk_score"`
	Decision      string  `json:"decision"`
	PolicyID      string  `json:"policy_id,omitempty"`
	PolicyVersion string  `json:"policy_version,omitempty"`
	LatencyUs     int     `json:"latency_us"`
	Error         string  `json:"error,omitempty"`
}

type approvalRequest struct {
	ID          string  `json:"id"`
	RequestID   string  `json:"request_id"`
	AgentID     string  `json:"agent_id"`
	Tool        string  `json:"tool"`
	ArgsSummary string  `json:"args_summary"`
	RiskScore   float64 `json:"risk_score"`
	Deadline    string  `json:"deadline"`
}

type wsMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func main() {
	url := flag.String("url", "ws://localhost:8080/ws", "Daemon WebSocket URL")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	printHeader(*url)

	for {
		err := connectAndStream(ctx, *url)
		if ctx.Err() != nil {
			fmt.Printf("\n%s%s ◼ Disconnected. Bye!%s\n", colorDim, colorCyan, colorReset)
			return
		}

		if err != nil {
			fmt.Printf("%s%s ⚠ Connection lost: %s%s\n", colorYellow, colorBold, err, colorReset)
		}

		if !reconnectWithBackoff(ctx, *url) {
			return
		}
	}
}

func printHeader(url string) {
	fmt.Printf("\n%s═══════════════════════════════════════════════════════════%s\n", colorCyan, colorReset)
	fmt.Printf("%s  AEGIS TRACE WATCHER%s  │  %s%s%s\n", colorBold, colorReset, colorDim, url, colorReset)
	fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n\n", colorCyan, colorReset)
}

func connectAndStream(ctx context.Context, url string) error {
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return err
	}
	defer conn.CloseNow()

	fmt.Printf("%s%s ● Connected%s\n\n", colorGreen, colorBold, colorReset)

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}

		handleMessage(data)
	}
}

func handleMessage(data []byte) {
	var msg wsMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		// Try as a raw trace event (daemon broadcasts TraceEvent directly)
		var ev traceEvent
		if err2 := json.Unmarshal(data, &ev); err2 == nil && ev.Tool != "" {
			printTraceEvent(&ev)
			return
		}
		fmt.Printf("%s  ? unknown message: %s%s\n", colorDim, string(data[:min(80, len(data))]), colorReset)
		return
	}

	switch msg.Type {
	case "approval_request":
		var req approvalRequest
		if err := json.Unmarshal(msg.Data, &req); err == nil {
			printApprovalRequest(&req)
		}
	case "approval_resolved":
		var resolved struct {
			ID     string `json:"id"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(msg.Data, &resolved); err == nil {
			printApprovalResolved(resolved.ID, resolved.Action, resolved.Reason)
		}
	default:
		var ev traceEvent
		if err := json.Unmarshal(data, &ev); err == nil && ev.Tool != "" {
			printTraceEvent(&ev)
		} else {
			fmt.Printf("%s  ? %s: %s%s\n", colorDim, msg.Type, string(msg.Data[:min(60, len(msg.Data))]), colorReset)
		}
	}
}

func printTraceEvent(ev *traceEvent) {
	ts := formatTimestamp(ev.Timestamp)
	agent := padRight(ev.AgentID, 12)
	tool := padRight(ev.Tool, 12)

	var decColor, decIcon, decLabel string
	switch ev.Decision {
	case "allow":
		decColor = colorGreen
		decIcon = "✓"
		decLabel = "ALLOW"
	case "deny":
		decColor = colorRed
		decIcon = "✗"
		decLabel = "DENY"
	case "escalate":
		decColor = colorYellow
		decIcon = "⏳"
		decLabel = "ESCALATE"
	case "throttle":
		decColor = colorYellow
		decIcon = "⏳"
		decLabel = "THROTTLE"
	default:
		decColor = colorDim
		decIcon = "?"
		decLabel = strings.ToUpper(ev.Decision)
	}

	decision := fmt.Sprintf("%s%s %-8s%s", decColor, decIcon, decLabel, colorReset)
	risk := fmt.Sprintf("risk:%.2f", ev.RiskScore)

	latency := fmt.Sprintf("%dμs", ev.LatencyUs)
	if ev.Decision == "escalate" {
		latency = "waiting..."
	}

	line := fmt.Sprintf("%s │ %s │ %s │ %s │ %s │ %s",
		ts, agent, tool, decision, risk, latency)

	if ev.PolicyID != "" {
		line += fmt.Sprintf(" │ %spolicy:%s%s", colorDim, ev.PolicyID, colorReset)
	}

	fmt.Println(line)
}

func printApprovalRequest(req *approvalRequest) {
	fmt.Printf("\n%s%s ╔══ AWAITING APPROVAL ══════════════════════════════════╗%s\n", colorBgRed, colorWhite, colorReset)
	fmt.Printf("%s%s ║  ID:    %s%s\n", colorBgRed, colorWhite, req.ID, colorReset)
	fmt.Printf("%s%s ║  Agent: %s │ Tool: %s%s\n", colorBgRed, colorWhite, req.AgentID, req.Tool, colorReset)
	fmt.Printf("%s%s ║  Args:  %s%s\n", colorBgRed, colorWhite, req.ArgsSummary, colorReset)
	fmt.Printf("%s%s ║  Risk:  %.2f │ Deadline: %s%s\n", colorBgRed, colorWhite, req.RiskScore, formatTimestamp(req.Deadline), colorReset)
	fmt.Printf("%s%s ╚═══════════════════════════════════════════════════════╝%s\n\n", colorBgRed, colorWhite, colorReset)
}

func printApprovalResolved(id, action, reason string) {
	var color, icon string
	switch action {
	case "approve":
		color = colorGreen
		icon = "✓"
	case "deny":
		color = colorRed
		icon = "✗"
	default:
		color = colorYellow
		icon = "?"
	}
	fmt.Printf("%s%s %s RESOLVED [%s]: %s — %s%s\n\n", color, colorBold, icon, id, strings.ToUpper(action), reason, colorReset)
}

func reconnectWithBackoff(ctx context.Context, url string) bool {
	const maxBackoff = 30 * time.Second
	attempt := 0

	for {
		attempt++
		backoff := time.Duration(math.Min(
			float64(time.Second)*math.Pow(2, float64(attempt-1)),
			float64(maxBackoff),
		))

		fmt.Printf("%s  ↻ Reconnecting in %s (attempt %d)...%s\n", colorDim, backoff.Round(time.Millisecond), attempt, colorReset)

		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}

		conn, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			fmt.Printf("%s  ✗ Failed: %s%s\n", colorRed, err, colorReset)
			continue
		}
		conn.CloseNow()
		fmt.Printf("%s%s ● Reconnected%s\n\n", colorGreen, colorBold, colorReset)
		return true
	}
}

func formatTimestamp(raw string) string {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Sprintf("%s%s%s", colorDim, raw, colorReset)
		}
	}
	return fmt.Sprintf("%s%s%s", colorCyan, t.Local().Format("15:04:05"), colorReset)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
