// aegis-hook is the Cursor/Claude Code hook binary.
// It reads a tool call as JSON from stdin, evaluates it with the aegis engine,
// and writes a permission decision as JSON to stdout.
//
// Cursor invokes this binary for:
//   - beforeShellExecution: {"command": "...", "cwd": "..."}
//   - preToolUse:           {"tool": "...", "input": {...}, "cwd": "..."}
//   - beforeMCPExecution:   {"serverName": "...", "tool": "...", "input": {...}, "cwd": "..."}
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
	aegisdaemon "github.com/mayjain/aegis/pkg/aegis/daemon"
	"github.com/mayjain/aegis/pkg/aegis/telemetry"
)

const daemonSocketPath = aegisdaemon.SocketPath
const daemonTimeout = 200 * time.Millisecond
const daemonAPIVersion = "1"

// hookResponse is the JSON written to stdout for Cursor.
type hookResponse struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// normalizedRequest is the internal representation after parsing hook input.
type normalizedRequest struct {
	Tool      string
	Arguments map[string]any
	CWD       string
}

var ruleDescriptions = map[string]string{
	"critical_path_destruction": "Command targets a critical system path",
	"critical_path_write":       "Command writes to a critical or sensitive system path",
	"system_control":            "Command attempts system control (shutdown/reboot/halt)",
	"raw_socket_open":           "Command opens a raw network socket",
	"privilege_escalation":      "Command attempts privilege escalation",
	"secret_leakage":            "Command contains sensitive credentials or API keys",
	"sensitive_file_access":     "Command accesses sensitive system files outside the project",
	"data_exfiltration":         "Command may exfiltrate data to an external host",
	"remote_code_execution":     "Command downloads and executes remote code",
	"execute_from_tmp":          "Command executes a binary from /tmp (download-execute pattern)",
	"suid_manipulation":         "Command attempts to set the SUID bit",
	"cron_persistence":          "Command installs a cron job for persistence",
	"bashrc_persistence":        "Command modifies shell profile with exec/network content",
	"evasion_with_danger":       "Command uses encoding/obfuscation with dangerous operations",
	"default_uncertain_shell":   "Shell command could not be confidently classified",
	"unknown_network_write":     "Command writes data to an unknown or untrusted external host",
	"default_uncertain":         "Tool call could not be confidently classified by any rule",
	"shell_no_rule_matched":     "Shell command with elevated danger score matched no specific rule",
}

// daemonRequest is the JSON body sent to the daemon's /evaluate endpoint.
type daemonRequest struct {
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
	CWD     string         `json:"cwd"`
	AgentID string         `json:"agent_id"`
}

// daemonResponse mirrors aegis.Decision in JSON form.
type daemonResponse struct {
	Action         string   `json:"action"`
	Rule           string   `json:"rule"`
	Severity       string   `json:"severity"`
	Confidence     float64  `json:"confidence"`
	Evidence       []string `json:"evidence"`
	CompositeScore float64  `json:"composite_score"`
	Stage          string   `json:"stage"`
}

var (
	wal     *telemetry.WAL
	walOnce sync.Once
)

func getWAL() *telemetry.WAL {
	walOnce.Do(func() {
		logPath := defaultLogPath()
		if logPath == "" {
			return
		}
		w, err := telemetry.Open(logPath)
		if err == nil {
			wal = w
		}
	})
	return wal
}

// closeWAL flushes and closes the WAL. Called via defer in main.
func closeWAL() {
	if w := getWAL(); w != nil {
		w.Close() //nolint:errcheck
	}
}

func main() {
	// Fail-open on empty input to avoid breaking the IDE
	input, err := io.ReadAll(os.Stdin)
	if err != nil || len(strings.TrimSpace(string(input))) == 0 {
		writeAllow()
		return
	}

	// req is declared before the defer so the panic recovery can log it to the WAL.
	var req *normalizedRequest

	// Ensure WAL is flushed before process exits (Cursor invokes us per-call, so exit is frequent)
	defer closeWAL()

	// Fail-open on engine panics; write a panic event to the WAL before allowing.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "aegis: panic recovered:", r)
			if req != nil {
				writeWAL(req, &aegis.Decision{Action: aegis.ActionAllow, Rule: "panic_recovered"}, 0)
			}
			writeAllow()
		}
	}()

	mode := strings.ToLower(os.Getenv("AEGIS_MODE"))
	if mode == "off" {
		writeAllow()
		return
	}

	req, err = parseHookInput(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: parse error (fail-open):", err)
		writeAllow()
		return
	}

	start := time.Now()
	decision := evaluate(req)
	latencyUs := time.Since(start).Microseconds()

	// Write to audit WAL regardless of mode
	writeWAL(req, decision, latencyUs)

	if mode == "audit" {
		if decision.Action == aegis.ActionDeny || decision.Action == aegis.ActionEscalate {
			fmt.Fprintf(os.Stderr, "aegis [AUDIT]: would deny rule=%s severity=%s\n",
				decision.Rule, decision.Severity)
		}
		writeAllow()
		return
	}

	if decision.Action == aegis.ActionDeny || decision.Action == aegis.ActionEscalate {
		writeDeny(decision)
		return
	}

	writeAllow()
}

// evaluate tries the daemon first (has session state for Phase 2), falls back to inline Phase 1.
func evaluate(req *normalizedRequest) *aegis.Decision {
	if d := tryDaemon(req); d != nil {
		return d
	}
	return evalInline(req)
}

// tryDaemon sends the request to the daemon's Unix socket. Returns nil if daemon is unreachable.
func tryDaemon(req *normalizedRequest) *aegis.Decision {
	body, _ := json.Marshal(daemonRequest{
		Tool:    req.Tool,
		Args:    req.Arguments,
		CWD:     req.CWD,
		AgentID: agentID(req),
	})

	client := &http.Client{
		Timeout: daemonTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ctx, "unix", daemonSocketPath)
			},
		},
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), "POST", "http://daemon/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Aegis-Version", daemonAPIVersion)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil // daemon not running
	}
	defer resp.Body.Close()

	var dr daemonResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil
	}

	return &aegis.Decision{
		Action:         aegis.Action(dr.Action),
		Rule:           dr.Rule,
		Severity:       dr.Severity,
		Confidence:     dr.Confidence,
		Evidence:       dr.Evidence,
		CompositeScore: dr.CompositeScore,
		Stage:          aegis.EvaluationStage(dr.Stage),
	}
}

// evalInline runs the engine in-process (Phase 1 only, no session state).
func evalInline(req *normalizedRequest) *aegis.Decision {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	engine, err := aegis.NewEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: engine init error (fail-open):", err)
		return &aegis.Decision{Action: aegis.ActionAllow, Rule: "engine_error"}
	}

	return engine.Evaluate(ctx, &aegis.Request{
		Tool:      req.Tool,
		Arguments: req.Arguments,
		CWD:       req.CWD,
		// No AgentID: stateless inline evaluation
	})
}

// agentID derives a stable agent ID from the CWD for session tracking in daemon mode.
func agentID(req *normalizedRequest) string {
	if req.CWD == "" {
		return ""
	}
	return "hook:" + req.CWD
}

func writeWAL(req *normalizedRequest, d *aegis.Decision, latencyUs int64) {
	w := getWAL()
	if w == nil {
		return
	}
	argSummary := req.Tool
	if cmd, ok := req.Arguments["command"]; ok {
		if s, ok := cmd.(string); ok && s != "" {
			argSummary = s
			if len(argSummary) > 120 {
				argSummary = argSummary[:120]
			}
		}
	}
	w.Write(telemetry.Event{ //nolint:errcheck
		Time:           time.Now(),
		Tool:           req.Tool,
		ArgSummary:     argSummary,
		Action:         string(d.Action),
		Rule:           d.Rule,
		Severity:       d.Severity,
		Confidence:     d.Confidence,
		CompositeScore: d.CompositeScore,
		Stage:          string(d.Stage),
		LatencyUs:      latencyUs,
	})
}

func defaultLogPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	dir := filepath.Join(home, ".aegis")
	os.MkdirAll(dir, 0o700) //nolint:errcheck
	return filepath.Join(dir, "audit.log")
}

func parseHookInput(data []byte) (*normalizedRequest, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	req := &normalizedRequest{}

	if _, hasCommand := raw["command"]; hasCommand {
		req.Tool = "Shell"
		req.Arguments = map[string]any{"command": raw["command"]}
		req.CWD = stringField(raw, "cwd")
		return req, nil
	}

	if serverName, hasServer := raw["serverName"]; hasServer {
		toolName := stringField(raw, "tool")
		req.Tool = "MCP:" + fmt.Sprint(serverName) + ":" + toolName
		req.Arguments = mapField(raw, "input")
		req.CWD = stringField(raw, "cwd")
		return req, nil
	}

	if tool, hasTool := raw["tool"]; hasTool {
		req.Tool = fmt.Sprint(tool)
		req.Arguments = mapField(raw, "input")
		req.CWD = stringField(raw, "cwd")
		return req, nil
	}

	return nil, fmt.Errorf("unrecognized hook input format (no command, tool, or serverName field)")
}

func writeAllow() {
	json.NewEncoder(os.Stdout).Encode(hookResponse{Permission: "allow"}) //nolint:errcheck
}

func writeDeny(d *aegis.Decision) {
	desc := ruleDescriptions[d.Rule]
	if desc == "" {
		desc = "Security policy violation"
	}

	evidenceLines := ""
	if len(d.Evidence) > 0 {
		evidenceLines = "\n\nEvidence:\n"
		for _, e := range d.Evidence {
			evidenceLines += "  - " + e + "\n"
		}
		evidenceLines = strings.TrimRight(evidenceLines, "\n")
	}

	userMsg := fmt.Sprintf(
		"Blocked by Aegis [rule: %s]\n%s%s\n\nTo override: add to .aegis/allowlist.yaml or run with AEGIS_MODE=audit\nTo disable temporarily: export AEGIS_MODE=off",
		d.Rule, desc, evidenceLines,
	)
	agentMsg := fmt.Sprintf(
		"Request blocked by Aegis security policy. Rule: %s. Severity: %s. Action: %s.",
		d.Rule, d.Severity, d.Action,
	)

	json.NewEncoder(os.Stdout).Encode(hookResponse{ //nolint:errcheck
		Permission:   "deny",
		UserMessage:  userMsg,
		AgentMessage: agentMsg,
	})
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mapField(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]any); ok {
			return sub
		}
	}
	return map[string]any{}
}
