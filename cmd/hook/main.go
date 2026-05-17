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
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
	"github.com/mayjain/aegis/pkg/aegis/telemetry"
)

const daemonSocketPath = "/tmp/aegis-daemon.sock"
const daemonTimeout = 200 * time.Millisecond

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
	"evasion_with_danger":       "Command uses evasion techniques with dangerous operations",
	"unknown_network_write":     "Command writes data to an unknown external host",
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
	Phase          int      `json:"phase"`
}

var wal *telemetry.WAL // opened once per process, nil if unavailable

func init() {
	// Try to open the WAL for audit logging. Non-fatal if unavailable.
	logPath := defaultLogPath()
	if logPath != "" {
		w, err := telemetry.Open(logPath)
		if err == nil {
			wal = w
		}
	}
}

func main() {
	// Fail-open on empty input to avoid breaking the IDE
	input, err := io.ReadAll(os.Stdin)
	if err != nil || len(strings.TrimSpace(string(input))) == 0 {
		writeAllow()
		return
	}

	// Fail-open on engine panics
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "aegis: panic recovered:", r)
			writeAllow()
		}
	}()

	mode := strings.ToLower(os.Getenv("AEGIS_MODE"))
	if mode == "off" {
		writeAllow()
		return
	}

	req, err := parseHookInput(input)
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

	resp, err := client.Post("http://daemon/evaluate", "application/json", bytes.NewReader(body))
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
		Phase:          dr.Phase,
	}
}

// evalInline runs the engine in-process (Phase 1 only, no session state).
func evalInline(req *normalizedRequest) *aegis.Decision {
	engine, err := aegis.NewEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: engine init error (fail-open):", err)
		return &aegis.Decision{Action: aegis.ActionAllow, Rule: "engine_error"}
	}

	return engine.Evaluate(context.Background(), &aegis.Request{
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
	if wal == nil {
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
	wal.Write(telemetry.Event{ //nolint:errcheck
		Time:           time.Now(),
		Tool:           req.Tool,
		ArgSummary:     argSummary,
		Action:         string(d.Action),
		Rule:           d.Rule,
		Severity:       d.Severity,
		Confidence:     d.Confidence,
		CompositeScore: d.CompositeScore,
		Phase:          d.Phase,
		LatencyUs:      latencyUs,
	})
}

func defaultLogPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	dir := filepath.Join(home, ".aegis")
	os.MkdirAll(dir, 0o755) //nolint:errcheck
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

	userMsg := fmt.Sprintf(
		"Blocked by Aegis [rule: %s]\n%s\n\nTo override: add to .aegis/allowlist.yaml or run with AEGIS_MODE=audit\nTo disable temporarily: export AEGIS_MODE=off",
		d.Rule, desc,
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
