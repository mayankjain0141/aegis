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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mayjain/aegis/pkg/aegis"
)

// hookResponse is the JSON written to stdout for Cursor.
type hookResponse struct {
	Permission  string `json:"permission"`
	UserMessage string `json:"user_message,omitempty"`
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
	"system_control":            "Command attempts system control (shutdown/reboot/halt)",
	"raw_socket_open":           "Command opens a raw network socket",
	"privilege_escalation":      "Command attempts privilege escalation",
	"secret_leakage":            "Command contains sensitive credentials or API keys",
	"sensitive_file_access":     "Command accesses sensitive system files outside the project",
	"data_exfiltration":         "Command may exfiltrate data to an external host",
	"remote_code_execution":     "Command downloads and executes remote code",
	"suid_manipulation":         "Command attempts to set the SUID bit",
	"cron_persistence":          "Command installs a cron job for persistence",
	"bashrc_persistence":        "Command modifies shell profile with exec/network content",
	"evasion_with_danger":       "Command uses evasion techniques with dangerous operations",
	"unknown_network_write":     "Command writes data to an unknown external host",
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

	// Audit/off mode shortcuts
	mode := strings.ToLower(os.Getenv("AEGIS_MODE"))
	if mode == "off" {
		writeAllow()
		return
	}

	req, err := parseHookInput(input)
	if err != nil {
		// Malformed input → fail-open
		fmt.Fprintln(os.Stderr, "aegis: parse error (fail-open):", err)
		writeAllow()
		return
	}

	engine, err := aegis.NewEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: engine init error (fail-open):", err)
		writeAllow()
		return
	}

	decision := engine.Evaluate(context.Background(), &aegis.Request{
		Tool:      req.Tool,
		Arguments: req.Arguments,
		CWD:       req.CWD,
	})

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

func parseHookInput(data []byte) (*normalizedRequest, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	req := &normalizedRequest{}

	// Detect hook type by fields present
	if _, hasCommand := raw["command"]; hasCommand {
		// beforeShellExecution: {"command": "...", "cwd": "..."}
		req.Tool = "Shell"
		req.Arguments = map[string]any{"command": raw["command"]}
		req.CWD = stringField(raw, "cwd")
		return req, nil
	}

	if serverName, hasServer := raw["serverName"]; hasServer {
		// beforeMCPExecution: {"serverName": "...", "tool": "...", "input": {...}}
		toolName := stringField(raw, "tool")
		req.Tool = "MCP:" + fmt.Sprint(serverName) + ":" + toolName
		req.Arguments = mapField(raw, "input")
		req.CWD = stringField(raw, "cwd")
		return req, nil
	}

	if tool, hasTool := raw["tool"]; hasTool {
		// preToolUse: {"tool": "...", "input": {...}, "cwd": "..."}
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
		"Blocked by Aegis [rule: %s]\n%s\n\nTo override: add to .aegis/allowlist.yaml or run with AEGIS_MODE=audit\nTo disable temporarily: export AEGIS_MODE=off\nTo report false positive: aegis report --id %s",
		d.Rule, desc, d.Rule,
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
