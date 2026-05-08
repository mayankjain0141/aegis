package policy

import (
	"context"
	"testing"
)

var defaultRulesYAML = `
version: "test-v1"
policies:
  - name: block-destructive-shell
    match:
      tool: shell_exec
      args_pattern: "(rm -rf|DROP TABLE|shutdown|reboot|mkfs|dd if=)"
    action: deny
    severity: critical

  - name: block-secret-access
    match:
      tool: file_read
      args_pattern: "(\\.env|credentials|secrets|private_key|id_rsa)"
    action: deny
    severity: high

  - name: rate-limit-all
    match:
      tool: "*"
    rate_limit:
      max_per_minute: 60
    action: throttle

  - name: default-allow
    match:
      tool: "*"
      agent_id: "*"
    action: allow
    severity: low
`

var policyTests = []struct {
	name        string
	yamlRules   string
	tool        string
	args        string
	agentID     string
	callsPerMin int
	wantAction  Action
	wantPolicy  string
}{
	{
		name:       "blocks rm -rf",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"rm -rf /"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "blocks DROP TABLE",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"DROP TABLE users"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "blocks shutdown",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"shutdown -h now"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "blocks reboot",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"reboot"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "blocks mkfs",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"mkfs.ext4 /dev/sda1"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "blocks dd if=",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"dd if=/dev/zero of=/dev/sda"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-destructive-shell",
	},
	{
		name:       "allows ls",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"ls -la"}`,
		wantAction: ActionAllow,
		wantPolicy: "default-allow",
	},
	{
		name:       "allows safe shell commands",
		yamlRules:  defaultRulesYAML,
		tool:       "shell_exec",
		args:       `{"command":"git status"}`,
		wantAction: ActionAllow,
		wantPolicy: "default-allow",
	},
	{
		name:       "blocks .env read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":".env"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-secret-access",
	},
	{
		name:       "blocks credentials read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":"config/credentials.json"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-secret-access",
	},
	{
		name:       "blocks private_key read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":"/home/user/.ssh/private_key"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-secret-access",
	},
	{
		name:       "blocks id_rsa read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":"~/.ssh/id_rsa"}`,
		wantAction: ActionDeny,
		wantPolicy: "block-secret-access",
	},
	{
		name:       "allows readme read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":"README.md"}`,
		wantAction: ActionAllow,
		wantPolicy: "default-allow",
	},
	{
		name:       "allows normal file read",
		yamlRules:  defaultRulesYAML,
		tool:       "file_read",
		args:       `{"path":"main.go"}`,
		wantAction: ActionAllow,
		wantPolicy: "default-allow",
	},
	{
		name:        "rate limits flood",
		yamlRules:   defaultRulesYAML,
		tool:        "shell_exec",
		args:        `{"command":"ls"}`,
		callsPerMin: 100,
		wantAction:  ActionThrottle,
		wantPolicy:  "rate-limit-all",
	},
	{
		name:        "no throttle under limit",
		yamlRules:   defaultRulesYAML,
		tool:        "shell_exec",
		args:        `{"command":"ls"}`,
		callsPerMin: 30,
		wantAction:  ActionAllow,
		wantPolicy:  "default-allow",
	},
	{
		name: "glob matches shell_*",
		yamlRules: `
version: "glob-test"
policies:
  - name: block-all-shell
    match:
      tool: "shell_*"
    action: deny
    severity: high
  - name: fallback-allow
    match:
      tool: "*"
    action: allow
`,
		tool:       "shell_exec",
		args:       `{}`,
		wantAction: ActionDeny,
		wantPolicy: "block-all-shell",
	},
	{
		name: "glob does not match non-shell",
		yamlRules: `
version: "glob-test"
policies:
  - name: block-all-shell
    match:
      tool: "shell_*"
    action: deny
    severity: high
  - name: fallback-allow
    match:
      tool: "*"
    action: allow
`,
		tool:       "file_read",
		args:       `{}`,
		wantAction: ActionAllow,
		wantPolicy: "fallback-allow",
	},
	{
		name: "agent pattern matches specific agent",
		yamlRules: `
version: "agent-test"
policies:
  - name: block-untrusted
    match:
      tool: "*"
      agent_id: "untrusted_*"
    action: deny
    severity: high
  - name: fallback-allow
    match:
      tool: "*"
    action: allow
`,
		tool:       "shell_exec",
		args:       `{}`,
		agentID:    "untrusted_bot",
		wantAction: ActionDeny,
		wantPolicy: "block-untrusted",
	},
	{
		name: "agent pattern does not match trusted agent",
		yamlRules: `
version: "agent-test"
policies:
  - name: block-untrusted
    match:
      tool: "*"
      agent_id: "untrusted_*"
    action: deny
    severity: high
  - name: fallback-allow
    match:
      tool: "*"
    action: allow
`,
		tool:       "shell_exec",
		args:       `{}`,
		agentID:    "trusted_bot",
		wantAction: ActionAllow,
		wantPolicy: "fallback-allow",
	},
	{
		name: "escalate action works",
		yamlRules: `
version: "escalate-test"
policies:
  - name: escalate-network
    match:
      tool: network_call
    action: escalate_human
    severity: medium
`,
		tool:       "network_call",
		args:       `{"url":"https://example.com"}`,
		wantAction: ActionEscalateHuman,
		wantPolicy: "escalate-network",
	},
	{
		name: "no rules fallback deny",
		yamlRules: `
version: "empty"
policies: []
`,
		tool:       "anything",
		args:       `{}`,
		wantAction: ActionDeny,
		wantPolicy: "",
	},
	{
		name: "exact tool match",
		yamlRules: `
version: "exact-test"
policies:
  - name: block-specific
    match:
      tool: "code_exec"
    action: deny
  - name: fallback-allow
    match:
      tool: "*"
    action: allow
`,
		tool:       "code_exec",
		args:       `{}`,
		wantAction: ActionDeny,
		wantPolicy: "block-specific",
	},
	{
		name: "first match wins (order matters)",
		yamlRules: `
version: "order-test"
policies:
  - name: allow-first
    match:
      tool: shell_exec
    action: allow
  - name: deny-second
    match:
      tool: shell_exec
    action: deny
`,
		tool:       "shell_exec",
		args:       `{}`,
		wantAction: ActionAllow,
		wantPolicy: "allow-first",
	},
	{
		name:        "rate limit at exact boundary not triggered",
		yamlRules:   defaultRulesYAML,
		tool:        "file_read",
		args:        `{"path":"foo.txt"}`,
		callsPerMin: 60,
		wantAction:  ActionAllow,
		wantPolicy:  "default-allow",
	},
	{
		name:        "rate limit just above boundary triggered",
		yamlRules:   defaultRulesYAML,
		tool:        "file_read",
		args:        `{"path":"foo.txt"}`,
		callsPerMin: 61,
		wantAction:  ActionThrottle,
		wantPolicy:  "rate-limit-all",
	},
}

func TestStaticEvaluator(t *testing.T) {
	for _, tc := range policyTests {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := parseYAML([]byte(tc.yamlRules))
			if err != nil {
				t.Fatalf("failed to parse yaml: %v", err)
			}

			req := &ToolCallRequest{
				Tool:      tc.tool,
				Arguments: tc.args,
				AgentID:   tc.agentID,
			}
			if tc.callsPerMin > 0 {
				req.SessionCtx = &SessionContext{
					CallsLastMinute: tc.callsPerMin,
				}
			}

			decision, err := eval.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision == nil {
				t.Fatal("expected decision, got nil")
			}
			if decision.Action != tc.wantAction {
				t.Errorf("action: got %q, want %q", decision.Action, tc.wantAction)
			}
			if decision.PolicyName != tc.wantPolicy {
				t.Errorf("policy: got %q, want %q", decision.PolicyName, tc.wantPolicy)
			}
		})
	}
}

func TestStaticEvaluator_NilRequest(t *testing.T) {
	eval, _ := parseYAML([]byte(`version: "test"
policies: []`))
	_, err := eval.Evaluate(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestEvaluatorChain_DefaultDeny(t *testing.T) {
	chain := EvaluatorChain{}
	decision, err := chain.Evaluate(context.Background(), &ToolCallRequest{Tool: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionDeny {
		t.Errorf("expected deny, got %q", decision.Action)
	}
}

type nilEvaluator struct{}

func (n *nilEvaluator) Evaluate(_ context.Context, _ *ToolCallRequest) (*PolicyDecision, error) {
	return nil, nil
}

func TestEvaluatorChain_PassThrough(t *testing.T) {
	eval, _ := parseYAML([]byte(`
version: "chain-test"
policies:
  - name: allow-all
    match:
      tool: "*"
    action: allow
`))
	chain := EvaluatorChain{&nilEvaluator{}, eval}
	decision, err := chain.Evaluate(context.Background(), &ToolCallRequest{Tool: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Errorf("expected allow, got %q", decision.Action)
	}
	if decision.PolicyName != "allow-all" {
		t.Errorf("expected policy 'allow-all', got %q", decision.PolicyName)
	}
}
