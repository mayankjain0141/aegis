# Aegis

> A runtime governance and observability layer for autonomous AI coding agents.

Aegis sits between AI agents and their tools — intercepting every action, enforcing policy, scoring risk, and blocking unsafe behavior before execution. Think: a firewall + Datadog, purpose-built for AI agents.

## The Problem

AI agents (Claude Code, Cursor, Codex) can autonomously execute shell commands, modify files, and call APIs. There is no standardized infrastructure to enforce what an agent is allowed to do, trace why it made a decision, or block dangerous behavior in real-time.

**Aegis explores**: What does zero-trust infrastructure look like for AI agents?

## Demo

```
┌─────────────────────────────────────────────────────────────┐
│ Aegis Attack Simulation Report                              │
├──────────────────────────┬──────────┬──────────┬────────────┤
│ Attack                   │ Attempts │ Blocked  │ Rate       │
├──────────────────────────┼──────────┼──────────┼────────────┤
│ Prompt Injection         │ 3        │ 3        │ 100%       │
│ Privilege Escalation     │ 2        │ 2        │ 100%       │
│ Data Exfiltration        │ 4        │ 4        │ 100%       │
│ Resource Exhaustion      │ 100      │ 40       │ ≥40/100    │
│ Recursive/Destructive    │ 2        │ 2        │ 100%       │
├──────────────────────────┼──────────┼──────────┼────────────┤
│ TOTAL                    │ 111      │ 51       │ 46%        │
└──────────────────────────┴──────────┴──────────┴────────────┘
```

All targeted attacks blocked. Rate limiting kicks in after 60 calls/minute threshold.

## How It Works

```
Agent ──stdio──▶ aegis-shim ──unix socket──▶ aegis-daemon ──exec──▶ tool
                                                    │
                                              ┌─────┴─────┐
                                              │ Policy    │ Risk     │
                                              │ Engine    │ Scorer   │
                                              └───────────┴──────────┘
                                                    │
                                              ┌─────┴─────┐
                                              │ Trace     │ Session  │
                                              │ Collector │ Registry │
                                              └───────────┴──────────┘
                                                    │
                                              ┌─────┴─────┐
                                              │ PostgreSQL│ WebSocket│
                                              │ (traces)  │ (live)   │
                                              └───────────┴──────────┘
```

The **shim** is a drop-in stdio wrapper that agents talk to as if it were the real MCP tool server. It forwards JSON-RPC requests over a Unix socket to the **daemon**, which runs the full governance pipeline before deciding to allow, deny, escalate, or throttle.

## Quick Start

```bash
# Install (requires Go 1.23+)
go install github.com/mayjain/aegis/cmd/daemon@latest
go install github.com/mayjain/aegis/cmd/shim@latest

# Or build from source
git clone https://github.com/mayjain/aegis.git
cd aegis
make build

# Start the daemon
bin/aegis-daemon --policies policies/default.yaml

# In another terminal — watch live traces
bin/aegis-watch

# Run the attack simulation (111 scenarios)
make test-attacks

# Use with Claude Code — add to .cursor/mcp.json:
# {
#   "mcpServers": {
#     "shell": {
#       "command": "aegis-shim",
#       "args": ["--tool", "shell-mcp", "--agent-id", "my-claude"]
#     }
#   }
# }
```

### From source

```bash
# Build all binaries
make build

# Start daemon with default policies
bin/aegis-daemon --policies policies/default.yaml &

# Run the full attack simulation (111 scenarios)
make test-attacks

# Watch live traces (in another terminal)
make watch

# Or run the full demo flow
make demo
```

## Architecture

### Shim/Daemon Split

The shim is intentionally thin (~150 lines). It handles only stdio↔socket bridging so that:
- Agents don't need to know Aegis exists (transparent interception)
- The daemon can enforce policy across multiple concurrent agents
- A crash in governance logic never orphans the agent's stdio pipe

### Why Not Just Use Built-in Agent Permissions?

Claude Code has `/permissions`, Cursor has approval dialogs. These are:
- **Per-product** — no unified policy across agents
- **Binary** — allow/deny, no risk scoring or rate limiting
- **User-facing** — require human intervention, defeating autonomy
- **Unobservable** — no trace log, no audit trail

Aegis provides infrastructure-grade governance that works across any MCP-speaking agent.

## Design Decisions

- **Policy as data, not code** — YAML rules hot-reloaded without restart
- **Risk-adaptive governance** — Not all actions deserve equal scrutiny
- **Fail-closed** — If Aegis can't decide, it denies
- **Interface-based extensibility** — Add ML scorers or OPA without changing the core
- **Non-blocking observability** — Traces never slow down the tool call path

## Policy Example

```yaml
policies:
  - name: block-destructive-shell
    match:
      tool: shell_exec
      args_pattern: "(rm -rf|DROP TABLE|shutdown)"
    action: deny
    severity: critical

  - name: block-secret-access
    match:
      tool: file_read
      args_pattern: "(\\.env|credentials|secrets|private_key)"
    action: deny
    severity: high

  - name: rate-limit-all
    match:
      tool: "*"
    rate_limit:
      max_per_minute: 60
    action: throttle
```

## Attack Simulation

`make test-attacks` runs 111 attack scenarios covering:

| Category | Scenarios | Technique |
|----------|-----------|-----------|
| Prompt Injection | 3 | "ignore previous instructions", "reveal system prompt" |
| Privilege Escalation | 2 | sudo, chmod, setuid |
| Data Exfiltration | 4 | curl POST, nc reverse shell, /dev/tcp |
| Resource Exhaustion | 100 | Rapid-fire calls to trigger rate limiting |
| Recursive/Destructive | 2 | rm -rf, fork bombs |

## Project Structure

```
aegis/
├── cmd/
│   ├── daemon/          # Main governance daemon
│   ├── shim/            # Transparent stdio proxy
│   └── watch/           # Live trace viewer (WebSocket client)
├── internal/
│   ├── daemon/          # Core daemon: router, executor, config
│   ├── policy/          # Policy engine: loader, chain, static rules
│   ├── risk/            # Risk scorer: signals, rate, arg patterns
│   ├── trace/           # Trace collector, WAL, schema
│   ├── session/         # Agent session state machine
│   ├── ipc/             # Unix socket transport + JSON-RPC envelope
│   ├── ws/              # WebSocket hub for live streaming
│   ├── approval/        # Human-in-the-loop escalation gate
│   ├── circuit/         # Circuit breaker for tool backends
│   └── errs/            # Structured error codes
├── agent/
│   ├── harness.py       # Attack simulation harness
│   └── attacks/         # Attack scenario modules
├── policies/            # YAML policy definitions
├── migrations/          # PostgreSQL schema
├── test/e2e/            # Integration tests
└── scripts/             # Demo and automation scripts
```

## Extensibility

Adding a new risk signal:

```go
type MySignal struct{}

func (s *MySignal) Name() string { return "my_signal" }

func (s *MySignal) Score(ctx context.Context, tool string, args string, callsLastMinute int) float64 {
    // Return 0.0–1.0 risk contribution
    if strings.Contains(args, "sensitive") {
        return 0.8
    }
    return 0.0
}
```

Register it in the daemon config and it automatically participates in risk scoring.

## Tradeoffs

| Decision | Rationale |
|----------|-----------|
| No Redis | In-memory sufficient for PoC; interface supports Redis later |
| No ML detection | Heuristic rules are auditable; ML plugs in via `RiskSignal` interface |
| Per-call exec | Simpler than process management; ~50ms overhead acceptable |
| Unix socket IPC | Lower latency than TCP; natural access control via filesystem perms |
| WAL before Postgres | Traces survive daemon crashes; async flush keeps hot path fast |
| Go for daemon | Single binary deployment, low memory, excellent concurrency |

## Tech Stack

- **Go 1.25** — daemon, shim, watcher
- **Python 3** — attack simulator, demo agent
- **PostgreSQL** — trace storage
- **WebSocket** — live dashboard feed
- **YAML** — policy definitions

## License

MIT
