# Aegis — Interview FAQ

Quick reference for common design and implementation questions.

---

## End-to-End Flow

**Q: Walk me through the end-to-end flow.**

1. Cursor fires a `beforeShellExecution`, `preToolUse`, or `beforeMCPExecution` event
2. Cursor reads `.cursor/hooks.json` and forks the `cmd/hook` binary with the event payload on stdin
3. Hook binary deserializes the JSON, extracts the command string and tool metadata
4. Bloom filter check (~100ns) — if command is in the known-safe set, allow immediately
5. Allowlist check (~1µs) — structured allowlist of benign tool patterns
6. Phase 1 Go rules (<50µs) — ~35 priority-ordered named rules evaluate 6 signals; first rule with confidence ≥0.85 is terminal
7. Phase 2 behavioral (<1ms) — hook connects to the daemon over `/tmp/aegis-daemon.sock`; daemon evaluates the call against `session.State` (ring buffer of last 20 calls)
8. Phase 3 LLM (~200ms, opt-in) — if configured, the tool call + last 5 session entries are sent to an LLM classifier; timeout or error → deny
9. Decision written to `~/.aegis/audit.log` (WAL)
10. Hook writes allow or deny JSON to stdout; Cursor acts on it

---

## Hook Binary Model

**Q: What is the hook binary?**

`cmd/hook` is a short-lived Go binary that Cursor spawns synchronously for each event. It reads a single JSON payload from stdin, evaluates it against Aegis policy, and writes a single JSON verdict to stdout. After that it exits. There is no persistent process, no MCP handshake, no WebSocket — just stdin/stdout JSON per invocation.

**Q: How does this differ from the old shim?**

The old architecture used an MCP shim proxy that sat between the agent and every tool binary as a long-lived subprocess. The hook model is simpler and tighter: Cursor owns the event lifecycle via `.cursor/hooks.json`, and Aegis only has to be a stateless decision function from Cursor's perspective. No MCP server, no proxy, no agent-visible intermediary.

**Q: Why stdin/stdout JSON instead of a persistent daemon connection?**

The hook binary is the fast path. Cursor drives the lifecycle — it forks, waits for stdout, and proceeds. stdin/stdout is the lowest-friction interface for that model. Persistent state lives in the daemon; the hook connects to it over a Unix socket when needed, but that is a separate concern from how Cursor talks to the hook.

**Q: What happens when the daemon is not running?**

The hook connects to `/tmp/aegis-daemon.sock` with a 200ms timeout. If the daemon is unavailable (not started, crashed, timeout), the hook falls back to inline Phase 1 evaluation only. Phase 2 behavioral analysis and session state are skipped. The hook still makes a decision — it does not block on the daemon. This is fail-operative for Phase 1, fail-secure for anything that requires session context.

**Q: What does the allow/deny JSON look like?**

```json
{ "action": "allow" }
{ "action": "deny", "reason": "critical_path_destruction", "confidence": 0.97 }
```

Cursor reads the `action` field and either proceeds with the shell command or suppresses it and shows the reason to the user.

---

## Policy Evaluation

**Q: How do Go rules differ from OPA/Rego?**

OPA/Rego is a general-purpose policy language evaluated by a separate runtime. Aegis Phase 1 rules are plain Go functions compiled into the binary. Each rule receives pre-extracted signals (ToolClass, Command, Path, Network, DLP, Evasion) and returns a verdict with a confidence score. There is no query language, no separate process, no serialization overhead — just a function call.

**Q: What is priority-ordered first-match semantics?**

Rules are evaluated in a fixed priority order. The first rule that fires with confidence ≥0.85 terminates evaluation — no further rules run. Lower-priority rules only execute if all higher-priority rules either do not match or return confidence below the terminal threshold. This is not weighted voting: a high-confidence early match cannot be overridden by later rules.

**Q: Why first-match instead of weighted voting?**

Weighted voting requires tuning weights across all rules and can produce unintuitive aggregations — a strong deny signal gets diluted by many weak allow signals. First-match makes the logic auditable: you can read the priority list and know exactly which rule governs a given input. It also makes testing tractable — each rule has a clear domain and can be tested in isolation.

**Q: What is confidence gating?**

Every rule returns a float64 confidence in [0.0, 1.0]. A confidence ≥0.85 marks a Phase 1 verdict as terminal. Confidence below that threshold means the rule matched partially but is not certain enough to stop evaluation. The call continues down the priority list. If no rule reaches terminal confidence, Phase 2 behavioral analysis runs.

**Q: How does a rule "fire"?**

A rule inspects the extracted signals for its domain. For example, `critical_path_destruction` checks whether the Command signal contains `rm`, `shred`, or `truncate` and whether the Path signal resolves to a protected prefix (`/etc`, `/boot`, `~/.ssh`, etc.). If both conditions hold, it returns `Deny` with confidence 0.97. The rule does not see the raw shell string — it sees normalized, expanded signals produced by the two-pass extractor.

**Q: Which DENY rules exist in Phase 1?**

`critical_path_destruction`, `system_control`, `raw_socket_open`, `privilege_escalation`, `critical_path_write`, `secret_leakage`, `sensitive_file_access`, `data_exfiltration`, `remote_code_execution`, `suid_manipulation`, `cron_persistence`, `bashrc_persistence`, `execute_from_tmp`, `evasion_with_danger`. Benign ALLOW rules cover git operations, npm, docker, test runners, file reads, and similar well-understood patterns.

---

## Variable Expansion via Sandboxed Interpreter

**Q: How does variable expansion work?**

`mvdan.cc/sh` is a pure-Go shell library. It has two parts:
- `syntax` — parses a shell string into an AST
- `interp` — executes that AST like a real shell would

Aegis uses `interp` but replaces the exec handler with a recorder:

```go
interp.ExecHandlers(func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
    return func(ctx context.Context, args []string) error {
        commands = append(commands, Command{Name: args[0], Args: args[1:]})
        return nil  // don't call next — execution never happens
    }
})
runner.Run(ctx, prog)
```

The interpreter expands `$HOME`, resolves `$(subshell)`, strips quotes — everything a real shell does before exec — then calls the recorder instead of `execve`. The result is fully-expanded, normalized args with zero execution.

**Q: Is it a real sandbox?**

Not a VM or container. It is simpler: evaluation yes, execution no. Three lines make it safe:
- `StdIO(nil, nil, nil)` — kills I/O
- ExecHandler replacement — kills exec
- `context.WithTimeout(ctx, 10ms)` — kills infinite loops

**Q: Why two passes (AST walk + interpreter)?**

| | AST Walk | Sandboxed Interpreter |
|---|---|---|
| Variables | Unexpanded (`$HOME`) | Expanded (`/root`) |
| Dead branches | Yes (`false && rm`) | No |
| Cost | ~0ms | ~1ms, 10ms timeout |

The AST walk catches everything syntactically, including dead code that the interpreter would skip. The interpreter catches what would actually run with expanded arguments. Both results are merged and deduplicated. Wrapper commands (`sudo`, `env`, `timeout`) are unwrapped iteratively. Recursive shell nesting is followed up to 3 levels deep.

---

## Behavioral Detection (Phase 2)

**Q: What is the session ring buffer?**

The daemon maintains a `session.State` per agent — a ring buffer of the last 20 call records. Each record includes the tool, normalized command, verdict, and timestamp. Phase 2 rules read this buffer to detect patterns that are invisible in a single call.

**Q: How does `retry_after_deny` work?**

After any Phase 1 deny, `retry_after_deny` watches for a semantically equivalent command in the next few calls. If the agent issues a structurally similar command (same tool class, overlapping path or network target) within the session window, the rule fires with elevated confidence. A one-time probe is a mistake; repeated attempts after denial are a signal.

**Q: How does `exfil_sequence` work?**

`exfil_sequence` looks for a sensitive file read (matching DLP patterns — `/etc/passwd`, `~/.ssh/id_rsa`, `.env`, credential file names) followed by any outbound network call within a 30-second window. Neither event alone is necessarily malicious. Together in sequence they match a classic exfiltration pattern.

**Q: What are the other Phase 2 rules?**

`encoded_exfil` — base64 or hex encoding immediately before a network call. `rate_burst` — sudden acceleration in call rate after a calm baseline. `sudden_tool_shift` — agent switches from a benign tool class (file reads, git) to a sensitive one (network, exec) with no intermediate calls. `session_fits_baseline` — inverse rule that confirms a session matches established benign patterns and allows with elevated confidence.

**Q: What happens when the daemon is not running?**

Phase 2 is skipped entirely. The hook falls back to Phase 1 inline evaluation. No session state is accumulated and no behavioral rules fire. Decisions are still correct for single-call threats; multi-call sequences go undetected until the daemon is restarted.

---

## Phase 3 LLM

**Q: When does Phase 3 fire?**

Phase 3 is opt-in — it must be enabled in the Aegis configuration. When enabled, it fires only when Phase 1 and Phase 2 do not reach a terminal verdict. It is not called for every tool event. In a typical session, the vast majority of calls are resolved by Phase 1 or the allowlist without ever reaching Phase 3.

**Q: What gets sent to the LLM?**

The current tool call (tool name, normalized command, extracted signals) plus the last 5 entries from the session ring buffer. The prompt asks the LLM to classify the call as allow or deny with a one-sentence reason, given the session context. It is a classifier call, not a conversation — `max_tokens` is small and the response is parsed for a structured verdict.

**Q: What LLM backends are supported?**

Phase 3 sends requests via LiteLLM, which provides a unified interface over OpenAI-compatible endpoints and Anthropic. The backend is configured in the Aegis config; switching providers does not require code changes.

**Q: What is fail-secure on timeout?**

If the LLM call times out or returns an error, the verdict is `deny` with rule name `llm_timeout`. Aegis does not fail open. An unavailable or slow LLM cannot be used to bypass policy by exhausting the timeout window.

**Q: What is the `llm_refusal` rule?**

If the LLM returns a response that cannot be parsed as a valid verdict (e.g., the model refuses to answer, or the response format is unexpected), the rule `llm_refusal` fires and the call is denied. Same fail-secure principle as `llm_timeout`.

---

## Testing

**Q: How is the policy engine tested?**

Three layers:

`make eval` runs the JSONL corpus in `testdata/eval/*.jsonl`. Each line is a test case with an input payload and an expected verdict. The eval runner reports pass/fail per rule and aggregate precision/recall. This is the primary regression check for Phase 1 rule changes.

Integration tests live in `test/integration/` and exercise the full hook-to-daemon pipeline. They start a real daemon, fire hook invocations over the Unix socket, and assert on verdicts and audit log entries.

Attack simulation is in `scripts/test-attacks.sh`. It replays known-bad command sequences — path traversal variants, exfiltration sequences, evasion patterns — and asserts that all are denied. It is the acceptance test for the behavioral and evasion detection layers.

**Q: What is the JSONL corpus format?**

```jsonl
{"input": {"tool": "shell_exec", "command": "rm -rf ~/.ssh"}, "expected": "deny", "rule": "critical_path_destruction"}
{"input": {"tool": "shell_exec", "command": "git status"}, "expected": "allow", "rule": "git_safe"}
```

Each line is a self-contained test. Adding a new rule means adding corpus lines that cover its match cases and its boundaries — inputs that should match, and inputs just outside the match that should not.
