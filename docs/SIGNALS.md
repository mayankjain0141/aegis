# Aegis Signal Reference

Aegis computes a `SignalBundle` for every tool call. Each signal field is derived from the
tool name, arguments, and working directory. These signals drive policy rule evaluation.

Use `aegis simulate --tool T --command C` to see live signal values for any request.

---

## Signal 1: ToolClass

**Type:** `ToolClassSignal`

Classifies the tool into a category and assigns a base risk score. This is always
the first computation because it determines whether command extraction runs at all.

| Field | Type | Description |
|---|---|---|
| `Category` | string | `shell`, `file_read`, `file_write`, `file_delete`, `search`, `network_read`, `unknown` |
| `Score` | float64 | Base risk for the tool type (0.0–1.0) |

Base scores by category:
- `shell` = 0.60 (arbitrary code execution)
- `file_delete` = 0.70 (irreversible)
- `file_write` = 0.30 (can corrupt state)
- `network_read` = 0.15 (external data)
- `file_read` = 0.05 (read-only)
- `search` = 0.02 (read-only, no side effects)
- `unknown` = 0.40 (conservative default)

Example condition:
```yaml
condition:
  tool_category: shell
```

---

## Signal 2: Command

**Type:** `CommandSignal`

Extracted command binaries with their individual danger scores. Only populated for
shell tools; empty for file/search tools.

| Field | Type | Description |
|---|---|---|
| `Commands` | `[]ResolvedCommand` | All parsed command invocations (binary, args, wrappers) |
| `Verbs` | `[]string` | Deduplicated list of binary names |
| `VerbDanger` | `map[string]float64` | Per-binary danger score (0.0–1.0) |
| `MaxVerbDanger` | float64 | Highest danger score across all verbs |
| `Paths` | `[]string` | Paths extracted from shell arguments |
| `Hosts` | `[]string` | Hosts extracted from shell arguments |

Notable danger scores:
- `rm` = 0.80, `passwd` = 0.80
- `mkfs`, `fdisk`, `dd`, `shred` = 0.90–0.95
- `sudo`, `su`, `pkexec` = 0.70
- `nc`, `ncat`, `socat`, `telnet` = 0.85
- `curl`, `wget` = 0.20 base (boosted to 0.70 with data upload flags)
- `git`, `go`, `npm` = 0.05

Example condition using `expr` to check specific verb:
```yaml
condition:
  expr: "max_verb_danger > 0.7"
```

Example condition using `verb_danger` threshold:
```yaml
condition:
  verb_danger:
    rm: { gt: 0.5 }
```

---

## Signal 3: Path

**Type:** `PathSignal`

File path risk analysis. Paths are extracted from shell arguments, file tool paths,
and redirect targets.

| Field | Type | Description |
|---|---|---|
| `Paths` | `[]AnalyzedPath` | All analyzed paths with per-path breakdown |
| `HasCritical` | bool | Any path is a critical system directory (`/etc`, `/dev`, `/usr`, etc.) |
| `HasSensitive` | bool | Any path matches a sensitive pattern (`.ssh`, `.aws`, `.env`, credentials) |
| `AllInProject` | bool | All paths are within the git project root |
| `MaxPathRisk` | float64 | Highest risk score across all paths |

Critical paths include: `/dev`, `/proc`, `/sys`, `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/lib`.

Sensitive paths include: `/.ssh/`, `/.aws/credentials`, `/.kube/config`, `/.gnupg/`, `.env`,
`credentials.json`, `*.pem`, `*.p12`, SSH private keys.

Example condition:
```yaml
condition:
  path:
    has_critical: true
    has_sensitive: false
```

Example expr condition:
```yaml
condition:
  expr: "has_critical && max_path_risk > 0.85"
```

---

## Signal 4: Network

**Type:** `NetworkSignal`

Network destination and intent analysis. Extracted from `curl`, `wget`, `nc`, `scp`,
`rsync`, `ssh`, and related binaries.

| Field | Type | Description |
|---|---|---|
| `Hosts` | `[]AnalyzedHost` | All detected network destinations with classification |
| `HasDataFlag` | bool | Upload flags present (`-d`, `--data`, `-F`, `-T`) |
| `HasStdinPipe` | bool | Command reads from stdin into a network binary |
| `Score` | float64 | Computed risk score (0.0–1.0) |

Score semantics:
- 0.05 — all hosts are known-safe package registries
- 0.10 — all hosts are internal (localhost, LAN)
- 0.30 — some hosts unknown, read-only
- 0.60–0.85 — data upload to unknown host
- 0.90 — stdin pipe into network binary
- 0.95 — known-bad host

Example condition:
```yaml
condition:
  network:
    score: { gt: 0.5 }
    has_data_flag: true
```

---

## Signal 5: DLP

**Type:** `DLPSignal`

Data Loss Prevention — scans all string arguments for leaked credentials and secrets.

| Field | Type | Description |
|---|---|---|
| `Hits` | `[]DLPHit` | All matched patterns with provider and is-test flag |
| `HasHit` | bool | At least one credential pattern matched |
| `AllTest` | bool | All matches are test/placeholder credentials |
| `Score` | float64 | 0.10 if all test, 0.90 if any real credential detected |

Detected providers: AWS keys (`AKIA...`), GitHub tokens (`ghp_`, `ghs_`, `github_pat_`),
Stripe (`sk_live_`), OpenAI (`sk-...`), Anthropic (`sk-ant-...`), Google (`AIza...`),
Slack (`xoxb-`, `xoxp-`), Twilio, SendGrid, PEM private keys.

Test credentials (containing `placeholder`, `example`, `test`, `fake`, `dummy`) are
detected but scored low.

Example condition — block only real credentials:
```yaml
condition:
  dlp:
    has_hit: true
    all_test: false
```

Example expr:
```yaml
condition:
  expr: "dlp_has_hit && !dlp_all_test"
```

---

## Signal 6: Evasion

**Type:** `EvasionSignal`

Detects obfuscation and evasion techniques.

| Field | Type | Description |
|---|---|---|
| `WrappersStripped` | int | Count of wrappers like `sudo`, `env`, `timeout`, `nohup` |
| `VarsExpanded` | bool | Variable assignment hiding a dangerous command |
| `VarsRevealedDanger` | bool | Variable expansion produced a dangerous verb |
| `ShellRecursionDepth` | int | Nested `sh -c '...'` depth |
| `EncodingDetected` | bool | Base64/hex decode piped to shell, or curl piped to bash |
| `CommandSubstitution` | bool | `$(dangerous-cmd)` or backtick with dangerous verb |
| `Score` | float64 | Composite evasion score (0.0–1.0) |

Score contributions:
- +0.10 per wrapper stripped (max 0.30)
- +0.40 if vars revealed a dangerous verb
- +0.20 if shell recursion depth > 1
- +0.50 if encoding piped to shell (highest single indicator)
- +0.30 if command substitution with dangerous verb

Example condition:
```yaml
condition:
  evasion:
    encoding_detected: true
```

Example — escalate on combined evasion + danger:
```yaml
condition:
  and:
    - expr: "evasion_score > 0.3"
    - expr: "max_verb_danger > 0.7"
```

---

## Signal 7: MLScore

**Type:** `float64`

Heuristic machine learning score for command maliciousness (0.0–1.0). Computed by
`signals.MLScorer` using n-gram patterns and token-level features. This is supplemental
— it never overrides a high-confidence rule decision.

Example condition:
```yaml
condition:
  expr: "ml_score > 0.8"
```

---

## Composite Score

**Type:** `float64` (on `Decision`)

Weighted sum of all signal scores for observability. Not used for decisions — only for
dashboards, WAL records, and the `aegis simulate` display.

```
composite = tool_class * 0.15
          + max_verb_danger * 0.20
          + max_path_risk * 0.20
          + network_score * 0.15
          + dlp_score * 0.10
          + evasion_score * 0.10
          + ml_score * 0.10
```
