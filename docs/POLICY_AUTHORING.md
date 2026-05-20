# Writing Aegis Policy Rules

Aegis policies are YAML files in the `policies/` directory. Rules are evaluated in priority order — lowest number wins.

## Quick Start

Copy an existing rule and modify it:

```yaml
rules:
  - name: my_custom_deny
    priority: 20
    action: deny
    severity: high
    confidence: 0.90
    description: "Blocks my specific dangerous pattern."
    remediation: "Do not do the thing."
    tags: [custom]
    condition:
      any_verb: [badtool]
```

Test it immediately:
```bash
aegis validate policies/my-rules.yaml
aegis simulate --tool Shell --command "badtool --arg"
```

## Rule Structure

| Field | Required | Description |
|---|---|---|
| `name` | yes | Unique snake_case identifier |
| `priority` | yes | Evaluation order (lower = earlier). 10-22=deny, 50-70=allow, 90-100=escalate |
| `action` | yes | `deny`, `allow`, `escalate`, or `throttle` |
| `severity` | no | `critical`, `high`, `medium`, `low` |
| `confidence` | yes | 0.0–1.0. Rules with confidence >= 0.85 are final decisions |
| `description` | yes | What the rule does and what it triggers on |
| `remediation` | no | How the user can fix the flagged behavior |
| `tags` | no | List of string labels for filtering |
| `condition` | yes | The match expression (see below) |

## Condition DSL — Tier 1: Declarative

Declarative fields are ANDed together at the top level.

### `any_verb`
Matches if any extracted command binary is in the list.
```yaml
condition:
  any_verb: [rm, shred, wipe]
```

### `all_verbs_safe`
Matches if every verb in the command has a known-safe score.
```yaml
condition:
  all_verbs_safe: true
```

### `tool_category`
Matches the tool type. Values: `shell`, `file_read`, `file_write`, `file_delete`, `search`, `other`.
```yaml
condition:
  tool_category: shell
# or match multiple:
  tool_category: [file_read, file_write]
```

### `path`
Matches based on path risk analysis.
```yaml
condition:
  path:
    has_critical: true      # path is /etc, /dev, /usr, /boot, etc.
    has_sensitive: true     # path matches .ssh, .aws, .env, credentials, etc.
    all_in_project: false   # all paths are inside the project root
```

### `network`
Matches based on network signals.
```yaml
condition:
  network:
    score: { gt: 0.5 }     # overall network risk score
    has_data_flag: true     # curl/wget -d/--data flag present (upload risk)
    has_stdin_pipe: true    # reading from stdin into a network tool
```

### `dlp`
Matches if a credential/secret pattern was detected in the arguments.
```yaml
condition:
  dlp:
    has_hit: true           # a real secret was found (not a test fixture)
    all_test: false         # all hits are test fixtures
```

### `evasion`
Matches on obfuscation signals (base64, hex encoding, suspicious redirects).
```yaml
condition:
  evasion:
    encoding_detected: true
    score: { gt: 0.3 }
```

### `verb_danger`
Matches on per-verb danger score thresholds.
```yaml
condition:
  verb_danger:
    rm: { gt: 0.5 }
    curl: { gte: 0.7 }
```

### Combinators: `and`, `or`, `not`
```yaml
condition:
  and:
    - any_verb: [rm, dd]
    - path:
        has_critical: true
  or:
    - dlp:
        has_hit: true
    - evasion:
        encoding_detected: true
  not:
    path:
      all_in_project: true
```

## Condition DSL — Tier 2: Expr

For logic that Tier 1 cannot express, use the `expr` field. The expression language is [Expr](https://github.com/expr-lang/expr).

Available variables:
- `tool` — tool name string (e.g. `"Shell"`)
- `verbs` — `[]string` of extracted command binaries
- `commands` — `[]Command` with `.binary`, `.args []string`, `.full_path`
- `has_critical` — bool
- `has_sensitive` — bool
- `all_in_project` — bool
- `max_path_risk` — float (0.0–1.0)
- `max_verb_danger` — float (0.0–1.0)
- `network_score` — float (0.0–1.0)
- `dlp_has_hit` — bool
- `dlp_all_test` — bool
- `evasion_score` — float (0.0–1.0)
- `ml_score` — float (0.0–1.0)
- `composite_score` — float (0.0–1.0)

```yaml
condition:
  expr: "max_verb_danger > 0.7 && network_score > 0.3"
```

```yaml
# Check specific go subcommand:
condition:
  expr: >
    any(commands, {.binary == "go" && len(.args) > 0 && .args[0] == "build"})
```

## Condition DSL — Tier 3: Rego

For complex policy-as-code, use `rego`. The `rego_rule` field sets the query (default: `data.aegis.deny`).

```yaml
condition:
  rego: |
    package aegis
    default deny = false
    deny {
      input.signals.network.score > 0.5
      input.signals.evasion.score > 0.2
    }
  rego_rule: "data.aegis.deny"
```

## Testing Your Rules

```bash
# Validate YAML syntax and schema:
aegis validate policies/my-rules.yaml

# See what the rule does:
aegis explain my_custom_deny

# Simulate a specific command:
aegis simulate --tool Shell --command "badtool --dangerous-arg"

# List all rules by priority:
aegis rules list

# Filter by action:
aegis rules list --action deny
```

## Priority Guide

| Range | Convention |
|---|---|
| 10–22 | Deny rules (highest urgency) |
| 50–70 | Allow rules (safe-path short-circuits) |
| 90–100 | Escalate rules (human review required) |

Lower priority numbers evaluate first. A deny at priority 10 fires before an allow at priority 50, so order your deny rules before allow rules when there's potential overlap.

If two rules in the same file have the same priority and both match, the first one declared wins. Use distinct priorities when ordering matters.

## Common Patterns

### Deny a verb only in dangerous contexts

```yaml
condition:
  and:
    - any_verb: [curl, wget]
    - network:
        has_data_flag: true
    - path:
        has_sensitive: true
```

### Allow a specific safe subcommand

```yaml
condition:
  expr: >
    any(commands, {.binary == "docker" && len(.args) > 0 && .args[0] == "ps"})
```

### Escalate anything touching .env files

```yaml
condition:
  and:
    - path:
        has_sensitive: true
    - expr: "any(verbs, {# == 'cat' || # == 'cp' || # == 'mv'})"
```

---

## Tier 2: Expr — Complex Predicates

**When to use**: when Tier 1 declarative fields can't express the condition because you need to:
- Inspect specific command arguments (e.g., `crontab -e` vs `crontab -l`)
- Check file paths for specific prefixes or patterns
- Look at full command structure (binary, args, full path)

Expr uses [expr-lang](https://github.com/expr-lang/expr) — a safe, sandboxed expression language that compiles to bytecode at load time. ~95ns/op evaluation.

### Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `tool_category` | `string` | Tool classification: `"shell"`, `"file_read"`, `"file_write"`, `"file_delete"`, `"search"` |
| `verbs` | `[]string` | Extracted binary names from the command (e.g., `["curl", "bash"]`) |
| `commands` | `[]ExprCommand` | Resolved commands with fields: `.binary`, `.args[]`, `.full_path` |
| `paths` | `[]string` | Normalized file path strings from arguments |
| `max_verb_danger` | `float64` | Highest danger score among all extracted verbs [0–1] |
| `has_critical` | `bool` | Any path targets `/etc`, `/boot`, `/dev`, `/usr`, `/bin`, `/sbin` |
| `has_sensitive` | `bool` | Any path matches `.ssh`, `.aws`, `.env`, credentials patterns |
| `all_in_project` | `bool` | All paths are inside the git project root |
| `network_score` | `float64` | Network risk score [0–1] |
| `has_data_flag` | `bool` | `curl`/`wget` `-d`/`--data` flag present (data upload) |
| `has_stdin_pipe` | `bool` | stdin is redirected into a network tool |
| `dlp_has_hit` | `bool` | A real credential was detected (not a test fixture) |
| `dlp_all_test` | `bool` | All DLP hits are in test fixture files |
| `evasion_score` | `float64` | Obfuscation/encoding signal score [0–1] |
| `encoding_detected` | `bool` | Base64, hex, or other encoding detected |
| `wrappers_stripped` | `int` | Number of `sudo`, `env`, `exec` wrappers removed during extraction |
| `ml_score` | `float64` | XGBoost maliciousness probability [0–1] |

### Available Methods

- `HasPrefix(s string, prefix string) bool`
- `HasSuffix(s string, suffix string) bool`
- `Contains(s string, sub string) bool`

### Expr Syntax

- Array iteration: `any(commands, {.binary == "bash"})` — `#` is the current element in filter expressions
- String methods: `HasPrefix(.full_path, "/tmp/")`
- Boolean logic: `&&`, `||`, `!`
- Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
- `len(array)`, `all(array, condition)`, `any(array, condition)`

### Production Examples

**`cron_persistence`** — checks whether `crontab` is invoked with editing flags (`-e`) or replace/remove (`-r`), blocking modification of the user's crontab:

```yaml
condition:
  expr: >
    any(commands, {
      .binary == "crontab" && any(.args, {# == "-e" || # == "-r"})
    })
```

**`execute_from_tmp`** — blocks shell interpreters executing scripts located under `/tmp` or `/var/tmp` by checking `.full_path` and the first argument:

```yaml
condition:
  expr: >
    any(commands, {HasPrefix(.full_path, "/tmp/") || HasPrefix(.full_path, "/var/tmp/")})
```

```yaml
# Also matches: bash /tmp/run.sh (script path in args)
condition:
  expr: >
    any(commands, {
      (.binary == "bash" || .binary == "sh" || .binary == "zsh") &&
      len(.args) > 0 && .args[0] != "-c" &&
      (HasPrefix(.args[0], "/tmp/") || HasPrefix(.args[0], "/var/tmp/"))
    })
```

**`bashrc_persistence`** — matches writes to shell RC/profile files combined with any network activity, using `HasSuffix` on path strings:

```yaml
condition:
  and:
    - expr: >
        any(paths, {
          HasSuffix(#, ".bashrc") || HasSuffix(#, ".profile") || HasSuffix(#, ".zshrc") ||
          HasSuffix(#, ".bash_profile") || HasSuffix(#, ".zprofile") || HasSuffix(#, ".fish")
        })
    - or:
        - expr: "network_score > 0.1"
        - evasion:
            encoding_detected: true
```

**`suid_manipulation`** — checks `chmod` arguments for SUID/SGID bit patterns (`+s`, `u+s`, `g+s`, or octal `4xxx`):

```yaml
condition:
  expr: >
    any(commands, {
      .binary == "chmod" &&
      any(.args, {# == "+s" || # == "u+s" || # == "g+s" ||
        (len(#) == 4 && # startsWith "4") || Contains(#, "+s")})
    })
```

### Combining Tier 1 and Tier 2

Tier 1 conditions evaluate first. Use them as a fast pre-filter before the expr expression is run:

```yaml
condition:
  any_verb: [curl, wget]      # Tier 1: verb check (fast, evaluated first)
  expr: >                     # Tier 2: only evaluated if verb check passes
    any(commands, {.binary == "bash" || .binary == "sh"})
```

**Performance note**: The `expr:` field is compiled at startup into a bytecode program — there is no parsing overhead per request. Evaluation is ~95ns/op.

---

## Tier 3: Rego — Custom Organization Policies

**When to use**:
- Your organization already has an OPA policy infrastructure
- You need policies that require complex multi-document analysis
- You want to express policies in a language your security team already knows

```yaml
condition:
  rego: |
    package aegis.custom

    import rego.v1

    deny if {
        input.verbs[_] == "curl"
        input.network_score > 0.5
    }
  rego_rule: "data.aegis.custom.deny"
```

**Input document** (`input`): the same fields as the expr environment, serialized as JSON. All signal bundle fields are available: `tool_category`, `verbs`, `max_verb_danger`, `has_critical`, `has_sensitive`, `all_in_project`, `network_score`, `has_data_flag`, `dlp_has_hit`, `dlp_all_test`, `evasion_score`, `encoding_detected`, `ml_score`.

### Security Restrictions

The following OPA builtins are **disabled** in Aegis Rego policies:
- `http.send` — no network calls from policy evaluation
- `opa.runtime` — no runtime introspection
- `net.lookup_ip_addr`, `net.cidr_contains_matches` — no DNS/network
- `io.jwt.*` — no JWT operations (decode, encode_sign, verify_*)

This ensures Rego policies cannot exfiltrate tool call data to an attacker endpoint.

**Performance**: ~1-5ms per evaluation. Rego is only invoked on the ESCALATE path (ambiguous commands that Phase 1 couldn't classify confidently). It does not run on every tool call.

### Working Example

From `policies/rego/example.rego`:

```rego
# Example custom Rego policy for Aegis
# This policy fires when curl downloads from an unknown host and pipes to bash
package aegis.example

import rego.v1

# deny is true when the command is a remote code execution pattern
deny if {
    input.verbs[_] == "curl"
    input.has_data_flag == false # GET request (not posting data)
    input.evasion_score > 0.3
}

# Allow safe network reads (GET requests to known hosts with no sensitive paths)
allow if {
    input.network_score <= 0.3
    input.has_data_flag == false
    input.has_sensitive == false
    input.has_critical == false
}
```

---

## Behavioral Conditions

Behavioral conditions match against session-level signals — they require session history and are only evaluated in **Phase 2** (when the daemon is running). A rule with only `behavioral:` conditions will return false in Phase 1 stateless mode.

```yaml
condition:
  behavioral:
    retry_after_deny: true    # agent retried a previously denied action
```

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `retry_after_deny: true` | bool | The current action was previously denied in this session |
| `sequence_risk: { gte: 0.85 }` | threshold | Session matches a known attack sequence pattern |
| `rate_burst: { gte: 0.80 }` | threshold | Call rate significantly exceeds session baseline |
| `baseline_deviation: { gt: 0.70 }` | threshold | Tool usage pattern far from established baseline (requires ≥10 samples) |

**Threshold operators**: `gt`, `gte`, `lt`, `lte`

### Sequence Patterns

Sequence patterns are defined in `policies/data/sequences.yaml`. Each pattern defines an ordered multi-step chain that must occur within a time window:

| Pattern | Window | Risk | Description |
|---------|--------|------|-------------|
| `exfil_after_sensitive_read` | 30s | 0.90 | Sensitive file read followed by a network write |
| `encoded_exfil` | 60s | 0.85 | Sensitive read → base64 encoding → network write |
| `escalating_access` | 120s | 0.75 | Non-critical path access progressing to critical path access |

### Example Behavioral Rule

```yaml
rules:
  - name: retry_after_deny
    priority: 10
    action: deny
    severity: high
    confidence: 0.90
    description: >
      Blocks when an agent retries an action that was previously denied.
      A legitimate agent should stop or seek approval after a deny.
    condition:
      behavioral:
        retry_after_deny: true
```

### Requiring the Daemon

Behavioral rules only fire when `aegis daemon start` is running. Without the daemon, Phase 2 is skipped and behavioral conditions always return false.
