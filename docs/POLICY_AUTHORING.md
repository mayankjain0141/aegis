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
