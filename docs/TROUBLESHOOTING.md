# Troubleshooting

Diagnosis guide for common Aegis issues. Most issues can be diagnosed with:

```bash
aegis doctor    # self-diagnostic check
aegis simulate --tool Shell --command "..."  # trace any decision
aegis explain <rule-name>  # inspect a rule's condition
```

If none of these resolve your issue, open a [GitHub Discussion](https://github.com/mayjain/aegis/discussions) or check [FAQ.md](FAQ.md).

---

## 1. Hook not blocking commands — daemon not running

**Symptom**: `aegis simulate` shows DENY but the Cursor/Claude Code agent still executes the command.

**Diagnosis**:
```bash
aegis daemon status
# Expected: Status: running (PID ..., socket /tmp/aegis-daemon.sock)
# If "Status: not running": hook is falling back to inline Phase 1 only
```

**Fix**:
```bash
aegis daemon start
# Verify:
aegis daemon status
```

When the daemon is unavailable, the hook falls back to stateless inline Phase 1 evaluation — no session history, no behavioral analysis. Commands that require Phase 2 pattern detection (`retry_after_deny`, `exfil_sequence`, `rate_burst`, `sudden_tool_shift`) won't be caught until the daemon is running.

---

## 2. ML model not loading (heuristic fallback active)

**Symptom**: `aegis doctor` shows `UseHeuristic: true`. Suspiciously high false negative rate on socket-based reverse shells or obfuscated commands.

**Diagnosis**:
```bash
aegis doctor
# Look for: "ML model: heuristic fallback" vs "Real XGBoost model loaded"
ls pkg/aegis/signals/models/
# Missing quasarnix.json or quasarnix_vocab.json → model not downloaded
```

**Fix**:
```bash
make models
# Downloads and converts the QuasarNix model from HuggingFace (~265KB total)
aegis doctor
# Verify: "Real XGBoost model loaded"
```

---

## 3. False positive — legitimate command blocked

**Symptom**: `aegis simulate --tool Shell --command "curl https://api.github.com/..."` returns DENY for a command you know is safe.

**Diagnosis**:
```bash
# See exactly which rule fired and why
aegis simulate --tool Shell --command "your command here"
# Inspect the Signals section to see which signal triggered the rule

aegis explain data_exfiltration
# Replace data_exfiltration with whichever rule fired
```

**Fix** (apply in order of preference):

1. Generate an allowlist entry from the last blocked event:
   ```bash
   aegis allow last
   # Paste the output into .aegis/allowlist.yaml
   ```

2. Reduce sensitivity globally:
   ```bash
   aegis config set sensitivity permissive
   ```

3. Write a higher-priority allow rule in `policies/custom.yaml`, then validate:
   ```bash
   aegis validate policies/custom.yaml
   ```

---

## 4. Allowlist entry not working

**Symptom**: `.aegis/allowlist.yaml` has an entry but the command still gets blocked.

**Diagnosis**:
```bash
aegis simulate --tool Shell --command "your allowlisted command"
# If the result is still DENY, the pattern is not matching
```

Common mistakes:
- A `hosts:` entry like `registry.internal` matches the hostname field, not the shell command string. Use the `commands:` section: `docker push registry.internal/*`
- Glob matching requires the full command: `docker push registry.internal/myapp` needs `docker push registry.internal/*`
- `paths_safe:` entries only affect file-read/write tools (`Write`, `Edit`, `StrReplace`), not shell commands

**Fix**:
```bash
# Regenerate from the last blocked event:
aegis allow last
# Paste the generated YAML into .aegis/allowlist.yaml, then verify:
aegis simulate --tool Shell --command "your command"
```

---

## 5. WAL growing too large

**Symptom**: `~/.aegis/audit.log` is over 50 MB or growing rapidly during normal sessions.

**Diagnosis**:
```bash
aegis telemetry show
# Displays total event count and time range

ls -lh ~/.aegis/audit.log
```

**Fix**:
```bash
# Option 1: Configure rotation in .aegis/config.yaml
# logging:
#   max_size_mb: 10
#   max_files: 5

# Option 2: Clear immediately (loses history)
aegis telemetry clear

# Option 3: Manual rotation
mv ~/.aegis/audit.log ~/.aegis/audit.log.bak
```

The WAL rotates automatically once `max_size_mb` is reached, shifting `audit.log` → `audit.log.1` → ... up to `max_files` copies. With no rotation config, the file grows without bound.

---

## 6. Phase 3 LLM classification slow or failing

**Symptom**: Hook responses take ~200ms. Decisions show `stage: intent_llm`. Some commands get unexpected DENY with rule `llm_timeout` or `llm_refusal`.

**Diagnosis**:
```bash
aegis config show
# Check: llm_classifier.enabled  true
```

**Fix**:
```bash
# Recommended: disable Phase 3 unless you specifically need it
aegis config set llm_classifier.enabled false

# Alternative: switch to a faster model in .aegis/config.yaml:
# llm_classifier:
#   model: claude-haiku-4-5
```

Phase 3 only fires for ESCALATE decisions (ambiguous commands not resolved by Phase 1 or Phase 2). On LLM timeout or unparseable response, Aegis fails secure and denies — an unavailable LLM cannot be used to bypass policy by exhausting the timeout window. This behavior is intentional.

---

## 7. Rule not matching as expected

**Symptom**: A command you expect to be blocked passes through (or vice versa).

**Diagnosis**:
```bash
# Step 1: Trace the full decision
aegis simulate --tool Shell --command "your command"

# Step 2: Inspect the rule you expect to fire
aegis explain your_rule_name

# Step 3: List all rules sorted by priority to find collisions
aegis rules list

# Step 4: Validate policy files for syntax errors
aegis validate policies/
```

Common causes:
- Priority collision: a lower-priority rule with identical conditions shadows a higher-priority one
- An allow rule with a lower priority number fires before a deny rule (priority 5 allow beats priority 10 deny)
- YAML condition field misspelled — e.g., `verbs:` instead of `any_verb:` — `aegis validate` catches this

**Fix**:
```bash
# Test your condition directly after editing:
aegis simulate --tool Shell --command "..."

# Adjust rule priority or condition, then re-validate:
aegis validate policies/custom.yaml
```
