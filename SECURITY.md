# Security Policy

Aegis is a runtime security engine for AI coding agents. We take vulnerability reports
seriously and aim to respond quickly and transparently.

---

## Supported Versions

| Version | Status |
|---------|--------|
| `main` (v2.x) | Supported — receives security patches |
| v1.x (OPA-based) | End of life — no longer maintained |

If you are running v1.x, upgrade to v2.x before reporting issues; the architecture
has been replaced entirely.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public disclosure
before a patch is available puts users at risk.

### Preferred: GitHub Security Advisories (private)

Use GitHub's built-in private reporting:

> **Repository → Security tab → "Report a vulnerability"**

This creates an encrypted, private advisory visible only to maintainers. GitHub will
notify you of acknowledgment and keep you updated through the advisory thread.

### Fallback: Email

If you cannot use GitHub advisories, email:

```
aegis-security@[maintainer domain]
```

If no email address is configured in the repository, open a private GitHub Security
Advisory as described above. Do not use public channels (issues, discussions, social
media) for initial disclosure.

### PGP

PGP encryption is not required but is supported if you prefer it. Request the
maintainer's public key via the advisory thread before sending encrypted mail.

### What to include in your report

Provide as much of the following as possible:

- **Version**: output of `aegis version` or the git commit hash
- **Reproduction steps**: a minimal `aegis simulate --tool <tool> --command '<cmd>'`
  invocation that demonstrates the issue, or a crafted policy/allowlist file
- **Expected behavior**: what Aegis should have done (e.g., "should have fired rule
  `net.exfil.dns`")
- **Actual behavior**: what it did instead (e.g., "returned ALLOW with no WAL entry")
- **Severity assessment**: your estimate of impact (critical / high / medium / low)
  and whether you believe it is exploitable in a default configuration

Incomplete reports are still welcome — we will follow up with questions.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment | Within 48 hours of receipt |
| Initial assessment | Within 5 business days |
| Patch — critical severity | Within 7 days of confirmation |
| Patch — high severity | Within 30 days of confirmation |
| Coordinated public disclosure | After patch is available, coordinated with reporter |

We will keep you informed at each stage through the advisory thread. If you have not
received an acknowledgment within 48 hours, follow up in the same thread.

---

## Scope

### In scope

The following are security vulnerabilities in Aegis:

- **Policy bypass (false negative)**: a documented threat pattern fires no rule and
  returns ALLOW when it should have been blocked or flagged
- **Path traversal in policy loading**: a crafted `policies/*.yaml` path causes Aegis
  to read files outside the policies directory
- **OPA/Rego evaluation escape**: the `rego:` field executes arbitrary code beyond
  standard OPA policy evaluation
- **Expr evaluation escape**: the `expr:` condition field accesses the filesystem,
  network, or environment variables beyond the documented `SignalBundle` fields
- **Engine panic → fail-open without WAL entry**: a panic in the engine core results
  in a silent ALLOW with no Write-Ahead Log record (panics should fail-open only as
  a documented last resort and must produce a WAL entry)
- **WAL poisoning or audit log manipulation**: a crafted input corrupts or silently
  drops WAL entries, undermining the audit trail
- **Unix socket authentication bypass**: the daemon IPC socket accepts commands from
  processes that should not have access
- **Allowlist bypass that is not a documented limitation**: a non-human actor can
  expand the effective allowlist beyond what `.aegis/allowlist.yaml` permits

### Out of scope

The following are **not** treated as security vulnerabilities:

- **Accuracy gaps**: the ML model assigns a low score to a pattern it was not trained
  to detect. These are evaluation corpus issues, tracked separately.
- **Bugs in wrapped tools**: vulnerabilities in `bash`, `curl`, `rm`, or other
  intercepted tools themselves are upstream issues.
- **Allowlist bypasses by an authorized human**: if a person with write access to
  `.aegis/allowlist.yaml` edits it to permit an action, that is by design.
- **Social engineering the user**: manipulating a human to approve an action is not
  a technical vulnerability in the engine.
- **Performance degradation via adversarial input**: crafted inputs that slow
  evaluation are noted as medium severity and tracked as hardening issues, not
  security vulnerabilities.

When in doubt, report it. We would rather triage a non-issue than miss a real one.

---

## Security Design Principles

Aegis is designed around two complementary failure modes:

**Fail-open on infrastructure errors.** If the hook itself panics (e.g., an
unexpected nil pointer in signal collection), the agent's action is allowed and a WAL
entry is written. IDE usability for legitimate work takes priority over blocking on
transient infrastructure failures, but the audit trail is never silently dropped.

**Fail-secure on policy uncertainty.** If an LLM-based scoring call times out or
returns an error, the result is DENY. Uncertainty does not become permission.

Additional hardening decisions:

- **OPA `http.send` disabled**: Rego conditions cannot make outbound network requests,
  preventing data exfiltration through policy evaluation.
- **Expr sandboxed**: the `expr:` field evaluates against `SignalBundle` fields only.
  It has no access to the filesystem, environment, or network.
- **`predictTree` bounds-checked**: the ML tree traversal validates node indices
  before each step. A crafted model JSON cannot cause an out-of-bounds panic.
- **WAL is append-only**: the audit log is written before policy disposition is
  returned to the caller, so a crash after the WAL write still produces a record.

---

## Known Limitations

We document these openly because accurate expectations build more trust than
overpromising.

**ML model accuracy (pipe-to-shell patterns):** The QuasarNix model specializes in
socket-based reverse shells. Pipe-to-shell patterns such as `curl | bash` score lower
than expected from the model (approximately 0.004 in testing). A heuristic fallback
rule covers these cases, but the coverage comes from the heuristic layer, not the
model score.

**Phase 2 analysis requires the daemon:** Behavioral analysis — session history,
command sequence detection, EWMA baseline scoring — is only available when the Aegis
daemon is running. When invoked inline without the daemon, only Phase 1 (per-command
signal evaluation) is active. Sequence-level detections do not fire in this mode.

**No multi-tenant isolation:** Aegis is a single-user tool. Allowlists are scoped
to a project directory, not to individual users. Running Aegis in a shared or
multi-user environment is not a supported configuration and provides no per-user
isolation guarantees.
