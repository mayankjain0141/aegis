---
name: Bug Report
about: Report incorrect behavior in rule evaluation, CLI, or daemon
title: '[BUG] '
labels: bug
assignees: ''
---

## Aegis version

```
# paste output of: aegis version
```

## OS + Go version

```
# paste output of: uname -a && go version
```

## Reproduction

Exact command that triggers the bug:

```bash
aegis simulate --tool X --command Y
```

## Expected behavior

What should happen.

## Actual behavior

What actually happened. Include any error messages verbatim.

## WAL output

Last few lines of `aegis telemetry show` if available:

```
# paste output here
```

## Config (sanitized)

Contents of `.aegis/config.yaml` with any secrets or tokens removed:

```yaml
# paste sanitized config here
```

## Additional context

Anything else that might be relevant (recent upgrades, unusual environment, related issues, etc.).
