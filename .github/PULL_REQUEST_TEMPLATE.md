## Summary
<!-- One sentence: what does this PR do? -->

## Changes
<!-- Bullet list of what changed -->

## Testing
<!-- How did you test this? -->

## Checklist
- [ ] `go test ./...` passes
- [ ] `aegis validate policies/` passes (if YAML changed)
- [ ] `make eval` passes — recall ≥ 90%, FPR ≤ 5% (if rules or corpus changed)
- [ ] `go test -race ./...` clean (if engine code changed)
- [ ] Docs updated (if CLI or public API changed)
- [ ] One commit per logical change

## Related issues
<!-- Closes #XX -->
