## Summary
<!-- What does this MR do? Which issue(s) does it address? -->

## Test evidence
<!-- What tests were added or updated? Which #27 test-matrix rows does this satisfy? -->
<!-- Paste go test output or CI link. -->

## Security considerations
<!-- Is this security-sensitive (hawk-required label)? If yes, Hawk audit must be linked before merge. -->
<!-- Does this touch signing, key material, principal validation, audit, Lambda handlers, or config? -->

## Dependency changes
<!-- List any new dependencies added. Each requires explicit justification per DEPENDENCY_POLICY.md. -->
<!-- If none: "No new dependencies." -->

## Compatibility impact
<!-- Any BLESS compatibility changes? Reference COMPATIBILITY.md. -->
<!-- If none: "No compatibility impact." -->

## Review checklist
- [ ] Builder and reviewer are from different model families (or human review)
- [ ] `go vet ./...` passes
- [ ] `go test -race ./...` passes
- [ ] Hawk audit complete and linked (required for hawk-required issues)
- [ ] Test matrix rows in #27 identified or updated
- [ ] No new unreviewed dependencies
- [ ] No secrets, key material, or stack traces in logs or error responses
- [ ] Docs updated if behavior changed

## Escalation
<!-- If builder and reviewer disagree on a security question, tag @ian for resolution. -->
