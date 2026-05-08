## Summary
<!-- What does this PR do? Which issue(s) does it address? -->

## Test evidence
<!-- What tests were added or updated? Which test-matrix rows does this satisfy? -->
<!-- Paste go test output or CI link. -->

## Security considerations
<!-- Does this touch signing, key material, principal validation, audit, Lambda handlers, or config? -->
<!-- If this is security-sensitive, a security-focused review must be completed before merge. -->

## Dependency changes
<!-- List any new dependencies added. Each requires explicit justification per DEPENDENCY_POLICY.md. -->
<!-- If none: "No new dependencies." -->

## Compatibility impact
<!-- Any BLESS compatibility changes? Reference COMPATIBILITY.md. -->
<!-- If none: "No compatibility impact." -->

## Review checklist
- [ ] `go vet ./...` passes
- [ ] `go test -race ./...` passes
- [ ] Security review complete (required when touching `internal/cert`, `internal/policy`, or `internal/signer`)
- [ ] Test matrix rows identified or updated
- [ ] No new unreviewed dependencies
- [ ] No secrets, key material, or stack traces in logs or error responses
- [ ] Docs updated if behavior changed
- [ ] If this PR fixes a blocking security review finding: regression case added to `testdata/regression/`

## Escalation
<!-- If reviewers disagree on a security question, open a discussion thread or tag a maintainer for resolution. -->
