# Security Regression Corpus

This directory contains minimized bug reports and regression cases for security-relevant bugs fixed during GoBless development. It serves as institutional memory and ensures that regressions are caught by the test suite.

## When to Add a Regression Case

Add a regression case when **any** of the following applies:

- A **blocking security review finding** is fixed (mandatory — the same change that fixes the bug must include the regression case)
- A **fuzz discovery** reveals a real bug or edge case worth preserving
- An **ADR-resolved ambiguity** produces a behavior decision that should be regression-tested
- A **BLESS compatibility delta** is found (we differ from upstream in a meaningful way)

If in doubt, add one. Regression cases are cheap; regressions are expensive.

## Directory Layout

Organize files by package/subsystem:

```
testdata/regression/
  cert/       — certificate signing, extensions, validity window, key type handling
  policy/     — principal validation, allow/deny evaluation, extension rules
  config/     — config loading, schema validation, defaults
  log/        — audit log formatting, redaction, structured output
  lambda/     — Lambda handler edge cases, fixture inputs
```

Create the subdirectory if it doesn't exist. Do not put files directly in `testdata/regression/`.

## File Naming Convention

```
<package>_<brief-description>_<issue-or-pr>.<ext>
```

- `<package>`: matches the subdirectory name (`cert`, `policy`, `config`, `log`, `lambda`)
- `<brief-description>`: snake_case, 2–5 words, describes the bug not the fix
- `<reference>`: a short stable reference such as `i<N>`, `pr<N>`, or a descriptive slug
- `<ext>`: `.md` for narrative bug reports; `.json` or `.go` for machine-readable reproducer inputs

Examples:
- `cert/host_cert_extensions_leak_i13.md`
- `policy/principal_unicode_injection_i36.md`
- `config/schema_unknown_field_unknown_field.md`

## File Format (Narrative `.md`)

Each `.md` regression case should be a concise bug report:

```markdown
# <Title>

**Package:** <package>
**Reference:** #N or short slug
**Severity:** BLOCKING | MAJOR | MINOR

## What Was Wrong
<!-- One paragraph. What was the bug? What could go wrong in practice? -->

## The Fix
<!-- One paragraph or bullet list. What changed? -->

## Test Coverage
<!-- Which test(s) now cover this case? File path and test function name. -->

## References
- Test file: `path/to/test.go`
```

## Process Rule

> **When adding a regression case, verify the referenced test file and function name exist with `grep -r <FunctionName> .` before committing.**

This prevents stale or fabricated test references from accumulating in the corpus. If the test does not yet exist, add it in the same change.

## Review Rule

> **Any blocking security review finding that gets fixed MUST have a regression case committed in the same change.**

This is enforced by the PR checklist. Reviewers should reject PRs that fix a BLOCKING finding without a corresponding `testdata/regression/` entry.
