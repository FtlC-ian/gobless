# Principal Unicode / Homoglyph Injection

**Package:** policy
**Reference:** policy Unicode validation follow-up
**Severity:** BLOCKING

## What Was Wrong

Principal names were not validated for character set, allowing non-ASCII Unicode characters to be submitted in signing requests. This created a homoglyph attack surface: an attacker (or misconfigured client) could supply a principal containing Cyrillic, Greek, or other Unicode lookalikes that appear identical to an authorized ASCII principal in human-readable diffs, logs, or audit UIs, while being byte-distinct.

Although the policy engine would correctly reject an unauthorized principal, the audit trail would show a string that *appeared* authorized — creating confusion and potential for social-engineering escalation.

## The Fix

GoBless **rejects** any principal containing characters outside the ASCII printable range (U+0020–U+007E) via an ASCII-only regex, with an additional 255-byte maximum length. There is no NFC normalization or opt-in Unicode model exposed in v0.1. The strict ASCII gate is preserved by the regression tests listed below.

## Test Coverage

- `internal/policy/policy_test.go` — `TestUnicodeHomoglyphPrincipalsDenied`
  Supplies principals containing Cyrillic and other non-ASCII lookalikes; asserts validation returns an error.
- `internal/policy/policy_test.go` — `TestOverlyLongPrincipalDenied`
  Asserts principals exceeding 255 bytes are rejected.

## References

- Test file: `internal/policy/policy_test.go`
