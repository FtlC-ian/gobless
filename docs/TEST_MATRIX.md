# GoBless Test Matrix

Schema:

| Issue | Feature/Risk | Test file path | Category | Pass criteria | Security-review required |
| --- | --- | --- | --- | --- | --- |
| #4 | SSH user certificate issuance preserves BLESS-compatible certificate fields and OpenSSH readability. | internal/cert/bless_compat_test.go | Golden/compatibility | Generated user cert matches expected normalized `ssh-keygen -L` fields and is parseable by OpenSSH tooling. | Yes |
| #6 | Policy denies unauthorized or privileged principals and rejects malformed principal lists. | internal/policy/policy_test.go | Negative/policy | Requests for mismatched, privileged, empty, null, whitespace, or homoglyph principals are denied with sanitized errors. | Yes |
| #7 | TTL enforcement prevents zero, negative, and overlong certificate validity windows. | internal/cert/cert_test.go | Negative/policy | TTL boundary tests reject invalid TTLs and accept only configured bounds without overflow or truncation. | Yes |
| #8 | Source-address critical option validation prevents malformed or unsafe CIDR constraints. | internal/cert/cert_test.go | Negative/policy | Invalid source-address options are denied; valid CIDR options are encoded exactly in certificate critical options. | Yes |
| #9 | Lambda request compatibility and sanitized error responses for BLESS-style callers. | internal/lambda/handler_test.go | Lambda fixture | Valid user/host events route correctly; malformed events return expected status and no leak assertions pass. | Yes |
| #13 | Host certificate issuance cannot be reached through user certificate paths or policy bypasses. | internal/policy/policy_test.go | Negative/policy | Host cert requests through user handlers are denied; valid host cert flow is separately covered by host fixtures. | Yes |
| #14 | IAM identity binding prevents account/ARN partial-match authorization bypasses. | internal/policy/policy_test.go | Negative/policy | Account mismatches and partial ARN matches are denied even when usernames or principal substrings match. | Yes |
