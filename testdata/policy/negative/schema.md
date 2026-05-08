# Negative Policy Fixture Schema

Each fixture is a JSON object with these fields:

- `name` string: stable case identifier, usually matching the file name without `.json`.
- `description` string: human-readable deny scenario.
- `request` object: requested certificate parameters.
  - `cert_type` string: requested certificate type, e.g. `user` or `host`.
  - `principals` array of strings, `null`, or omitted when testing missing/null principal behavior.
  - `ttl_seconds` number when TTL is relevant.
  - `critical_options` object for options such as `source-address`.
  - `public_key` string: placeholder public key text for fixture-only requests.
- `iam_context` object: caller identity data used for authorization decisions.
  - `arn` string
  - `account_id` string
  - `username` string
- `policy` object: expected policy settings relevant to the case.
- `expected` object:
  - `decision`: always `deny` for this catalog.
  - `reason` string: stable reason label suitable for test assertions.
  - `no_leak_assertions` array of strings that must not appear in returned errors or logs. Include generic secret/panic sentinels rather than real credentials.
- `expected_denial_reason` string: optional human-readable denial substring for consumers that index fixtures without expanding `expected`. When omitted, tests derive the expected substring from `expected.reason`.

Fixtures must not contain real private keys, credentials, or production account IDs. Account IDs such as `111122223333`, `123456789012`, and `444455556666` are AWS documentation-style placeholders only.
