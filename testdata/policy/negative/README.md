# Negative Policy Fixtures

This catalog contains JSON deny-case fixtures for authorization, principal normalization, TTL validation, source-address validation, certificate-type boundaries, and IAM identity binding.

Each fixture is intentionally small and implementation-neutral. Tests should load every `*.json` file in this directory, submit the described request/context to the policy layer, and assert that the request is denied with a sanitized error.

Format details are documented in [`schema.md`](schema.md).
