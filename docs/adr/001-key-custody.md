# ADR 001: CA key custody

Status: ACCEPTED

Issue: #18

## Context

GoBless signs SSH certificates with a CA private key. If that private key is exposed, an attacker can mint trusted SSH certificates until the CA key is removed from every relying host. Classic BLESS deployments commonly used encrypted private key material available to Lambda. AWS KMS asymmetric signing provides a stronger custody boundary but requires integration with KMS signing APIs and OpenSSH-compatible signature handling.

## Decision

GoBless will prefer AWS KMS asymmetric signing. The CA private key must remain inside KMS for production deployments.

GoBless will support encrypted PEM as an explicitly configured fallback only. PEM mode must carry a prominent production warning in documentation, config validation output, and reviewer notes. It is for local development, migration, compatibility testing, or exceptional environments that cannot use KMS.

## Rationale

KMS asymmetric signing reduces the blast radius of Lambda compromise. A compromised Lambda invocation can request signatures while it has permissions, but it cannot directly read or export the private key. KMS also gives operators IAM controls, key policy controls, CloudTrail events, and rotation/revocation workflows that fit AWS deployments.

Encrypted PEM is operationally simpler and closer to classic BLESS, but the plaintext key must exist in Lambda memory during signing. That makes memory disclosure, unsafe logging, crash artifacts, or dependency bugs materially worse.

## Consequences

### KMS asymmetric signing

Positive consequences:
- CA private key never leaves KMS.
- Lambda code handles signing results, not private key bytes.
- KMS permissions can be constrained to `kms:Sign` for the specific key.
- CloudTrail can record signing activity independently of GoBless audit.

Negative consequences:
- KMS integration adds AWS SDK dependency surface behind an internal signer interface.
- Tests need KMS fakes and golden signature verification fixtures.
- OpenSSH certificate signing must correctly map KMS algorithms and signature formats.
- Local development needs either a fake signer or explicit PEM fallback.

Residual risks:
- Overbroad KMS key policies can allow unintended signing outside GoBless.
- A compromised Lambda role can still ask KMS to sign malicious certificates until IAM or key policy is corrected.
- KMS availability affects certificate issuance.

### Encrypted PEM fallback

Positive consequences:
- Enables local tests and migration from existing BLESS key material.
- Avoids KMS dependency for non-production or constrained deployments.
- Makes fixture generation straightforward.

Negative consequences:
- Plaintext private key exists in process memory.
- Passphrase and encrypted key storage become operational secrets that GoBless must read.
- Go cannot guarantee complete zeroization of decrypted key material.
- A Lambda memory disclosure becomes potential CA compromise.

Residual risks:
- PEM mode remains vulnerable to runtime memory disclosure even with careful logging and short-lived processes.
- Operators may ignore warnings and deploy PEM mode to production; config and documentation must make that choice explicit and reviewable.
