# ADR 004: Source-address derivation and RSA key-size floor

Status: ACCEPTED

Issues: #42, #44

## Context

OpenSSH certificates can include a `source-address` critical option that limits where the certificate may be used. In the direct AWS Lambda invocation model, Lambda does not provide the function with a trustworthy TCP peer address for the eventual SSH client connection. BLESS-compatible callers may provide source-address values in the signing request, but request payload fields are caller-controlled.

GoBless also accepts RSA public keys for BLESS/OpenSSH compatibility. Accepting undersized RSA keys would be a silent security regression, especially for older BLESS-era clients or fixtures that might still use 1024-bit RSA.

## Decision

GoBless derives `source-address` from the signing request payload. It is caller-supplied input, not a network-layer fact observed or enforced by Lambda. The value may be copied into the SSH certificate only after policy validation against configured allowed ranges and normal CIDR parsing.

The CA trusts the caller to supply an accurate intended source address, but does not treat that claim as proof of network location. The relying SSH server is the enforcement point: OpenSSH evaluates the certificate's `source-address` critical option at authentication time against the client's observed address.

GoBless rejects RSA keys below 2048 bits. The default and minimum configurable `CA.RSAMinKeyBits` value is 2048. This applies as a deliberate security floor for RSA CA/user-key validation paths; deployments may choose a higher minimum but must not lower it.

## Rationale

Lambda invocation authenticates the AWS principal, not the later SSH network path. Because the eventual SSH connection may originate from a workstation, bastion, VPN, or automation host that is separate from the Lambda invocation path, GoBless cannot reliably infer the SSH source address from Lambda's network metadata. Treating the payload value as untrusted but policy-validated preserves BLESS compatibility without pretending Lambda has network enforcement context.

A 2048-bit RSA floor matches common contemporary minimums and prevents accidental acceptance of 1024-bit RSA keys while retaining compatibility with typical BLESS/OpenSSH RSA deployments. Larger keys remain allowed by policy/configuration.

## Consequences

- Request-body `source-address` values must be validated before they appear in certificate critical options.
- If `source-address` is absent, GoBless should not invent a network-derived value; policy decides whether absence is allowed or denied.
- Audit records should capture the requested and/or approved source-address value when present so operators can investigate misuse.
- Operators that need stronger source-location guarantees must combine GoBless policy with network controls, bastion workflows, VPN enforcement, or a trusted integration that supplies source context.
- Existing clients or tests using RSA keys smaller than 2048 bits must rotate or regenerate keys before GoBless will sign them.
