# GoBless Architecture

GoBless is a Go implementation of a BLESS-compatible serverless SSH certificate authority. It issues short-lived OpenSSH certificates from AWS Lambda after IAM-authenticated invocation and policy validation.

## System overview

```mermaid
flowchart LR
    subgraph Caller[Caller workstation or automation]
        CLI[CLI client]
        PUB[SSH public key]
    end

    subgraph AWSInvoke[API Gateway AWS_IAM invocation layer]
        IAM[AWS IAM / STS identity]
        LAMBDA[Lambda handler]
    end

    subgraph GoBless[GoBless process]
        CFG[Config loader]
        POL[Policy engine]
        CERT[Certificate builder]
        AUDIT[Audit sink]
        SIGN[Signer interface]
    end

    subgraph Custody[CA key custody]
        KMS[AWS KMS asymmetric key]
        PEM[Encrypted PEM fallback]
    end

    CLI -->|AWS_IAM-signed API Gateway request| LAMBDA
    PUB --> CLI
    IAM -->|caller identity context| LAMBDA
    LAMBDA --> CFG
    LAMBDA --> POL
    POL --> CERT
    CERT --> SIGN
    SIGN --> KMS
    SIGN -. explicit fallback only .-> PEM
    LAMBDA --> AUDIT
    LAMBDA -->|OpenSSH certificate or typed error| CLI
```

## Components

### Signer interface

The signer is the only component allowed to perform CA signing. Implementations expose signing and public-key export without revealing private key material. The interface hides KMS and PEM details and returns typed errors that exclude key material, request secrets, and provider internals.

The default implementation uses AWS KMS asymmetric signing. Encrypted PEM is available as an explicit fallback for development, migration, or deployments that cannot use KMS.

### Certificate builder

The certificate builder converts a validated signing request into an `ssh.Certificate`. It parses and validates the submitted SSH public key, builds user and host certificates with approved principals, extensions, critical options, TTL, serial, and key ID, and enforces OpenSSH wire-format constraints.

The builder does not decide whether a principal is allowed — it only consumes policy-approved inputs.

### Policy engine

The policy engine is the authorization decision point. It treats all request-body fields as untrusted and binds IAM caller identity to requested user principals by default. It validates principals against allowlist policy, enforces maximum TTL, allowed critical options, allowed extensions, source-address and force-command restrictions, and rejects malformed, ambiguous, Unicode-confusable, or duplicate principals.

Host certificate authorization is separate from user certificate authorization.

### Lambda handler

The Lambda handler is the request/response adapter. It receives API Gateway proxy events, extracts trusted AWS caller identity from API Gateway request context, decodes request JSON from the event body, and calls config, policy, certificate builder, signer, and audit in order. It returns BLESS-compatible success responses and stable, non-secret error responses.

The handler does not make authorization decisions inline — anything beyond syntactic request rejection goes through policy.

### Config

Config defines compatibility behavior and deployment policy. It loads BLESS-compatible configuration keys and GoBless-native equivalents, validates required keys at startup (CA mode, allowed principals, TTL ceilings, allowed critical options, audit backend, compatibility flags), and fails closed when config is missing, ambiguous, or allows unsafe production behavior without an explicit opt-in. PEM mode surfaces a production warning.

### Audit

Audit records every certificate decision, successful or rejected. It emits structured events containing request ID, AWS caller identity, certificate type, public-key fingerprint, requested principals, approved principals, TTL, KeyID, serial, source address, decision, and reason code. Secrets, private key material, and raw request payloads are never logged.

Audit failures are explicit. Production policy fails closed unless an emergency mode is explicitly configured.

### CLI client

The CLI client is the user-facing request tool. It reads or generates the SSH public key, signs an API Gateway request with AWS credentials, submits BLESS-compatible request bodies, and prints returned certificates. Local development also supports `ca-pubkey` for CA public key export.

## Trust boundaries

| Boundary | What's trusted inside | What's untrusted | Rule |
| --- | --- | --- | --- |
| Caller workstation | User keypair, local CLI arguments | Local shell environment, filesystem, request body | Server validates every requested principal and option. |
| API Gateway AWS_IAM invocation | AWS-authenticated principal and API Gateway request context | Request JSON fields claiming usernames, hosts, TTL, IPs | API Gateway authenticates caller identity; policy authorizes certificate contents. |
| GoBless process | Internal validated request objects | Lambda event payload and environment strings before validation | Decode, validate, and normalize before use. |
| CA key custody | KMS private key or decrypted PEM during signing | Lambda logs, audit events, request/response data | Private key is never serialized or logged; prefer KMS. |
| Audit backend | Append-only audit records and backend IAM controls | Caller-controlled request content | Audit records decisions with redacted, normalized fields. |

## Dependency tree

```text
Lambda handler
├── Config loader
├── Request decoder
├── Policy engine
│   └── Config policy data
├── Certificate builder
│   ├── Random source: crypto/rand
│   └── SSH primitives: golang.org/x/crypto/ssh
├── Signer interface
│   ├── KMS signer: AWS SDK v2 KMS client
│   └── Encrypted PEM signer: crypto/x509 + encoding/pem + ssh primitives
└── Audit sink
    ├── Structured event formatter
    └── Backend implementation, for example DynamoDB via AWS SDK v2

CLI client
├── AWS_IAM-signed HTTPS client for API Gateway
├── SSH key parsing: golang.org/x/crypto/ssh
└── Output formatting
```

No component may import a concrete AWS client except AWS adapter packages. Core policy and certificate construction must be testable without AWS.

## Key flows

### User certificate request

1. CLI reads the user's SSH public key and sends an AWS_IAM-signed request through API Gateway.
2. Lambda receives the API Gateway proxy event and obtains trusted caller identity from request context.
3. Handler decodes request body and rejects malformed JSON or unsupported request type.
4. Config loader supplies policy and compatibility settings.
5. Policy engine validates:
   - requested certificate type is `user`;
   - requested username principal matches the AWS caller username/ARN mapping unless policy explicitly overrides it;
   - all principals are in the allowlist and are canonical ASCII-safe values;
   - TTL is within configured maximum;
   - critical options and extensions are allowed.
6. Certificate builder constructs an OpenSSH user certificate with random serial and audit KeyID.
7. Signer signs through KMS by default, or encrypted PEM only when explicitly configured.
8. Audit sink records success or failure with reason code and correlation fields.
9. Handler returns the OpenSSH certificate or a stable error response.

### Host certificate request

1. Authorized automation or host bootstrap process sends an AWS_IAM-signed request through API Gateway.
2. Lambda obtains trusted IAM caller identity from API Gateway request context.
3. Policy engine validates the caller is allowed to request host certificates.
4. Policy validates requested host principals against configured host allowlists, instance identity rules, or explicit mappings.
5. Certificate builder emits an OpenSSH host certificate with approved host principals, TTL, KeyID, and random serial.
6. Signer signs the certificate.
7. Audit records caller identity, host principals, public-key fingerprint, KeyID, serial, and decision.
8. Handler returns the host certificate.

User-principal binding rules do not automatically authorize host certificates. Host authorization must be configured separately.

### CA public key export

The production Lambda handler does not currently expose a CA public key export operation. Operators should publish the CA public key through their deployment process, or use the local `gobless ca-pubkey` development command against approved local configuration.

Private CA key material must never be returned by any export flow.
