# BLESS Compatibility

GoBless is a Go reimplementation of [Netflix BLESS](https://github.com/Netflix/bless)
(archived), an AWS Lambda–based SSH certificate authority written in Python.

This document describes what GoBless is compatible with, what intentionally
differs, and how operators can migrate from BLESS.

---

## What GoBless Is Compatible With

### Certificate Types

| Feature | BLESS | GoBless |
|---|---|---|
| User certs (`ssh.UserCert`) | ✅ | ✅ |
| Host certs (`ssh.HostCert`) | ✅ | ✅ |

### Extensions (User Certs)

GoBless produces the **exact same five extensions** as BLESS for user certs
(in lexicographic / OpenSSH-wire order):

```
permit-X11-forwarding   (empty value)
permit-agent-forwarding (empty value)
permit-port-forwarding  (empty value)
permit-pty              (empty value)
permit-user-rc          (empty value)
```

These extensions are applied automatically when `Extensions` is `nil` on the
signing request.  They can be overridden by supplying an explicit map.

### Extensions (Host Certs)

Both BLESS and GoBless produce host certs with **no extensions** (`{}`).
This is correct per OpenSSH and is enforced in GoBless: when `CertType` is
`HostCert` and `Extensions` is `nil`, an empty map is used—never the user
defaults.

### Critical Options

| Critical Option | BLESS | GoBless |
|---|---|---|
| `source-address` | Always present (bastion IPs) | Present when supplied by caller |
| `force-command` | Not supported | Supported (opt-in) |

`source-address` is mandatory in BLESS because every request passes through a
bastion host.  In GoBless it is caller-supplied; operators **must** populate it
in their policy/handler to achieve the same network-restriction security
property.

### Principals

BLESS allowed operators to pass principal lists through with relatively little transformation. GoBless is stricter: request-body principals are untrusted until policy approval, must be canonical ASCII-safe strings, and are rejected when empty, duplicated, overlong, whitespace/control-containing, NUL-containing, or Unicode-confusable.

This is an intentional compatibility difference. It prevents visually ambiguous usernames from reaching logs, audit records, or certificates.

---

## What Intentionally Differs

### Serial Number

| | Value |
|---|---|
| BLESS | Always **0** (never set) |
| GoBless | **Non-zero random `uint64`** (cryptographically generated) |

GoBless intentionally uses a non-zero random serial to support:

- Certificate revocation lists (CRLs) that reference serials.
- Audit log correlation — each cert can be uniquely identified.
- Future OCSP or online revocation support.

See [ADR 003](adr/003-serial-generation.md) for the full rationale.

**Migration note:** If you have tooling that asserts `serial == 0`, update it
to assert `serial != 0` (or remove the assertion).  OpenSSH itself does not
care whether the serial is zero; it is an operator-visible field only.

### KeyID Format

| | Format |
|---|---|
| BLESS | `request[<id>] for[<user>] from[<ip>] command[<cmd>] ssh_key[<fp>]  ca[<arn>] valid_to[<datetime>]` |
| GoBless | `gobless-<type>-<principal>-<unix_ts>-<random_hex>` |

Both formats are **non-empty opaque strings** used by `sshd` for audit logging
(`AuthorizedKeysCommand`, `PubkeyAcceptedAlgorithms` logging, etc.).  The exact
format is not part of the SSH protocol and sshd does not parse it.

**Migration note:** If you parse BLESS KeyID strings for audit/SIEM purposes,
update your parser to handle the GoBless format, or supply a custom `KeyID`
value on the signing request.

### ValidAfter (Backdating)

| | ValidAfter |
|---|---|
| BLESS | `now - validity_before_seconds` (default: now − 120 s) |
| GoBless | `now` (no backdate) |

BLESS backdates to tolerate clock skew.  GoBless sets `ValidAfter = now`.
The effective security window is the same; operators relying on the backdate
for clock-skew tolerance should either accept the slight difference or add a
small backdate themselves (planned as a future option).

---

## Migration Guide for BLESS Operators

1. **Deploy GoBless** using the same IAM/KMS infrastructure as BLESS
   (see [DEPLOY_AWS.md](DEPLOY_AWS.md)).

2. **Update your bastion handler** to populate `SourceAddress` with the
   bastion's outbound CIDR(s).  In BLESS this was automatic; in GoBless it is
   explicit.

3. **Update serial-based tooling** — see [Serial Number](#serial-number) above.

4. **Update KeyID parsers** — see [KeyID Format](#keyid-format) above.

5. **Run the compatibility harness** to confirm your build is compatible:

   ```sh
   GOTOOLCHAIN=local go test -race -run TestBLESSCompat ./internal/cert/...
   ```

6. **Test with `ssh -v`** against a real sshd to verify certs are accepted.

---

## References

- Netflix BLESS (archived): <https://github.com/Netflix/bless>
- GoBless ADR 003 (serial): [adr/003-serial-generation.md](adr/003-serial-generation.md)
- GoBless ADR 004 (source-address): [adr/004-source-address.md](adr/004-source-address.md)
- OpenSSH `PROTOCOL.certkeys`: <https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys>
