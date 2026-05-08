# Host Certificate Extensions Leak

**Package:** cert
**Reference:** host-certificate extension regression
**Severity:** BLOCKING

## What Was Wrong

When `Extensions` was `nil` in a `HostCert` signing request, `cert.Sign` fell through to its default extension handling path and populated the certificate with the five standard user permit-* extensions (`permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`, `permit-X11-forwarding`, `permit-user-rc`) instead of producing a certificate with an empty extension map.

Host certificates should carry no extensions by default. The bug meant every host cert signed with a nil extensions field silently received user-oriented extensions — extensions that have no meaning for host certs but could confuse SSH implementations or audit tooling that inspects raw cert bytes.

## The Fix

The `cert.Sign` default-extension path was guarded to apply only for user certificates. For host certificate requests, when `Extensions == nil`, the signer now sets `cert.Extensions` to an explicit empty `map[string]string{}` rather than falling through to the user permit-* defaults.

## Test Coverage

- `internal/cert/bless_compat_test.go` — `TestHostCertNilExtensionsEmpty`
  Signs a host cert with `Extensions: nil` and asserts the resulting certificate contains zero extensions.
- `internal/cert/bless_compat_test.go` — `TestHostCertExplicitExtensionsIgnored`
  Signs a host cert with an explicit non-nil extensions map and asserts only the caller-supplied extensions (or none, per policy) appear — no user permit-* extensions are injected.

## References

- Test file: `internal/cert/bless_compat_test.go`
