# ValidAfter Second-Boundary Rollover Flakiness

**Package:** cert
**Reference:** ValidAfter boundary test regression
**Severity:** BLOCKING

## What Was Wrong

`TestWireFormat_RoundTrip_UserCert` (and `TestWireFormat_ValidBeforeAfter`) captured `before := time.Now()` before calling `Sign`, then asserted `wireCert.ValidAfter > before.Unix()` (strict greater-than). When the test happened to run right at a Unix second boundary — i.e., `Sign` was called in the *next* second from where `before` was sampled — the assertion failed intermittently.

This was a **test-correctness bug**; the production signing code was correct. The flakiness obscured real regressions and made CI results non-reproducible in time-sensitive environments.

## The Fix

The `ValidAfter` assertion was changed to allow 1-second slack:

```go
if wireCert.ValidAfter > uint64(before.Unix()+1) {
    t.Errorf(...)
}
```

This accommodates the case where `Sign` is called in the second immediately following `before`, without masking genuine off-by-many bugs.

## Test Coverage

- `internal/cert/wire_format_test.go` — `TestWireFormat_RoundTrip_UserCert`
  Uses `before.Unix()+1` slack in the `ValidAfter` upper-bound assertion.
- `internal/cert/wire_format_test.go` — `TestWireFormat_ValidBeforeAfter`
  Same 1-second slack applied consistently.

## References

- Test file: `internal/cert/wire_format_test.go`
