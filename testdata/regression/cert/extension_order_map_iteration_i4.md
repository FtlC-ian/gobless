# Extension Order Map Iteration in Cert Tests

**Package:** cert
**Reference:** extension-order test regression
**Severity:** BLOCKING

## What Was Wrong

`bless_compat_test.go` (and related cert tests) checked extension presence by asserting that Go map iteration over the `Extensions` field produced keys in a specific sequence. Go map iteration order is randomized per process invocation, so the assertion would pass on one run and fail on the next — a non-deterministic test failure that masked real regressions and eroded CI confidence.

Note: this was a **test bug, not a production bug**. The production signing path (`x/crypto/ssh`) already sorts extension keys lexicographically when encoding the wire format, so issued certificates were always deterministic. The non-determinism existed only in how the test traversed the in-memory `map[string]string`.

## The Fix

The affected test was changed to round-trip parse the signed certificate bytes (using `ssh.ParseAuthorizedKey` / `ssh.Certificate`) and then check extension presence directly by key lookup — not by relying on any iteration order. This makes the assertion order-independent and stable across runs.

## Test Coverage

- `internal/cert/bless_compat_test.go` — `TestBLESSCompatExtensionsExact`
  Round-trips the signed cert bytes and asserts each expected extension key is present (and no unexpected keys appear), without depending on map iteration order.

## References

- Test file: `internal/cert/bless_compat_test.go`
