# GoBless v0.1 Roadmap

GoBless v0.1 is substantially complete. All core implementation, security review, testing, and deployment phases have shipped. What remains is the final documentation polish track.

## Phase Status

| Issue | Title | Phase | Status |
|-------|-------|-------|--------|
| #1 | Project scaffold and Go module init | 1 – Core scaffold | ✅ done |
| #2 | CA key generation and loading | 1 – Core scaffold | ✅ done |
| #3 | Host certificate signing (core) | 2 – Certificate ops | ✅ done |
| #4 | Golden cert tests | 2 – Certificate ops | ✅ done |
| #5 | User certificate signing | 2 – Certificate ops | ✅ done |
| #6 | Principal validation | 2 – Certificate ops | ✅ done |
| #7 | Certificate extensions | 2 – Certificate ops | ✅ done |
| #8 | ValidAfter / ValidBefore handling | 2 – Certificate ops | ✅ done |
| #9 | Policy engine — allow/deny rules | 3 – Policy | ✅ done |
| #10 | Policy engine — principal maps | 3 – Policy | ✅ done |
| #11 | Policy engine — extension rules | 3 – Policy | ✅ done |
| #12 | Policy loading and validation | 3 – Policy | ✅ done |
| #13 | Config loading and schema | 4 – Config & integration | ✅ done |
| #14 | CLI — sign command | 4 – Config & integration | ✅ done |
| #17 | Audit logging | 4 – Config & integration | ✅ done |
| #18 | Security review — pass 1 | 5 – Security | ✅ done |
| #19 | Security review — pass 2 | 5 – Security | ✅ done |
| #20 | Fuzz targets — cert parsing | 5 – Security | ✅ done |
| #21 | Fuzz targets — policy evaluation | 5 – Security | ✅ done |
| #22 | Fuzz targets — config parsing | 5 – Security | ✅ done |
| #23 | Fix ValidAfter boundary flakiness | 5 – Security | ✅ done |
| #24 | Test matrix definition | 6 – Test & docs | ✅ done |
| #25 | Fix host cert extensions leak | 5 – Security | ✅ done |
| #26 | ADR index | 6 – Test & docs | ✅ done |
| #27 | Test matrix coverage | 6 – Test & docs | ✅ done |
| #28 | Architecture doc | 6 – Test & docs | ✅ done |
| #29 | BLESS compatibility doc | 6 – Test & docs | ✅ done |
| #30 | Lambda fixtures | 6 – Test & docs | ✅ done |
| #33 | Threat model doc | 6 – Test & docs | ✅ done |
| #34 | Quickstart guide | 6 – Test & docs | ✅ done |
| #35 | Fix principal Unicode injection | 5 – Security | ✅ done |
| #36 | Test strategy doc | 6 – Test & docs | ✅ done |
| #38 | Deployment runbooks | 6 – Test & docs | ✅ done |
| #31 | Security regression corpus process | 6 – Test & docs | ✅ done |
| #32 | Roadmap epic | 6 – Test & docs | ✅ done |
| #39 | Machine-readable manifest | 6 – Test & docs | ✅ done |
| #40 | Worked example | 6 – Test & docs | ✅ done |
| #41 | Docs quality gates | 6 – Test & docs | ✅ done |

## Current Status

All v0.1 milestone items tracked in this repository are complete. The CLI currently exposes `lambda`, `sign`, `ca-pubkey`, `version`, and `help`; separate verify/policy subcommands are not part of the v0.1 public surface.

See [docs/INDEX.md](INDEX.md) for the full documentation set.
