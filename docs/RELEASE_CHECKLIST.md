# GoBless Release Checklist

Use this checklist for every production release. Work through it top to bottom on a **fresh clone** — do not skip steps or carry state from a previous workspace.

---

## Pre-Release Validation

### 1. Clone and run CI gates

```sh
git clone https://github.com/FtlC-ian/gobless.git gobless-release
cd gobless-release
git checkout <release-tag-or-branch>
make ci
```

**Expected:** `vet`, `test`, and `test-race` all pass with exit code 0.


---

### 2. Docs quality gate

```sh
make docs-check
```

**Expected:** Script prints `=== PASS ===`. No `TODO`, `FIXME`, or `PLACEHOLDER` stale references. All files referenced in `docs/manifest.json` exist. All `.md` files in `docs/` are listed in `docs/manifest.json`.

> **Release rule:** `docs-check` must pass manually before tagging, even while the GitHub Actions job is advisory.
> **Before a 1.0 release**, change the workflow to make docs-check blocking.

---

### 3. End-to-end smoke test (real AWS target)

Configure credentials for the target environment, then:

```sh
GOTOOLCHAIN=local go test -v -tags e2e ./test/e2e/
```

**Expected:** All e2e tests pass. Signed certificates are returned and valid.

---

### 4. Review BLESS_COMPATIBILITY.md

Open `docs/BLESS_COMPATIBILITY.md` and verify:

- [ ] Every intentional behaviour difference from Netflix BLESS is documented and still intentional.
- [ ] No new differences were introduced in this release that are not reflected in the document.
- [ ] Migration guidance is current for operators upgrading from BLESS.

---

### 5. Review THREAT_MODEL.md

Open `docs/THREAT_MODEL.md` and verify:

- [ ] No new attack surfaces were introduced by recent changes (new endpoints, new deps, changed trust boundaries).
- [ ] All mitigations listed are still in place.
- [ ] Residual risks are still acceptable.

If new threats are identified, update `THREAT_MODEL.md` before tagging.

---

## Tagging and Publishing

### 6. Tag the release

```sh
git tag -s v<X.Y.Z> -m "Release v<X.Y.Z>"
git push origin v<X.Y.Z>
```

Use a signed tag (`-s`) when your GPG key is configured.

---

### 7. Confirm CI green on tag

After pushing the tag, confirm in the GitHub Actions UI that the CI workflow triggered on the tag ref passes all jobs (vet, deps, test, test-race, docs-check).

```sh
gh run list --workflow=ci.yml
```

**Expected:** All jobs green. Note: docs-check may be advisory in GitHub Actions before 1.0, but a release must not be tagged unless the manual `make docs-check` gate passes.

---

## Post-Release

- [ ] Announce release in the relevant channel with the tag and changelog summary.
- [ ] Archive this checklist (or a copy with completion timestamps) in the release notes or PR description.

---

*If any step fails, stop and resolve before proceeding. Do not tag a release with a known failing gate.*
