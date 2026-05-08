#!/usr/bin/env sh
# scripts/check-docs.sh
# Docs quality gate: checks existence, non-emptiness, stale references, and manifest coverage.
# Usage: bash scripts/check-docs.sh
# Exits 0 on PASS, 1 on any failure.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs"
MANIFEST="$DOCS_DIR/manifest.json"
FAIL_FILE="$(mktemp)"

# Clean up temp file on exit
trap 'rm -f "$FAIL_FILE"' EXIT

fail() {
  echo "FAIL: $*" >&2
  echo 1 >> "$FAIL_FILE"
}

echo "=== GoBless docs quality check ==="

# 1. Check all markdown files in docs/ exist and are non-empty
echo ""
echo "-- Checking docs/ markdown files exist and are non-empty --"
find "$DOCS_DIR" -name "*.md" | while IFS= read -r f; do
  if [ ! -s "$f" ]; then
    fail "Empty or missing doc file: $f"
  fi
done

# 2. Grep for stale references in doc files
# Exclude RELEASE_CHECKLIST.md — it legitimately describes what this check does
echo ""
echo "-- Checking for stale references (TODO/FIXME/PLACEHOLDER) --"
STALE_PATTERN='TODO\|FIXME\|PLACEHOLDER'
grep -rn "$STALE_PATTERN" "$DOCS_DIR" --include="*.md" \
  | grep -v 'RELEASE_CHECKLIST.md' \
  | while IFS= read -r line; do
    fail "Stale reference found: $line"
  done || true

# 3. Check that every file listed in docs/manifest.json actually exists
echo ""
echo "-- Checking manifest.json file references exist --"
if [ ! -f "$MANIFEST" ]; then
  fail "docs/manifest.json not found"
else
  # Use jq if available; otherwise fall back to grep-based extraction
  if command -v jq >/dev/null 2>&1; then
    jq -r '.docs[].path' "$MANIFEST" | while IFS= read -r rel_path; do
      abs_path="$REPO_ROOT/$rel_path"
      if [ ! -f "$abs_path" ]; then
        fail "manifest.json references missing file: $rel_path"
      fi
    done
  else
    # Fallback: extract quoted paths after "path": using grep+sed (no jq)
    grep '"path"' "$MANIFEST" | sed 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | while IFS= read -r rel_path; do
      abs_path="$REPO_ROOT/$rel_path"
      if [ ! -f "$abs_path" ]; then
        fail "manifest.json references missing file: $rel_path"
      fi
    done
  fi
fi

# 4. Reverse coverage check: every .md in docs/ must be listed in manifest.json
echo ""
echo "-- Checking all docs/*.md files are listed in manifest.json --"
if [ -f "$MANIFEST" ]; then
  if command -v jq >/dev/null 2>&1; then
    MANIFEST_PATHS=$(jq -r '.docs[].path' "$MANIFEST")
  else
    MANIFEST_PATHS=$(grep '"path"' "$MANIFEST" | sed 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  fi
  find "$DOCS_DIR" -name "*.md" | while IFS= read -r f; do
    # Convert to repo-relative path
    rel="${f#$REPO_ROOT/}"
    if ! echo "$MANIFEST_PATHS" | grep -qF "$rel"; then
      fail "Doc file not listed in manifest.json: $rel"
    fi
  done
fi

echo ""
FAILURE_COUNT=$(wc -l < "$FAIL_FILE" | tr -d ' ')
if [ "$FAILURE_COUNT" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
else
  echo "=== FAIL: $FAILURE_COUNT issue(s) found ===" >&2
  exit 1
fi
