#!/usr/bin/env sh
# Docs quality gate: checks docs are non-empty and do not contain stale public placeholders.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs"
FAIL_FILE="$(mktemp)"
trap 'rm -f "$FAIL_FILE"' EXIT

fail() {
  echo "FAIL: $*" >&2
  echo 1 >> "$FAIL_FILE"
}

echo "=== GoBless docs quality check ==="

echo ""
echo "-- Checking docs/ markdown files exist and are non-empty --"
find "$DOCS_DIR" -name "*.md" | while IFS= read -r f; do
  if [ ! -s "$f" ]; then
    fail "Empty or missing doc file: $f"
  fi
done

echo ""
echo "-- Checking for stale references (TODO/FIXME/PLACEHOLDER) --"
STALE_PATTERN='TODO\|FIXME\|PLACEHOLDER'
grep -rn "$STALE_PATTERN" "$DOCS_DIR" --include="*.md" \
  | while IFS= read -r line; do
    fail "Stale reference found: $line"
  done || true

echo ""
FAILURE_COUNT=$(wc -l < "$FAIL_FILE" | tr -d ' ')
if [ "$FAILURE_COUNT" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
else
  echo "=== FAIL: $FAILURE_COUNT issue(s) found ===" >&2
  exit 1
fi
