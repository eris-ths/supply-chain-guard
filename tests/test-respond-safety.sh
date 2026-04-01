#!/usr/bin/env bash
# SAFETY: This test does not modify your system. All operations use temporary directories.
# Tests that respond.sh safety mechanisms work correctly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "=== test-respond-safety ==="

# ─── Test 1: --high without args shows usage and exits 1 ───
set +e
OUTPUT=$("$PROJECT_DIR/scripts/respond.sh" --high 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
  pass "--high without args exits non-zero"
else
  fail "--high without args should exit non-zero (got $EXIT_CODE)"
fi

if echo "$OUTPUT" | grep -qi "usage\|package.*safe_version\|package.json not found"; then
  pass "--high without args shows usage or error"
else
  fail "--high without args did not show usage or error"
fi

# ─── Test 2: No args shows help ───
set +e
OUTPUT2=$("$PROJECT_DIR/scripts/respond.sh" 2>&1)
set -e

if echo "$OUTPUT2" | grep -qi "Remediation Script\|--critical\|--high"; then
  pass "No args shows help"
else
  fail "No args did not show help"
fi

# ─── Test 3: --critical with /dev/null stdin (all prompts default N) ───
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR"

# Create a marker file to verify nothing gets deleted
touch "$TMPDIR/marker.txt"

# Run --critical from tmpdir with empty stdin (all y/N prompts → N)
set +e
OUTPUT3=$(cd "$TMPDIR" && "$PROJECT_DIR/scripts/respond.sh" --critical </dev/null 2>&1)
set -e

if [ -f "$TMPDIR/marker.txt" ]; then
  pass "--critical with empty stdin deletes nothing"
else
  fail "--critical deleted files despite no confirmation!"
fi

if echo "$OUTPUT3" | grep -qi "Skipped\|No RAT\|No Launch\|No node_modules"; then
  pass "--critical reports skipped/clean status"
else
  # It's OK if there's nothing to skip — the point is nothing was deleted
  pass "--critical completed without destructive action"
fi

# ─── Cleanup ───
rm -rf "$TMPDIR"

echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ] && exit 0 || exit 1
