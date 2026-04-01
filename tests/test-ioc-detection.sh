#!/usr/bin/env bash
# SAFETY: This test does not modify your system. All operations use temporary directories.
# Tests that env-scan.sh detects compromised axios versions in lockfiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "=== test-ioc-detection ==="

# ─── Test 1: Detect compromised axios@1.14.1 ───
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/project"
cp "$SCRIPT_DIR/fixtures/compromised-package-lock.json" "$TMPDIR/project/package-lock.json"

set +e
OUTPUT=$("$PROJECT_DIR/scripts/env-scan.sh" "$TMPDIR" 2>&1)
EXIT_CODE=$?
set -e

if echo "$OUTPUT" | grep -q '!!HIGH:'; then
  pass "Detects compromised axios@1.14.1"
else
  fail "Did not detect compromised axios@1.14.1"
  echo "    Output: $OUTPUT"
fi

if [ $EXIT_CODE -ne 0 ]; then
  pass "Non-zero exit code on detection ($EXIT_CODE)"
else
  fail "Exit code should be non-zero when threats found (got 0)"
fi

# ─── Test 2: Detect malicious package (plain-crypto-js) ───
if echo "$OUTPUT" | grep -q '!!CRITICAL.*plain-crypto-js'; then
  pass "Detects malicious package plain-crypto-js"
else
  fail "Did not detect plain-crypto-js in lockfile"
fi

# ─── Test 3: Clean lockfile should be CLEAR ───
TMPDIR2=$(mktemp -d)
mkdir -p "$TMPDIR2/project"
cp "$SCRIPT_DIR/fixtures/clean-package-lock.json" "$TMPDIR2/project/package-lock.json"

set +e
OUTPUT2=$("$PROJECT_DIR/scripts/env-scan.sh" "$TMPDIR2" 2>&1)
EXIT_CODE2=$?
set -e

if echo "$OUTPUT2" | grep -q 'VERDICT.*CLEAR'; then
  pass "Clean lockfile produces CLEAR verdict"
else
  fail "Clean lockfile did not produce CLEAR verdict"
fi

if [ $EXIT_CODE2 -eq 0 ]; then
  pass "Zero exit code for clean scan"
else
  fail "Exit code should be 0 for clean scan (got $EXIT_CODE2)"
fi

# ─── Cleanup ───
rm -rf "$TMPDIR" "$TMPDIR2"

echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ] && exit 0 || exit 1
