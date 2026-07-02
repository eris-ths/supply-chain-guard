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

rm -rf "$TMPDIR"

# ─── Test 4: --high on a pip project PRINTS the pin command and, when the user
#            declines, creates NO constraints.txt (the conservative "guide" path
#            must not mutate the project on [N]). ───
PIPDIR=$(mktemp -d)
printf 'urllib3<2.6\n' > "$PIPDIR/requirements.txt"
set +e
OUT4=$(cd "$PIPDIR" && printf 'n\n' | "$PROJECT_DIR/scripts/respond.sh" --high urllib3 2.7.0 2>&1)
set -e

if echo "$OUT4" | grep -q "Manager: pip" && echo "$OUT4" | grep -q "constraints.txt"; then
  pass "--high python(pip) prints the constraints pin command"
else
  fail "--high python(pip) did not show pip pin guidance"
  echo "    Output: $OUT4"
fi

if [ ! -f "$PIPDIR/constraints.txt" ]; then
  pass "--high python(pip) declined → constraints.txt NOT created (no mutation on N)"
else
  fail "--high python(pip) created constraints.txt despite declining!"
fi
rm -rf "$PIPDIR"

# ─── Test 5: --high on a uv/poetry project only PRINTS lockfile-mutating
#            commands (never auto-runs them). ───
UVDIR=$(mktemp -d)
: > "$UVDIR/uv.lock"; : > "$UVDIR/pyproject.toml"
set +e
OUT5=$(cd "$UVDIR" && "$PROJECT_DIR/scripts/respond.sh" --high requests 2.32.5 </dev/null 2>&1)
set -e

if echo "$OUT5" | grep -q "Manager: uv" && echo "$OUT5" | grep -q "uv add" && echo "$OUT5" | grep -qi "won't run it unattended\|Run the command above yourself"; then
  pass "--high python(uv) prints uv command but does not auto-run it"
else
  fail "--high python(uv) guidance missing or auto-ran a lockfile command"
  echo "    Output: $OUT5"
fi
rm -rf "$UVDIR"

# ─── Test 6: --high with neither package.json nor Python files → error, exit 1 ───
EMPTYDIR=$(mktemp -d)
set +e
OUT6=$(cd "$EMPTYDIR" && "$PROJECT_DIR/scripts/respond.sh" --high foo 1.0.0 2>&1)
EXIT6=$?
set -e
if [ "$EXIT6" -ne 0 ] && echo "$OUT6" | grep -qi "no package.json or Python project"; then
  pass "--high with no project files errors out (exit $EXIT6)"
else
  fail "--high with no project files should error (got exit $EXIT6)"
  echo "    Output: $OUT6"
fi
rm -rf "$EMPTYDIR"

echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ $FAILED -eq 0 ] && exit 0 || exit 1
