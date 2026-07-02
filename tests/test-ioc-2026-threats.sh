#!/usr/bin/env bash
# SAFETY: This test does not modify your system. All operations use temporary directories.
# Tests that ioc-scan.sh detects the 2026 threats added to it (Shai-Hulud worm
# payload artifacts, SANDWORM_MODE MCP signatures) without false-positiving on a
# clean project.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IOC="$PROJECT_DIR/scripts/ioc-scan.sh"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "=== test-ioc-2026-threats ==="

# ─── Test 1: Clean project — T004/T008 stay CLEAR, exit 0 (no false positive) ───
CLEAN=$(mktemp -d)
set +e
OUT=$(cd "$CLEAN" && bash "$IOC" 2>&1)
EXIT=$?
set -e
rm -rf "$CLEAN"

if echo "$OUT" | grep -qE 'T004: Shai-Hulud worm' && echo "$OUT" | grep -qE '\[ok\] No Shai-Hulud indicators'; then
  pass "Shai-Hulud (T004) CLEAR on clean project"
else
  fail "T004 did not report clean on a clean project"
  echo "    Output: $OUT"
fi

if echo "$OUT" | grep -qE '\[ok\] No known malicious MCP tool signatures'; then
  pass "MCP poisoning (T008) CLEAR on clean project"
else
  fail "T008 did not report clean on a clean project"
fi

if [ "$EXIT" -eq 0 ]; then
  pass "Clean project → exit 0 (no false positive from added sections)"
else
  fail "Clean project should exit 0 (got $EXIT)"
  echo "    Output: $OUT"
fi

# ─── Test 2: Shai-Hulud payload files ARE detected ───
SH=$(mktemp -d)
mkdir -p "$SH/.github/workflows"
: > "$SH/bun_environment.js"
: > "$SH/.github/workflows/shai-hulud-workflow.yml"
set +e
OUT2=$(cd "$SH" && bash "$IOC" 2>&1)
EXIT2=$?
set -e
rm -rf "$SH"

if echo "$OUT2" | grep -qE '!!CRITICAL: Shai-Hulud payload file present: bun_environment.js'; then
  pass "Detects Shai-Hulud payload file bun_environment.js"
else
  fail "Did not detect bun_environment.js"
  echo "    Output: $OUT2"
fi

if [ "$EXIT2" -ne 0 ]; then
  pass "Shai-Hulud payload → non-zero exit ($EXIT2)"
else
  fail "Should exit non-zero when Shai-Hulud payload present (got 0)"
fi

# ─── Test 3: SANDWORM_MODE MCP signature IS detected ───
# Simulate a poisoned MCP config by pointing HOME at a temp dir with a planted
# signature. ioc-scan.sh reads $HOME/.cursor/mcp.json among others.
POISON=$(mktemp -d)
mkdir -p "$POISON/.cursor"
cat > "$POISON/.cursor/mcp.json" <<'JSON'
{ "mcpServers": { "helper": { "tools": ["index_project", "lint_check", "scan_dependencies"] } } }
JSON
set +e
OUT3=$(cd "$POISON" && HOME="$POISON" bash "$IOC" 2>&1)
EXIT3=$?
set -e
rm -rf "$POISON"

if echo "$OUT3" | grep -qE '!!SUSPECT: SANDWORM_MODE tool signature'; then
  pass "Detects SANDWORM_MODE MCP tool signature in mcp.json"
else
  fail "Did not detect SANDWORM_MODE signature"
  echo "    Output: $OUT3"
fi

if [ "$EXIT3" -ne 0 ]; then
  pass "Poisoned MCP config → non-zero exit ($EXIT3)"
else
  fail "Should exit non-zero when MCP signature present (got 0)"
fi

# ─── Results ───
echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
