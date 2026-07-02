#!/usr/bin/env bash
# SAFETY: This test does not modify your system. All operations use temporary directories.
# Tests that project-scan-py.sh correctly evaluates Python projects:
#   - CVE-flagged version detection (BadHost CVE-2026-48710) in both directions
#   - Static malicious package detection (ctx hijack)
#   - Clean project produces CLEAR verdict
#   - Missing project markers produce an actionable error
#   - Offline-capable: L3/IOC layers work without pip-audit / osv-scanner installed

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCANNER="$PROJECT_DIR/scripts/project-scan-py.sh"
FIX="$SCRIPT_DIR/fixtures"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

# Run the scanner inside a throwaway copy of the given fixtures.
# Usage: run_scan <fixture-file:dest-name> [<fixture-file:dest-name> ...]
# Sets: SCAN_OUTPUT, SCAN_EXIT
run_scan() {
  local tmp; tmp=$(mktemp -d)
  local spec src dst
  for spec in "$@"; do
    src="${spec%%:*}"; dst="${spec#*:}"
    cp "$FIX/$src" "$tmp/$dst"
  done
  set +e
  SCAN_OUTPUT=$(cd "$tmp" && bash "$SCANNER" 2>&1)
  SCAN_EXIT=$?
  set -e
  rm -rf "$tmp"
}

echo "=== test-python-scan ==="

# ─── Test 1: CVE-flagged vulnerable version IS detected (no false negative) ───
run_scan "py-vuln-pyproject.toml:pyproject.toml" "py-vuln-uv.lock:uv.lock"

if echo "$SCAN_OUTPUT" | grep -qE '!! CVE: starlette.*CVE-2026-48710'; then
  pass "Detects vulnerable starlette@0.47.0 (BadHost CVE-2026-48710)"
else
  fail "Did not flag vulnerable starlette@0.47.0"
  echo "    Output: $SCAN_OUTPUT"
fi

if [ "$SCAN_EXIT" -ne 0 ]; then
  pass "Non-zero exit code when CVE-flagged version present ($SCAN_EXIT)"
else
  fail "Exit code should be non-zero on CVE detection (got 0)"
fi

# ─── Test 2: Patched version is NOT flagged (no false positive) ───
run_scan "py-clean-pyproject.toml:pyproject.toml" "py-clean-uv.lock:uv.lock"

if echo "$SCAN_OUTPUT" | grep -qE '✓ safe: starlette@1.1.0'; then
  pass "Patched starlette@1.1.0 reported safe (not affected by CVE-2026-48710)"
else
  fail "Patched starlette@1.1.0 not reported safe"
  echo "    Output: $SCAN_OUTPUT"
fi

if echo "$SCAN_OUTPUT" | grep -qE 'Verdict: CLEAR'; then
  pass "Clean Python project produces CLEAR verdict"
else
  fail "Clean Python project did not produce CLEAR verdict"
fi

if [ "$SCAN_EXIT" -eq 0 ]; then
  pass "Zero exit code for clean scan"
else
  fail "Exit code should be 0 for clean scan (got $SCAN_EXIT)"
fi

# ─── Test 3: IOC layer does not false-positive on a clean project ───
# (Test 2's fixture is clean; verify no IOC indicators were raised)
if echo "$SCAN_OUTPUT" | grep -qE '\[IOC\] CLEAR'; then
  pass "IOC layer stays CLEAR on a clean project (no false positive)"
else
  fail "IOC layer raised an indicator on a clean project"
  echo "    Output: $SCAN_OUTPUT"
fi

# ─── Test 4: Static malicious package (ctx hijack) IS detected ───
run_scan "py-malicious-requirements.txt:requirements.txt"

if echo "$SCAN_OUTPUT" | grep -qE '!! MALICIOUS: ctx'; then
  pass "Detects hijacked package ctx in requirements.txt"
else
  fail "Did not detect hijacked package ctx"
  echo "    Output: $SCAN_OUTPUT"
fi

if [ "$SCAN_EXIT" -ne 0 ]; then
  pass "Non-zero exit code when malicious package present ($SCAN_EXIT)"
else
  fail "Exit code should be non-zero on malicious detection (got 0)"
fi

# ─── Test 5: Missing project markers produce an actionable error ───
run_scan "py-malicious-requirements.txt:README.txt"  # not a recognized marker

if echo "$SCAN_OUTPUT" | grep -qE 'no Python project markers found'; then
  pass "Errors clearly when no Python markers are present"
else
  fail "Did not error on missing Python project markers"
  echo "    Output: $SCAN_OUTPUT"
fi

if [ "$SCAN_EXIT" -ne 0 ]; then
  pass "Non-zero exit code when no markers found ($SCAN_EXIT)"
else
  fail "Exit code should be non-zero when no markers found (got 0)"
fi

# ─── Test 6: L3/IOC layers are offline-capable (no network tools required) ───
# Tests 1 & 4 detected threats purely via the static L3 list + local file reads,
# regardless of whether pip-audit / osv-scanner are installed. Assert that the
# scanner announces SKIP (not ERROR) for absent network scanners so absence never
# masks a real L3/IOC hit.
run_scan "py-clean-pyproject.toml:pyproject.toml" "py-clean-uv.lock:uv.lock"
if ! command -v pip-audit >/dev/null 2>&1; then
  if echo "$SCAN_OUTPUT" | grep -qE '\[L1:pip-audit\] SKIP'; then
    pass "pip-audit absence degrades to SKIP, not ERROR (fail-visible)"
  else
    fail "pip-audit absent but no clean SKIP notice"
  fi
else
  pass "pip-audit installed — offline-degradation path not exercised (informational)"
fi

# ─── Test 7: 2026 CVE-flagged packages are detected ───
# lightning 2.6.2 (compromised release, CVE-2026-44484) and urllib3 2.5.0
# (CVE-2026-21441 + CVE-2026-44431) must all be flagged. urllib3 has two
# distinct CVE entries → verifies multiple entries per package are evaluated
# independently.
run_scan "py-cve2026-pyproject.toml:pyproject.toml" "py-cve2026-uv.lock:uv.lock"

if echo "$SCAN_OUTPUT" | grep -qE '!! CVE: lightning@2\.6\.2.*CVE-2026-44484'; then
  pass "Detects compromised lightning@2.6.2 (CVE-2026-44484)"
else
  fail "Did not flag lightning@2.6.2"
  echo "    Output: $SCAN_OUTPUT"
fi

if [ "$(echo "$SCAN_OUTPUT" | grep -cE '!! CVE: urllib3@2\.5\.0')" -eq 2 ]; then
  pass "urllib3@2.5.0 flagged by both CVE entries (independent per-entry eval)"
else
  fail "urllib3@2.5.0 not flagged by both CVE-2026-21441 and CVE-2026-44431"
  echo "    Output: $SCAN_OUTPUT"
fi

if [ "$SCAN_EXIT" -ne 0 ]; then
  pass "Non-zero exit code when 2026 CVE-flagged versions present ($SCAN_EXIT)"
else
  fail "Exit code should be non-zero on 2026 CVE detection (got 0)"
fi

# ─── Results ───
echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
