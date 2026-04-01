#!/usr/bin/env bash
# SAFETY: These tests do not modify your system. All operations use temporary directories.
# Runs all SCG test suites and reports a summary.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0
SUITES=0
SUITE_FAILURES=0

run_suite() {
  local name="$1"
  local script="$2"
  SUITES=$((SUITES + 1))

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if bash "$script"; then
    echo "  Suite: $name ✓"
  else
    echo "  Suite: $name ✗"
    SUITE_FAILURES=$((SUITE_FAILURES + 1))
  fi
}

echo "SCG Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

run_suite "IOC Detection" "$SCRIPT_DIR/test-ioc-detection.sh"
run_suite "Respond Safety" "$SCRIPT_DIR/test-respond-safety.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary: $SUITES suites, $SUITE_FAILURES failures"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ $SUITE_FAILURES -eq 0 ] && exit 0 || exit 1
