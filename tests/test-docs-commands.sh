#!/usr/bin/env bash
# SAFETY: This test does not modify your system. It only reads files.
# Guards against doc rot: every scripts/*.sh|.ps1 path referenced in README.md
# or SKILL.md must actually exist. This catches the class of bug where docs
# point at a script that was renamed or never created.
#
# NOTE: guild-cli `gate ...` command examples cannot be verified here — guild-cli
# is an external dependency not present in this repo (keeping SCG dependency-free).
# Those are verified manually against `gate <verb> --help` when edited; see the
# flag-notes callout in README's "Guild-CLI Devil Integration" section.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "=== test-docs-commands ==="

# Extract every scripts/<name>.sh or scripts/<name>.ps1 mentioned in the docs
# (with or without a leading ./), dedupe, and assert the file exists.
DOCS=("$PROJECT_DIR/README.md" "$PROJECT_DIR/SKILL.md")
REFS=$(grep -ohE '(\./)?scripts/[A-Za-z0-9_-]+\.(sh|ps1)' "${DOCS[@]}" 2>/dev/null \
        | sed 's#^\./##' | sort -u)

if [ -z "$REFS" ]; then
  fail "No scripts/*.sh references found in docs (extraction likely broke)"
else
  missing=0
  while IFS= read -r ref; do
    if [ -f "$PROJECT_DIR/$ref" ]; then
      pass "doc references existing script: $ref"
    else
      fail "doc references MISSING script: $ref"
      missing=$((missing + 1))
    fi
  done <<< "$REFS"
fi

# Also assert the reverse is sane: the core scanners are documented at all.
for core in scripts/env-scan.sh scripts/project-scan.sh scripts/project-scan-py.sh scripts/ioc-scan.sh scripts/respond.sh; do
  if grep -qF "$core" "${DOCS[@]}" 2>/dev/null; then
    pass "core script documented: $core"
  else
    fail "core script NOT documented anywhere: $core"
  fi
done

echo ""
echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
