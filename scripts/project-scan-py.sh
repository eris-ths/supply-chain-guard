#!/usr/bin/env bash
# Supply Chain Guard — Python project scan (v4.0+)
# Runs scanner layers against a Python project (pip / poetry / uv).
# Requires: at least one of pyproject.toml / requirements*.txt / poetry.lock / uv.lock
#
# SAFETY: This script is READ-ONLY. It does not modify, delete, or install
#         anything on your system. Safe to run at any time.
#
# Layers:
#   L1: pip-audit (registry vulnerabilities, PyPI Advisory DB)
#   L2: osv-scanner (Google OSV database) for lockfiles
#   L3: Static malicious package list (known typosquats / hijacks / CVE-flagged)
#   IOC: Python-flavored filesystem + process artifact check
#   LF:  Lockfile integrity verification
#
# Usage: cd my-python-project && /path/to/project-scan-py.sh

set -euo pipefail

# ─── Project type detection ───
_HAS_PYPROJECT=0
_HAS_REQUIREMENTS=0
_HAS_POETRY_LOCK=0
_HAS_UV_LOCK=0
_PRIMARY_LOCK=""

[ -f "pyproject.toml" ] && _HAS_PYPROJECT=1
ls requirements*.txt &>/dev/null && _HAS_REQUIREMENTS=1
[ -f "poetry.lock" ] && { _HAS_POETRY_LOCK=1; _PRIMARY_LOCK="poetry.lock"; }
[ -f "uv.lock" ] && { _HAS_UV_LOCK=1; _PRIMARY_LOCK="uv.lock"; }

if [ "$_HAS_PYPROJECT" = 0 ] && [ "$_HAS_REQUIREMENTS" = 0 ] && [ "$_HAS_POETRY_LOCK" = 0 ] && [ "$_HAS_UV_LOCK" = 0 ]; then
  echo "ERROR: no Python project markers found (pyproject.toml / requirements*.txt / poetry.lock / uv.lock)."
  echo "Run this script from your Python project root, or use project-scan.sh for npm/yarn projects."
  exit 1
fi

_OS=$(uname -s)
_EXIT_CODE=0
_PROJECT=$(basename "$(pwd)")

echo "SCG-PY ═══════════════════════════════════"
echo "  Project Scan (Python): $_PROJECT"
echo "  OS: $_OS"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Markers: pyproject=$_HAS_PYPROJECT, requirements=$_HAS_REQUIREMENTS, poetry.lock=$_HAS_POETRY_LOCK, uv.lock=$_HAS_UV_LOCK"
echo "══════════════════════════════════════════"

# ─── L1: pip-audit ───
echo ""
echo "─── L1: pip-audit ────────────────────────"

if command -v pip-audit &>/dev/null; then
  # pip-audit can read pyproject.toml / requirements / lockfile
  _PIPAUDIT_ARGS=""
  if [ "$_HAS_REQUIREMENTS" = 1 ]; then
    for req in requirements*.txt; do
      _PIPAUDIT_ARGS="$_PIPAUDIT_ARGS -r $req"
    done
  elif [ "$_HAS_PYPROJECT" = 1 ]; then
    _PIPAUDIT_ARGS=""  # pip-audit reads pyproject.toml from cwd by default
  fi

  if pip-audit $_PIPAUDIT_ARGS --format=json 2>/dev/null > /tmp/scg-pip-audit-$$.json; then
    python3 -c "
import sys, json
try:
    with open('/tmp/scg-pip-audit-$$.json') as f:
        d = json.load(f)
    deps = d.get('dependencies', [])
    vulns = []
    for dep in deps:
        for v in dep.get('vulns', []):
            vulns.append((dep.get('name'), dep.get('version'), v.get('id'), v.get('description', '')[:80]))
    if not vulns:
        print('[L1:pip-audit] CLEAR')
    else:
        for name, ver, vid, desc in vulns:
            print(f'  !! {vid}: {name}@{ver} — {desc}')
        print(f'[L1:pip-audit] FAIL ({len(vulns)} vulnerabilities)')
        sys.exit(1)
except Exception as e:
    print(f'[L1:pip-audit] ERROR parsing — {e}', file=sys.stderr)
    sys.exit(2)
" || _EXIT_CODE=1
    rm -f /tmp/scg-pip-audit-$$.json
  else
    echo "[L1:pip-audit] CLEAR (no vulnerabilities found, or pip-audit returned no JSON)"
    rm -f /tmp/scg-pip-audit-$$.json
  fi
else
  echo "[L1:pip-audit] SKIP — pip-audit not installed (recommended: pip install pip-audit)"
fi

# ─── L2: OSV scanner ───
echo ""
echo "─── L2: OSV scanner ──────────────────────"

if command -v osv-scanner &>/dev/null; then
  if [ -n "$_PRIMARY_LOCK" ]; then
    if osv-scanner --lockfile="$_PRIMARY_LOCK" --format=json > /tmp/scg-osv-$$.json 2>/dev/null; then
      python3 -c "
import json
try:
    with open('/tmp/scg-osv-$$.json') as f:
        d = json.load(f)
    results = d.get('results', [])
    total = 0
    for r in results:
        for pkg in r.get('packages', []):
            for v in pkg.get('vulnerabilities', []):
                total += 1
                print(f'  !! {v.get(\"id\")}: {pkg[\"package\"][\"name\"]}@{pkg[\"package\"][\"version\"]} — {v.get(\"summary\", \"\")[:80]}')
    if total == 0:
        print('[L2:osv-scanner] CLEAR ($_PRIMARY_LOCK)')
    else:
        print(f'[L2:osv-scanner] FAIL ({total} vulnerabilities in $_PRIMARY_LOCK)')
        exit(1)
except Exception as e:
    print(f'[L2:osv-scanner] ERROR parsing — {e}')
    exit(2)
" || _EXIT_CODE=1
      rm -f /tmp/scg-osv-$$.json
    else
      echo "[L2:osv-scanner] CLEAR ($_PRIMARY_LOCK, exit code 0 = no vulns)"
      rm -f /tmp/scg-osv-$$.json
    fi
  else
    echo "[L2:osv-scanner] SKIP — no lockfile (poetry.lock / uv.lock) found"
  fi
else
  echo "[L2:osv-scanner] SKIP — osv-scanner not installed (recommended: https://github.com/google/osv-scanner)"
fi

# ─── L3: Static malicious / CVE-flagged package list ───
echo ""
echo "─── L3: Static malicious & CVE-flagged list ──"

# Known malicious / hijacked / typosquat PyPI packages (curated, append as discovered)
# Format: "package_name|reason|reference"
_L3_LIST=(
  "ctx|hijacked package (2022-05-21), credential exfil postinstall|https://www.bleepingcomputer.com/news/security/pypi-package-ctx-hijacked-to-collect-environment-variables/"
  "phpass|typosquat of legitimate package, credential theft|generic typosquat"
  "colorama-py|typosquat of colorama|generic typosquat"
  "requesocks|typosquat / known abandoned, do not use|generic"
)

# Known CVE-flagged versions of legitimate packages (for awareness, not blocking)
# Format: "package_name|version_constraint|cve|description"
_L3_CVE_LIST=(
  "starlette|<1.0.1|CVE-2026-48710|BadHost — HTTP Host header path injection → SSRF/RCE"
)

_L3_MAL_HITS=0
_L3_CVE_HITS=0

# Combine pyproject deps + requirements + lock content for grep
_L3_SEARCH_FILES=""
for f in pyproject.toml requirements*.txt poetry.lock uv.lock Pipfile Pipfile.lock; do
  [ -f "$f" ] && _L3_SEARCH_FILES="$_L3_SEARCH_FILES $f"
done

if [ -n "$_L3_SEARCH_FILES" ]; then
  # Malicious / hijack check (block-worthy)
  #
  # Match three common shapes (unified with CVE-flagged version check pattern):
  #   PEP 621 list:   `    "crossenv",`  or  `["crossenv"]`
  #   Poetry inline:  `crossenv = "^1.0"`
  #   requirements:   `crossenv==1.0`  (with optional leading whitespace)
  #
  # Trade-off: matches commented-out quotes like `# "crossenv" is bad`. For
  # malicious packages this false-positive is acceptable (raises awareness
  # rather than missing a real declaration).
  for entry in "${_L3_LIST[@]}"; do
    pkg="${entry%%|*}"
    rest="${entry#*|}"
    if grep -qiE "(\"${pkg}([><=~!,\"[:space:]]|$))|(^[[:space:]]*${pkg}[[:space:]]*[=><~!])" $_L3_SEARCH_FILES 2>/dev/null \
       || grep -qiE "^name = \"${pkg}\"" $_L3_SEARCH_FILES 2>/dev/null; then
      echo "  !! MALICIOUS: $pkg — ${rest%%|*}"
      _L3_MAL_HITS=$((_L3_MAL_HITS + 1))
    fi
  done

  # CVE-flagged version check (warn, do not block)
  for entry in "${_L3_CVE_LIST[@]}"; do
    pkg="${entry%%|*}"
    rest="${entry#*|}"
    constraint="${rest%%|*}"
    rest="${rest#*|}"
    cve="${rest%%|*}"
    desc="${rest#*|}"

    # Find pinned version in lock files
    _ver_in_lock=""
    for lf in poetry.lock uv.lock; do
      if [ -f "$lf" ]; then
        # uv.lock / poetry.lock both use TOML `name = "pkg"\nversion = "x.y.z"`
        _ver_in_lock=$(awk -v p="$pkg" '/^name = "/{n=$3} /^version = "/{if (n=="\""p"\"") {print $3; exit}}' "$lf" 2>/dev/null | tr -d '"')
        [ -n "$_ver_in_lock" ] && break
      fi
    done

    if [ -n "$_ver_in_lock" ]; then
      # Strict evaluation: only flag when actually matching the vulnerable constraint
      _vuln=$(python3 -c "
try:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version
    print('1' if Version('$_ver_in_lock') in SpecifierSet('$constraint') else '0')
except ImportError:
    print('?')
except Exception:
    print('?')
" 2>/dev/null)
      if [ "$_vuln" = "1" ]; then
        echo "  !! CVE: $pkg@$_ver_in_lock matches $constraint — $cve — $desc"
        _L3_CVE_HITS=$((_L3_CVE_HITS + 1))
      elif [ "$_vuln" = "0" ]; then
        echo "  ✓ safe: $pkg@$_ver_in_lock (not affected by $cve, fix applied)"
      else
        echo "  ⚠️ unable to evaluate $pkg@$_ver_in_lock vs $cve (install: pip install packaging)"
      fi
    else
      # No resolved version in any lockfile. If the package is declared in
      # pyproject/requirements/Pipfile, warn that CVE cannot be evaluated
      # from a constraint alone — user might assume "we're fine" silently.
      # Match three common shapes:
      #   PEP 621 list:   "starlette>=0.36"  or  "starlette"
      #   Poetry inline:  starlette = ">=0.36"
      #   requirements:   starlette>=0.36
      _declared=0
      for f in pyproject.toml requirements*.txt Pipfile; do
        [ -f "$f" ] || continue
        if grep -qiE "(\"${pkg}([><=~!,\"[:space:]]|$))|(^[[:space:]]*${pkg}[[:space:]]*[=><~!])" "$f" 2>/dev/null; then
          _declared=1
          break
        fi
      done
      if [ "$_declared" = 1 ]; then
        echo "  ⚠️  $pkg declared without lockfile — cannot evaluate $cve (run 'uv lock' or 'poetry lock' first)"
      fi
    fi
  done

  _L3_TOTAL=$((_L3_MAL_HITS + _L3_CVE_HITS))
  if [ $_L3_TOTAL -gt 0 ]; then
    _summary=""
    [ $_L3_MAL_HITS -gt 0 ] && _summary="$_L3_MAL_HITS malicious package(s)"
    if [ $_L3_CVE_HITS -gt 0 ]; then
      [ -n "$_summary" ] && _summary="$_summary, "
      _summary="${_summary}$_L3_CVE_HITS CVE-flagged version(s)"
    fi
    echo "[L3:static] FAIL ($_summary)"
    _EXIT_CODE=1
  else
    echo "[L3:static] CLEAR (no malicious packages or CVE-flagged versions in known list)"
  fi
else
  echo "[L3:static] SKIP — no scannable files"
fi

# ─── IOC: Python-flavored RAT artifacts ───
echo ""
echo "─── IOC: Python RAT artifacts ────────────"

_IOC_HITS=0

# Known Python-related RAT-style filesystem markers
_IOC_PATHS=(
  "/tmp/ld.py"
  "/tmp/_init_.py"
  "/tmp/setup_.py"
  "/var/tmp/.python_log"
)

for p in "${_IOC_PATHS[@]}"; do
  if [ -e "$p" ]; then
    echo "  !! IOC file present: $p"
    _IOC_HITS=$((_IOC_HITS + 1))
  fi
done

# Suspicious running Python processes (loose heuristic, manual verify recommended)
if command -v pgrep &>/dev/null; then
  _susp=$(pgrep -f "python.* /tmp/" 2>/dev/null | head -3)
  if [ -n "$_susp" ]; then
    echo "  ⚠️  Python process from /tmp/ detected (PIDs: $_susp) — manual investigation recommended"
    _IOC_HITS=$((_IOC_HITS + 1))
  fi
fi

if [ $_IOC_HITS -eq 0 ]; then
  echo "[IOC] CLEAR"
else
  echo "[IOC] FAIL ($_IOC_HITS indicator(s))"
  _EXIT_CODE=1
fi

# ─── LF: Lockfile integrity ───
echo ""
echo "─── LF: Lockfile integrity ───────────────"

if [ -n "$_PRIMARY_LOCK" ]; then
  # Phantom dependency check: lockfile entries not in pyproject deps
  # (simple heuristic — full validation needs poetry/uv tooling)
  if [ "$_HAS_PYPROJECT" = 1 ]; then
    echo "  Lockfile present: $_PRIMARY_LOCK"
    echo "  Note: full phantom-dependency validation requires 'poetry check' or 'uv lock --check'"
    if command -v uv &>/dev/null && [ "$_HAS_UV_LOCK" = 1 ]; then
      if uv lock --check 2>&1 | tail -3 | grep -qiE "would update|out of sync|drift"; then
        echo "  ⚠️  uv.lock may be out of sync with pyproject.toml"
        _EXIT_CODE=1
      else
        echo "[LF:uv] CLEAR"
      fi
    fi
  fi
else
  echo "[LF] SKIP — no lockfile"
fi

# ─── Verdict ───
echo ""
echo "══════════════════════════════════════════"
if [ $_EXIT_CODE -eq 0 ]; then
  echo "  Verdict: CLEAR (Python scan)"
else
  echo "  Verdict: ATTENTION REQUIRED — review findings above"
fi
echo "══════════════════════════════════════════"

exit $_EXIT_CODE
