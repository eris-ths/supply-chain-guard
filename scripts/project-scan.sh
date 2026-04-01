#!/usr/bin/env bash
# Supply Chain Guard — Project-level scan
# Runs all scanner layers against the current project.
# Requires: package.json in current directory
#
# SAFETY: This script is READ-ONLY. It does not modify, delete, or install
#         anything on your system. Safe to run at any time.
#
# Layers:
#   L1: npm audit (registry vulnerabilities)
#   L2: osv-scanner or OSV.dev API (Google OSV database)
#   L3: Static malicious package list
#   IOC: Filesystem + network artifact check
#   LF:  Lockfile integrity verification
#
# Usage: cd my-project && /path/to/project-scan.sh

set -euo pipefail

if [ ! -f "package.json" ]; then
  echo "ERROR: package.json not found in current directory."
  echo "Run this script from your project root, or use env-scan.sh for machine-wide scanning."
  exit 1
fi

_OS=$(uname -s)
_EXIT_CODE=0
_PROJECT=$(basename "$(pwd)")

echo "SCG ══════════════════════════════════════"
echo "  Project Scan: $_PROJECT"
echo "  OS: $_OS"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "══════════════════════════════════════════"

# ─── L1: npm audit ───
echo ""
echo "─── L1: npm audit ────────────────────────"

if command -v npm &>/dev/null; then
  npm audit --json 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    vs = d.get('vulnerabilities', {})
    if not vs:
        print('[L1:audit] CLEAR')
    else:
        for n, i in vs.items():
            s = i.get('severity', '?')
            va = [v.get('title', '?') if isinstance(v, dict) else v for v in i.get('via', [])]
            print(f'  !!{s.upper()}: {n} — {va}')
except:
    print('[L1:audit] ERR — manual check needed')
" || echo "[L1:audit] ERR — npm audit failed"
else
  echo "[L1:audit] SKIP — npm not found"
fi

# ─── L2: OSV scanner ───
echo ""
echo "─── L2: OSV.dev ──────────────────────────"

if [ -f "package-lock.json" ]; then
  if command -v osv-scanner &>/dev/null; then
    if osv-scanner --lockfile=package-lock.json 2>/dev/null; then
      echo "[L2:osv] CLEAR"
    else
      echo "  !!FOUND — see osv-scanner output above"
      _EXIT_CODE=1
    fi
  else
    echo "[L2:osv] osv-scanner not installed — using API fallback"
    python3 -c "
import json, urllib.request as ur
lk = json.load(open('package-lock.json'))
ps = lk.get('packages', lk.get('dependencies', {}))
hits = []
for p, i in ps.items():
    n = i.get('name') or p.replace('node_modules/', '')
    v = i.get('version', '')
    if not n or not v:
        continue
    b = json.dumps({'package': {'name': n, 'ecosystem': 'npm'}, 'version': v}).encode()
    try:
        r = json.loads(ur.urlopen(
            ur.Request('https://api.osv.dev/v1/query', data=b,
                       headers={'Content-Type': 'application/json'}),
            timeout=5
        ).read())
        if r.get('vulns'):
            hits.append(f'{n}@{v}: {[x[\"id\"] for x in r[\"vulns\"][:3]]}')
    except:
        pass
if hits:
    print('[L2:osv] HITS:')
    for h in hits:
        print(f'  !!{h}')
else:
    print('[L2:osv] CLEAR')
" 2>/dev/null || echo "[L2:osv] ERR — API check failed"
  fi
elif [ -f "yarn.lock" ]; then
  if command -v osv-scanner &>/dev/null; then
    osv-scanner --lockfile=yarn.lock 2>/dev/null || true
  else
    echo "[L2:osv] SKIP — osv-scanner not installed and no package-lock.json for API fallback"
  fi
else
  echo "[L2:osv] SKIP — no lockfile found"
fi

# ─── L3: Static malicious package list ───
echo ""
echo "─── L3: Static List ──────────────────────"

_MALICIOUS=(plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm)
_L3_HIT=0

for p in "${_MALICIOUS[@]}"; do
  if npm list "$p" 2>/dev/null | grep -v "empty" | grep -q "$p"; then
    echo "  !!CRITICAL: $p is installed!"
    _L3_HIT=1
    _EXIT_CODE=1
  fi
done

if [ $_L3_HIT -eq 0 ]; then
  echo "[L3:static] CLEAR"
fi

# ─── IOC: Filesystem + Network ───
echo ""
echo "─── IOC: Filesystem + Network ────────────"

_IOC_HIT=0

case "$_OS" in
  Darwin)
    ls /Library/Caches/com.apple.act.mond 2>/dev/null && { echo "  !!CRITICAL: darwin RAT binary"; _IOC_HIT=1; } || true
    ls ~/Library/LaunchAgents/com.apple.act.mond.plist 2>/dev/null && { echo "  !!CRITICAL: darwin LaunchAgent"; _IOC_HIT=1; } || true
    pgrep -f com.apple.act.mond >/dev/null 2>&1 && { echo "  !!CRITICAL: darwin RAT process"; _IOC_HIT=1; } || true
    ;;
  Linux)
    ls /tmp/ld.py 2>/dev/null && { echo "  !!CRITICAL: linux RAT script"; _IOC_HIT=1; } || true
    ls /tmp/.npm-cache/ 2>/dev/null && { echo "  !!SUSPECT: linux staging dir"; _IOC_HIT=1; } || true
    pgrep -f "python3 /tmp/ld.py" >/dev/null 2>&1 && { echo "  !!CRITICAL: linux RAT process"; _IOC_HIT=1; } || true
    ;;
esac

lsof -i -nP 2>/dev/null | grep -qE '142\.11\.206\.73|sfrclak' && { echo "  !!CRITICAL: C2 connection active"; _IOC_HIT=1; } || true

if [ $_IOC_HIT -eq 0 ]; then
  echo "[IOC] CLEAR"
else
  _EXIT_CODE=1
fi

# ─── LF: Lockfile integrity ───
echo ""
echo "─── LF: Lockfile Integrity ───────────────"

if [ -f "package-lock.json" ]; then
  _INTEGRITY_COUNT=$(grep -c '"integrity"' package-lock.json 2>/dev/null || echo "0")
  echo "  Integrity hashes: $_INTEGRITY_COUNT"

  if npm ci --dry-run 2>&1 | tail -3 | grep -qi "error\|ERR"; then
    echo "  !!LOW: lockfile integrity check failed"
    _EXIT_CODE=1
  else
    echo "[LF:integ] CLEAR"
  fi
else
  echo "[LF:integ] SKIP — no package-lock.json"
fi

# ─── G4: Postinstall scripts ───
echo ""
echo "─── G4: Postinstall Scripts ──────────────"

if [ -d "node_modules" ]; then
  _SAFE_POSTINSTALL="node-gyp\|husky\|esbuild\|puppeteer\|sharp\|better-sqlite3\|bcrypt\|canvas\|grpc\|leveldown\|nodegit\|sqlite3\|electron"
  _SUSPICIOUS=$(find node_modules -maxdepth 2 -name "package.json" -exec grep -l '"postinstall"' {} \; 2>/dev/null | while read -r pj; do
    _pkg=$(python3 -c "import json; print(json.load(open('$pj')).get('name','?'))" 2>/dev/null || echo "?")
    if ! echo "$_pkg" | grep -qi "$_SAFE_POSTINSTALL"; then
      echo "  $_pkg ($pj)"
    fi
  done)

  if [ -n "$_SUSPICIOUS" ]; then
    echo "  !!MEDIUM: Suspicious postinstall scripts found:"
    echo "$_SUSPICIOUS"
  else
    echo "[G4:postinstall] CLEAR"
  fi
else
  echo "[G4:postinstall] SKIP — node_modules not found (run npm install first)"
fi

# ─── Verdict ───
echo ""
echo "═══════════════════════════════════════════"
if [ $_EXIT_CODE -ne 0 ]; then
  echo "[VERDICT] ISSUES FOUND — Review output above"
  echo "For remediation steps, see README.md#response-playbook"
else
  echo "[VERDICT] CLEAR"
fi
echo "═══════════════════════════════════════════"

exit $_EXIT_CODE
