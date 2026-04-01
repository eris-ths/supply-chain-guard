#!/usr/bin/env bash
# Supply Chain Guard — Environment-wide scan
# Scans all projects under a root directory for compromised packages
# Usage: ./env-scan.sh [scan_root_dir]
#
# SAFETY: This script is READ-ONLY. It does not modify, delete, or install
#         anything on your system. Safe to run at any time.

set -euo pipefail

_ROOT="${1:-$HOME/Develop}"
_OS=$(uname -s)

echo "SCG ══════════════════════════════════════"
echo "  Environment Scan"
echo "  Root: $_ROOT"
echo "  OS:   $_OS"
echo "══════════════════════════════════════════"

# ─── Phase 1: IOC Filesystem Scan ───
echo ""
echo "─── IOC: Filesystem ──────────────────────"

_IOC_HIT=0

case "$_OS" in
  Darwin)
    if ls /Library/Caches/com.apple.act.mond 2>/dev/null; then
      echo "!!CRITICAL: darwin RAT binary found"; _IOC_HIT=1
    fi
    if ls ~/Library/LaunchAgents/com.apple.act.mond.plist 2>/dev/null; then
      echo "!!CRITICAL: darwin LaunchAgent found"; _IOC_HIT=1
    fi
    if pgrep -f com.apple.act.mond >/dev/null 2>&1; then
      echo "!!CRITICAL: darwin RAT process running"; _IOC_HIT=1
    fi
    ;;
  Linux)
    if ls /tmp/ld.py 2>/dev/null; then
      echo "!!CRITICAL: linux RAT script found"; _IOC_HIT=1
    fi
    if ls /tmp/.npm-cache/ 2>/dev/null; then
      echo "!!SUSPECT: linux staging directory found"; _IOC_HIT=1
    fi
    if pgrep -f "python3 /tmp/ld.py" >/dev/null 2>&1; then
      echo "!!CRITICAL: linux RAT process running"; _IOC_HIT=1
    fi
    if crontab -l 2>/dev/null | grep -qi "ld.py\|npm-cache"; then
      echo "!!CRITICAL: linux cron persistence found"; _IOC_HIT=1
    fi
    ;;
esac

if [ $_IOC_HIT -eq 0 ]; then
  echo "[IOC:fs] CLEAR"
fi

# ─── Phase 2: IOC Network Scan ───
echo ""
echo "─── IOC: Network ─────────────────────────"

if lsof -i -nP 2>/dev/null | grep -qE '142\.11\.206\.73|sfrclak'; then
  echo "!!CRITICAL: Active C2 connection detected (142.11.206.73 / sfrclak.com)"
else
  echo "[IOC:net] CLEAR"
fi

# ─── Phase 3: Cross-project compromised version scan ───
echo ""
echo "─── Cross-project: Compromised Versions ──"

# axios compromised versions (T001)
_COMPROMISED='1\.14\.1\|0\.30\.4'
_AXIOS_HIT=0

find "$_ROOT" -name "package-lock.json" -not -path "*/node_modules/*" -maxdepth 5 2>/dev/null | while read -r f; do
  hit=$(grep -A2 '"axios"' "$f" 2>/dev/null | grep '"version"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | grep -E "$_COMPROMISED" || true)
  if [ -n "$hit" ]; then
    echo "!!HIGH: $(dirname "$f") — axios@$hit"
    _AXIOS_HIT=1
  fi
done

if [ $_AXIOS_HIT -eq 0 ]; then
  echo "[axios] CLEAR — no compromised versions found"
fi

# ─── Phase 4: Cross-project malicious package scan ───
echo ""
echo "─── Cross-project: Malicious Packages ────"

_MALICIOUS=(plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm)
_MAL_HIT=0

for mal in "${_MALICIOUS[@]}"; do
  find "$_ROOT" -name "package-lock.json" -not -path "*/node_modules/*" -maxdepth 5 -exec grep -l "\"$mal\"" {} \; 2>/dev/null | while read -r f; do
    echo "!!CRITICAL: $mal found in $(dirname "$f")"
    _MAL_HIT=1
  done
done

if [ $_MAL_HIT -eq 0 ]; then
  echo "[malicious] CLEAR — no known malicious packages found"
fi

# ─── Verdict ───
echo ""
echo "═══════════════════════════════════════════"
if [ $_IOC_HIT -ne 0 ]; then
  echo "[VERDICT] CRITICAL — IOC artifacts detected. Run ioc-scan.sh for details."
else
  echo "[VERDICT] CLEAR"
fi
echo "═══════════════════════════════════════════"
