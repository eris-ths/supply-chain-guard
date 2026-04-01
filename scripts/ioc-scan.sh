#!/usr/bin/env bash
# Supply Chain Guard — IOC (Indicators of Compromise) Scanner
# Checks filesystem artifacts, running processes, and network connections
# against known supply chain attack indicators.
#
# Covers: T001 (axios RAT), with extensible structure for future threats.
# Cross-platform: macOS, Linux. For Windows, see ioc-scan.ps1.
#
# Usage: ./ioc-scan.sh

set -euo pipefail

_OS=$(uname -s)
_EXIT_CODE=0

echo "SCG ══════════════════════════════════════"
echo "  IOC Scanner"
echo "  OS: $_OS"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "══════════════════════════════════════════"

# ─── T001: axios RAT (2026-03-31) ───
echo ""
echo "─── T001: axios RAT (UNC1069/DPRK-APT) ──"

# Filesystem artifacts
echo ""
echo "[fs] Checking filesystem artifacts..."

case "$_OS" in
  Darwin)
    for path in "/Library/Caches/com.apple.act.mond" "$HOME/Library/LaunchAgents/com.apple.act.mond.plist"; do
      if [ -e "$path" ]; then
        echo "  !!CRITICAL: Found $path"
        ls -la "$path"
        _EXIT_CODE=1
      else
        echo "  [ok] $path — not found"
      fi
    done
    ;;
  Linux)
    for path in "/tmp/ld.py" "/tmp/.npm-cache/"; do
      if [ -e "$path" ]; then
        echo "  !!CRITICAL: Found $path"
        ls -la "$path"
        _EXIT_CODE=1
      else
        echo "  [ok] $path — not found"
      fi
    done
    ;;
  *)
    echo "  [skip] Unsupported OS for fs scan: $_OS"
    echo "  For Windows, use ioc-scan.ps1"
    ;;
esac

# Process check
echo ""
echo "[proc] Checking running processes..."

case "$_OS" in
  Darwin)
    if pgrep -fl com.apple.act.mond 2>/dev/null; then
      echo "  !!CRITICAL: RAT process running (com.apple.act.mond)"
      _EXIT_CODE=1
    else
      echo "  [ok] No RAT processes found"
    fi
    ;;
  Linux)
    if pgrep -fl "python3 /tmp/ld.py" 2>/dev/null; then
      echo "  !!CRITICAL: RAT process running (ld.py)"
      _EXIT_CODE=1
    else
      echo "  [ok] No RAT processes found"
    fi
    ;;
esac

# Persistence check
echo ""
echo "[persist] Checking persistence mechanisms..."

case "$_OS" in
  Darwin)
    if launchctl list 2>/dev/null | grep -q "com.apple.act.mond"; then
      echo "  !!CRITICAL: LaunchAgent registered (com.apple.act.mond)"
      _EXIT_CODE=1
    else
      echo "  [ok] No malicious LaunchAgents"
    fi
    ;;
  Linux)
    if crontab -l 2>/dev/null | grep -qi "ld.py\|\.npm-cache"; then
      echo "  !!CRITICAL: Cron persistence found"
      crontab -l | grep -i "ld.py\|\.npm-cache"
      _EXIT_CODE=1
    else
      echo "  [ok] No malicious cron entries"
    fi
    ;;
esac

# Network check
echo ""
echo "[net] Checking network connections..."
echo "  C2 indicators: 142.11.206.73, sfrclak.com"

if lsof -i -nP 2>/dev/null | grep -E '142\.11\.206\.73|sfrclak'; then
  echo "  !!CRITICAL: Active C2 connection detected!"
  _EXIT_CODE=1
else
  echo "  [ok] No C2 connections found"
fi

# DNS cache check (macOS)
if [ "$_OS" = "Darwin" ]; then
  if dscacheutil -cachedump 2>/dev/null | grep -qi "sfrclak"; then
    echo "  !!SUSPECT: sfrclak.com found in DNS cache (may indicate past connection)"
    _EXIT_CODE=1
  fi
fi

# ─── Verdict ───
echo ""
echo "═══════════════════════════════════════════"
if [ $_EXIT_CODE -ne 0 ]; then
  echo "[VERDICT] CRITICAL — Compromise indicators detected!"
  echo ""
  echo "Recommended immediate actions:"
  echo "  1. Block C2: echo '127.0.0.1 sfrclak.com' | sudo tee -a /etc/hosts"
  echo "  2. Kill processes (see output above)"
  echo "  3. Remove persistence artifacts"
  echo "  4. Run full project scan: ./project-scan.sh"
  echo ""
  echo "For detailed remediation, see README.md#response-playbook"
else
  echo "[VERDICT] CLEAR — No compromise indicators found"
fi
echo "═══════════════════════════════════════════"

exit $_EXIT_CODE
