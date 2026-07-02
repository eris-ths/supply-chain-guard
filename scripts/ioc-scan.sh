#!/usr/bin/env bash
# Supply Chain Guard — IOC (Indicators of Compromise) Scanner
# Checks filesystem artifacts, running processes, and network connections
# against known supply chain attack indicators.
#
# Covers: T001 (axios RAT), with extensible structure for future threats.
# Cross-platform: macOS, Linux. For Windows, see ioc-scan.ps1.
#
# SAFETY: This script is READ-ONLY. It does not modify, delete, or install
#         anything on your system. Safe to run at any time.
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

# ─── T004: Shai-Hulud self-replicating worm (2025-09 → 2026, ongoing) ───
echo ""
echo "─── T004: Shai-Hulud worm ────────────────"

# Payload files dropped into the project / node_modules. Search the current
# project tree (bounded depth to stay fast + read-only). `grep -q`/`find` are
# kept inside `if` conditions so a no-match (exit 1) never aborts under set -e.
echo ""
echo "[fs] Checking Shai-Hulud payload artifacts..."

_SH_MARKERS=(setup_bun.js bun_environment.js shai-hulud-workflow.yml)
_sh_found=0
for marker in "${_SH_MARKERS[@]}"; do
  # -path prune keeps it quick; limit depth so huge trees don't stall
  if find . -maxdepth 6 -name "$marker" -not -path '*/.git/*' 2>/dev/null | grep -q .; then
    echo "  !!CRITICAL: Shai-Hulud payload file present: $marker"
    find . -maxdepth 6 -name "$marker" -not -path '*/.git/*' 2>/dev/null | head -5
    _EXIT_CODE=1
    _sh_found=1
  fi
done

# Malicious GitHub Actions workflow dropped for persistence
if [ -d ".github/workflows" ]; then
  if grep -rilqE "shai-hulud|webhook\.site/bb8ca5f6" .github/workflows 2>/dev/null; then
    echo "  !!CRITICAL: Shai-Hulud workflow signature in .github/workflows/"
    _EXIT_CODE=1
    _sh_found=1
  fi
fi

# /tmp daemon path (Linux/macOS)
if ls /tmp/kitty-* &>/dev/null; then
  echo "  !!SUSPECT: /tmp/kitty-* daemon path present (Shai-Hulud persistence)"
  _EXIT_CODE=1
  _sh_found=1
fi

# Exfil signature in network / DNS
if lsof -i -nP 2>/dev/null | grep -qE 't\.m-kosche\.com|webhook\.site'; then
  echo "  !!CRITICAL: Active connection to Shai-Hulud exfil host"
  _EXIT_CODE=1
  _sh_found=1
fi

[ "$_sh_found" -eq 0 ] && echo "  [ok] No Shai-Hulud indicators found"

# ─── T008: SANDWORM_MODE — malicious MCP server / AI-toolchain poisoning ───
echo ""
echo "─── T008: MCP / AI-toolchain poisoning ───"
echo ""
echo "[cfg] Checking AI dev-tool MCP configs for injected malicious tools..."

# Config files SANDWORM_MODE targets. We do NOT flag mere existence (these are
# normal). We flag known-malicious MCP tool/server signatures inside them.
_MCP_CFGS=(
  "$HOME/.claude/settings.json"
  "$HOME/.cursor/mcp.json"
  "$HOME/.continue/config.json"
  "$HOME/.windsurf/mcp.json"
)
# Signatures: the three innocuous-looking tool names SANDWORM_MODE registers,
# and its publisher aliases. Presence of these tool names in an MCP config that
# you did not intentionally install warrants manual review.
_MCP_SIG='index_project|lint_check|scan_dependencies|official334|javaorg'
_mcp_found=0
for cfg in "${_MCP_CFGS[@]}"; do
  if [ -f "$cfg" ]; then
    if grep -qE "$_MCP_SIG" "$cfg" 2>/dev/null; then
      echo "  !!SUSPECT: SANDWORM_MODE tool signature in $cfg — verify you installed these MCP tools intentionally"
      _EXIT_CODE=1
      _mcp_found=1
    fi
  fi
done
[ "$_mcp_found" -eq 0 ] && echo "  [ok] No known malicious MCP tool signatures found"
echo "  [note] Tool-name innocuousness is NOT trust. Review any unfamiliar MCP server's tool definitions manually (see SKILL.md D.7)."

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
