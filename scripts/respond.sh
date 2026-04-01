#!/usr/bin/env bash
# Supply Chain Guard — Remediation Script
# Interactive response for confirmed compromises.
#
# WARNING: This script performs DESTRUCTIVE operations:
#   - Kills processes
#   - Deletes files
#   - Removes persistence mechanisms
#   - Wipes node_modules and lockfiles
#   - Modifies /etc/hosts (requires sudo)
#
# Every destructive action requires explicit [y/N] confirmation.
# Default is NO — pressing Enter without input skips the action.
#
# Usage: ./respond.sh [--critical | --high]
#   --critical  Full RAT cleanup (network isolate, kill, remove, reinstall)
#   --high      Version pin only (override compromised version, reinstall)

set -euo pipefail

_OS=$(uname -s)
_MODE="${1:---help}"

# ─── Colors ───
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Confirm before every destructive action ───
confirm() {
  local msg="$1"
  printf "${YELLOW}⚠  %s${NC}\n" "$msg"
  printf "   Continue? [y/N]: "
  read -r ans
  case "$ans" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) printf "   ${GREEN}Skipped.${NC}\n"; return 1 ;;
  esac
}

# ─── Dry-run guard ───
run_destructive() {
  local description="$1"
  shift
  if confirm "$description"; then
    printf "   Running: %s\n" "$*"
    "$@"
    printf "   ${GREEN}Done.${NC}\n"
  fi
}

# ═══════════════════════════════════════════
# CRITICAL response — full RAT cleanup
# ═══════════════════════════════════════════
do_critical() {
  echo ""
  printf "${RED}${BOLD}SCG — CRITICAL Response${NC}\n"
  printf "${RED}This will perform destructive cleanup operations.${NC}\n"
  printf "${RED}Each step requires your explicit confirmation.${NC}\n"
  echo ""

  # Step 1: Network isolate
  echo "─── Step 1/6: Network Isolation ────────────"
  echo "   Block C2 domain (sfrclak.com) via /etc/hosts"
  if confirm "Add '127.0.0.1 sfrclak.com' to /etc/hosts? (requires sudo)"; then
    if grep -q "sfrclak.com" /etc/hosts 2>/dev/null; then
      printf "   ${GREEN}Already blocked.${NC}\n"
    else
      echo "127.0.0.1 sfrclak.com" | sudo tee -a /etc/hosts
      printf "   ${GREEN}Blocked.${NC}\n"
    fi
  fi
  echo ""

  # Step 2: Kill RAT processes
  echo "─── Step 2/6: Kill Processes ───────────────"
  case "$_OS" in
    Darwin)
      if pgrep -f com.apple.act.mond >/dev/null 2>&1; then
        run_destructive "Kill RAT process (com.apple.act.mond)?" pkill -f com.apple.act.mond
      else
        printf "   ${GREEN}No RAT processes found.${NC}\n"
      fi
      ;;
    Linux)
      if pgrep -f "python3 /tmp/ld.py" >/dev/null 2>&1; then
        run_destructive "Kill RAT process (ld.py)?" pkill -f "python3 /tmp/ld.py"
      else
        printf "   ${GREEN}No RAT processes found.${NC}\n"
      fi
      ;;
  esac
  echo ""

  # Step 3: Remove persistence
  echo "─── Step 3/6: Remove Persistence ───────────"
  case "$_OS" in
    Darwin)
      if [ -f "$HOME/Library/LaunchAgents/com.apple.act.mond.plist" ]; then
        run_destructive "Remove LaunchAgent (com.apple.act.mond)?" \
          launchctl remove com.apple.act.mond
        run_destructive "Delete plist file?" \
          rm -f "$HOME/Library/LaunchAgents/com.apple.act.mond.plist"
      else
        printf "   ${GREEN}No LaunchAgent found.${NC}\n"
      fi
      if [ -f "/Library/Caches/com.apple.act.mond" ]; then
        run_destructive "Delete RAT binary (/Library/Caches/com.apple.act.mond)?" \
          rm -f /Library/Caches/com.apple.act.mond
      else
        printf "   ${GREEN}No RAT binary found.${NC}\n"
      fi
      ;;
    Linux)
      if crontab -l 2>/dev/null | grep -qi "ld.py\|npm-cache"; then
        echo "   Malicious cron entries found:"
        crontab -l | grep -i "ld.py\|npm-cache"
        # NOTE: grep -v "npm-cache" could remove legitimate cron entries that
        # happen to contain "npm-cache" in their command. Low risk since such
        # entries are rare, and this step requires explicit user confirmation.
        if confirm "Remove malicious cron entries?"; then
          crontab -l | grep -v "ld.py\|npm-cache" | crontab -
          printf "   ${GREEN}Cleaned.${NC}\n"
        fi
      else
        printf "   ${GREEN}No malicious cron entries.${NC}\n"
      fi
      [ -f "/tmp/ld.py" ] && run_destructive "Delete /tmp/ld.py?" rm -f /tmp/ld.py
      [ -d "/tmp/.npm-cache/" ] && run_destructive "Delete /tmp/.npm-cache/?" rm -rf /tmp/.npm-cache/
      ;;
  esac
  echo ""

  # Step 4: Clean npm
  echo "─── Step 4/6: Clean npm ────────────────────"
  if [ -d "node_modules" ] || [ -f "package-lock.json" ]; then
    run_destructive "Delete node_modules/ and package-lock.json?" \
      sh -c 'rm -rf node_modules package-lock.json'
    run_destructive "Clear npm cache?" \
      npm cache clean --force
  else
    printf "   ${GREEN}No node_modules or lockfile in current directory.${NC}\n"
  fi
  echo ""

  # Step 5: Reinstall
  echo "─── Step 5/6: Reinstall ────────────────────"
  if [ -f "package.json" ]; then
    run_destructive "Run 'npm install && npm ci'?" \
      sh -c 'npm install && npm ci'
  else
    printf "   ${YELLOW}No package.json — skipping reinstall.${NC}\n"
  fi
  echo ""

  # Step 6: Rescan
  echo "─── Step 6/6: Verification Scan ────────────"
  echo "   Run a scan to verify cleanup:"
  echo "   ./ioc-scan.sh    (IOC artifacts)"
  if [ -f "package.json" ]; then
    echo "   ./project-scan.sh (project dependencies)"
  fi
  echo ""

  printf "${GREEN}${BOLD}Remediation complete.${NC}\n"
  echo "Review scan results above. If issues persist, re-run with --critical."
}

# ═══════════════════════════════════════════
# HIGH response — version pin
# ═══════════════════════════════════════════
do_high() {
  local pkg="${2:-}"
  local safe_ver="${3:-}"

  echo ""
  printf "${YELLOW}${BOLD}SCG — HIGH Response${NC}\n"
  printf "Pin compromised package to a safe version.\n"
  echo ""

  if [ ! -f "package.json" ]; then
    printf "${RED}ERROR: package.json not found in current directory.${NC}\n"
    exit 1
  fi

  if [ -z "$pkg" ] || [ -z "$safe_ver" ]; then
    echo "Usage: ./respond.sh --high <package> <safe_version>"
    echo ""
    echo "Examples:"
    echo "  ./respond.sh --high axios 1.14.0"
    echo "  ./respond.sh --high event-stream 3.3.5"
    exit 1
  fi

  # Detect package manager
  if [ -f "yarn.lock" ]; then
    _PM="yarn"
    _KEY="resolutions"
  else
    _PM="npm"
    _KEY="overrides"
  fi

  echo "─── Step 1/3: Pin Safe Version ─────────────"
  echo "   Package manager: $_PM"
  echo "   Will add to package.json:"
  echo "     \"$_KEY\": { \"$pkg\": \"$safe_ver\" }"
  echo ""

  if confirm "Add version override to package.json?"; then
    python3 -c "
import json, sys
with open('package.json', 'r') as f:
    data = json.load(f)
key = sys.argv[1]
pkg = sys.argv[2]
ver = sys.argv[3]
if key not in data:
    data[key] = {}
data[key][pkg] = ver
with open('package.json', 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
print('   Added override.')
" "$_KEY" "$pkg" "$safe_ver"
    printf "   ${GREEN}Done.${NC}\n"
  fi
  echo ""

  echo "─── Step 2/3: Reinstall ────────────────────"
  if [ "$_PM" = "yarn" ]; then
    run_destructive "Run 'yarn install'?" yarn install
  else
    run_destructive "Run 'npm ci'?" npm ci
  fi
  echo ""

  echo "─── Step 3/3: Verify ───────────────────────"
  echo "   Run './project-scan.sh' to verify the fix."
  echo ""

  printf "${GREEN}${BOLD}Version pin complete.${NC}\n"
}

# ═══════════════════════════════════════════
# Help
# ═══════════════════════════════════════════
show_help() {
  echo "Supply Chain Guard — Remediation Script"
  echo ""
  echo "Usage:"
  echo "  ./respond.sh --critical                     Full RAT cleanup"
  echo "  ./respond.sh --high <package> <safe_version> Pin to safe version"
  echo ""
  echo "Examples:"
  echo "  ./respond.sh --critical"
  echo "  ./respond.sh --high axios 1.14.0"
  echo "  ./respond.sh --high event-stream 3.3.5"
  echo ""
  echo "Every destructive action requires explicit [y/N] confirmation."
  echo "Default is NO — pressing Enter skips the action."
  echo ""
  echo "Run a scan first to determine severity:"
  echo "  ./ioc-scan.sh       (check for RAT artifacts)"
  echo "  ./project-scan.sh   (check project dependencies)"
  echo "  ./env-scan.sh       (check all projects on machine)"
}

# ─── Main ───
case "$_MODE" in
  --critical) do_critical ;;
  --high)     do_high "$@" ;;
  *)          show_help ;;
esac
