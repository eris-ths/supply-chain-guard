# Supply Chain Guard — IOC Scanner (Windows/PowerShell)
# Checks filesystem artifacts, running processes, scheduled tasks,
# and network connections against known supply chain attack indicators.
#
# Covers: T001 (axios RAT), T004 (Shai-Hulud worm), T008 (SANDWORM_MODE
#         MCP/AI-toolchain poisoning). Kept in parity with ioc-scan.sh.
#
# SAFETY: This script is READ-ONLY. It does not modify, delete, or install
#         anything on your system. Safe to run at any time.
#
# Usage: .\ioc-scan.ps1

$ErrorActionPreference = "Stop"
$exitCode = 0

Write-Host "SCG ══════════════════════════════════════"
Write-Host "  IOC Scanner (Windows)"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC)"
Write-Host "══════════════════════════════════════════"

# ─── T001: axios RAT (2026-03-31) ───
Write-Host ""
Write-Host "─── T001: axios RAT (UNC1069/DPRK-APT) ──"

# Filesystem artifacts
Write-Host ""
Write-Host "[fs] Checking filesystem artifacts..."

$iocPaths = @(
    "$env:PROGRAMDATA\wt.exe",
    "$env:TEMP\6202033.vbs",
    "$env:TEMP\6202033.ps1"
)

foreach ($path in $iocPaths) {
    if (Test-Path $path) {
        Write-Host "  !!CRITICAL: Found $path" -ForegroundColor Red
        Get-Item $path | Format-List Name, Length, LastWriteTime
        $exitCode = 1
    } else {
        Write-Host "  [ok] $path — not found"
    }
}

# Process check
Write-Host ""
Write-Host "[proc] Checking running processes..."

# NOTE: Legitimate Windows Terminal may also use the "wt" process name.
# The ProgramData path filter reduces false positives, but edge cases exist
# if Windows Terminal is installed to a non-standard ProgramData location.
$wtProcs = Get-Process wt -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*ProgramData*" }
if ($wtProcs) {
    Write-Host "  !!CRITICAL: Suspicious wt.exe running from ProgramData" -ForegroundColor Red
    $wtProcs | Format-Table Id, Path -AutoSize
    $exitCode = 1
} else {
    Write-Host "  [ok] No suspicious processes found"
}

# Persistence check
Write-Host ""
Write-Host "[persist] Checking scheduled tasks..."

try {
    $task = schtasks /query /TN WindowsTerminalUpdate 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  !!CRITICAL: Scheduled task 'WindowsTerminalUpdate' found" -ForegroundColor Red
        Write-Host $task
        $exitCode = 1
    } else {
        Write-Host "  [ok] No malicious scheduled tasks"
    }
} catch {
    Write-Host "  [ok] No malicious scheduled tasks"
}

# Network check
Write-Host ""
Write-Host "[net] Checking network connections..."
Write-Host "  C2 indicators: 142.11.206.73, sfrclak.com"

$c2Hit = netstat -an | Select-String "142.11.206.73"
if ($c2Hit) {
    Write-Host "  !!CRITICAL: Active C2 connection detected!" -ForegroundColor Red
    $c2Hit | ForEach-Object { Write-Host "    $_" }
    $exitCode = 1
} else {
    Write-Host "  [ok] No C2 connections found"
}

# DNS cache check
try {
    $dnsHit = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -like "*sfrclak*" }
    if ($dnsHit) {
        Write-Host "  !!SUSPECT: sfrclak.com found in DNS cache" -ForegroundColor Yellow
        $exitCode = 1
    }
} catch {}

# ─── T004: Shai-Hulud self-replicating worm (2025-09 → 2026, ongoing) ───
Write-Host ""
Write-Host "─── T004: Shai-Hulud worm ────────────────"
Write-Host ""
Write-Host "[fs] Checking Shai-Hulud payload artifacts..."

# Payload files dropped into the project / node_modules. Search the current
# project tree (bounded depth to stay fast + read-only). -ErrorAction
# SilentlyContinue keeps an unreadable subtree from aborting under Stop mode.
$shMarkers = @("setup_bun.js", "bun_environment.js", "shai-hulud-workflow.yml")
$shFound = $false
foreach ($marker in $shMarkers) {
    $hits = Get-ChildItem -Path . -Filter $marker -Recurse -Depth 6 -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\\.git\\' } | Select-Object -First 5
    if ($hits) {
        Write-Host "  !!CRITICAL: Shai-Hulud payload file present: $marker" -ForegroundColor Red
        $hits | ForEach-Object { Write-Host "    $($_.FullName)" }
        $exitCode = 1
        $shFound = $true
    }
}

# Malicious GitHub Actions workflow dropped for persistence
if (Test-Path ".github\workflows") {
    $wfHit = Get-ChildItem -Path ".github\workflows" -File -ErrorAction SilentlyContinue |
             Select-String -Pattern "shai-hulud|webhook\.site/bb8ca5f6" -List -ErrorAction SilentlyContinue
    if ($wfHit) {
        Write-Host "  !!CRITICAL: Shai-Hulud workflow signature in .github\workflows\" -ForegroundColor Red
        $exitCode = 1
        $shFound = $true
    }
}

# Exfil signature in DNS cache (active-connection check folded into T001 netstat)
try {
    $shDns = Get-DnsClientCache -ErrorAction SilentlyContinue |
             Where-Object { $_.Entry -like "*t.m-kosche.com*" -or $_.Entry -like "*webhook.site*" }
    if ($shDns) {
        Write-Host "  !!SUSPECT: Shai-Hulud exfil host in DNS cache" -ForegroundColor Yellow
        $exitCode = 1
        $shFound = $true
    }
} catch {}

if (-not $shFound) { Write-Host "  [ok] No Shai-Hulud indicators found" }

# ─── T008: SANDWORM_MODE — malicious MCP server / AI-toolchain poisoning ───
Write-Host ""
Write-Host "─── T008: MCP / AI-toolchain poisoning ───"
Write-Host ""
Write-Host "[cfg] Checking AI dev-tool configs for injected malicious tools..."

# Config files SANDWORM_MODE targets on Windows. We do NOT flag mere existence
# (these are normal). We flag known-malicious MCP tool/server signatures inside
# them. .vscode\tasks.json is a Windows-primary vector (auto-run on folder open).
$mcpCfgs = @(
    "$env:USERPROFILE\.claude\settings.json",
    "$env:USERPROFILE\.cursor\mcp.json",
    "$env:USERPROFILE\.continue\config.json",
    "$env:USERPROFILE\.windsurf\mcp.json",
    ".vscode\tasks.json"
)
# Signatures: the innocuous-looking tool names SANDWORM_MODE registers, plus its
# publisher aliases. Presence in a config you did not intentionally install
# warrants manual review.
$mcpSig = "index_project|lint_check|scan_dependencies|official334|javaorg"
$mcpFound = $false
foreach ($cfg in $mcpCfgs) {
    if (Test-Path $cfg) {
        $sigHit = Select-String -Path $cfg -Pattern $mcpSig -List -ErrorAction SilentlyContinue
        if ($sigHit) {
            Write-Host "  !!SUSPECT: SANDWORM_MODE tool signature in $cfg — verify you installed these tools intentionally" -ForegroundColor Yellow
            $exitCode = 1
            $mcpFound = $true
        }
    }
}
if (-not $mcpFound) { Write-Host "  [ok] No known malicious MCP tool signatures found" }
Write-Host "  [note] Tool-name innocuousness is NOT trust. Review any unfamiliar MCP server's tool definitions manually (see SKILL.md D.7)."

# ─── Verdict ───
Write-Host ""
Write-Host "═══════════════════════════════════════════"
if ($exitCode -ne 0) {
    Write-Host "[VERDICT] CRITICAL — Compromise indicators detected!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Recommended immediate actions:"
    Write-Host "  1. Block C2: Add '127.0.0.1 sfrclak.com' to C:\Windows\System32\drivers\etc\hosts"
    Write-Host "  2. Kill suspicious processes (see output above)"
    Write-Host "  3. Remove scheduled task: schtasks /Delete /TN WindowsTerminalUpdate /F"
    Write-Host "  4. Delete IOC files listed above"
    Write-Host ""
    Write-Host "For detailed remediation, see README.md#response-playbook"
} else {
    Write-Host "[VERDICT] CLEAR — No compromise indicators found" -ForegroundColor Green
}
Write-Host "═══════════════════════════════════════════"

exit $exitCode
