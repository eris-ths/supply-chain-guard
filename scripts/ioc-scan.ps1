# Supply Chain Guard — IOC Scanner (Windows/PowerShell)
# Checks filesystem artifacts, running processes, scheduled tasks,
# and network connections against known supply chain attack indicators.
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
