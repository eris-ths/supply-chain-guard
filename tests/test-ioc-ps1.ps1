# SAFETY: This test does not modify your system outside of temp directories.
# Windows analogue of tests/test-ioc-2026-threats.sh — verifies ioc-scan.ps1
# detects the 2026 threats ported in PR #15 (Shai-Hulud T004 payloads,
# SANDWORM_MODE T008 MCP signatures) AND stays CLEAR / exit 0 on a clean tree.
#
# Run locally:  pwsh tests/test-ioc-ps1.ps1
# In CI:        invoked by the windows-ps1 job in .github/workflows/tests.yml

$ErrorActionPreference = "Stop"
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo    = Split-Path -Parent $here
$ioc     = Join-Path $repo "scripts\ioc-scan.ps1"
$passed  = 0
$failed  = 0

function Pass($m) { Write-Host "  PASS: $m"; $script:passed++ }
function Fail($m) { Write-Host "  FAIL: $m"; $script:failed++ }

# Run ioc-scan.ps1 from inside $dir, optionally overriding USERPROFILE (so the
# T008 MCP-config scan reads a planted config instead of the real home). Returns
# a hashtable @{ Out = <combined output string>; Exit = <exit code> }.
function Invoke-Scan {
    param([string]$Dir, [string]$UserProfile)
    $prevPwd  = Get-Location
    $prevUP   = $env:USERPROFILE
    try {
        Set-Location $Dir
        if ($UserProfile) { $env:USERPROFILE = $UserProfile }
        # Capture output + exit code. ioc-scan.ps1 sets $ErrorActionPreference
        # itself; run it in a child scope so a mid-scan throw can't abort us.
        $out = & pwsh -NoProfile -File $ioc 2>&1 | Out-String
        return @{ Out = $out; Exit = $LASTEXITCODE }
    } finally {
        Set-Location $prevPwd
        $env:USERPROFILE = $prevUP
    }
}

Write-Host "=== test-ioc-ps1 ==="

# ─── Test 1: Clean project — T004/T008 CLEAR, exit 0 (no false positive) ───
$clean = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("scg-clean-" + [guid]::NewGuid())) -Force
$r1 = Invoke-Scan -Dir $clean.FullName -UserProfile $clean.FullName
Remove-Item -Recurse -Force $clean

if ($r1.Out -match 'T004: Shai-Hulud worm' -and $r1.Out -match '\[ok\] No Shai-Hulud indicators') {
    Pass "Shai-Hulud (T004) CLEAR on clean project"
} else {
    Fail "T004 did not report clean on a clean project"; Write-Host $r1.Out
}
if ($r1.Out -match '\[ok\] No known malicious MCP tool signatures') {
    Pass "MCP poisoning (T008) CLEAR on clean project"
} else {
    Fail "T008 did not report clean on a clean project"
}
if ($r1.Exit -eq 0) {
    Pass "Clean project -> exit 0 (no false positive)"
} else {
    Fail "Clean project should exit 0 (got $($r1.Exit))"; Write-Host $r1.Out
}

# ─── Test 2: Shai-Hulud payload files ARE detected ───
$sh = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("scg-sh-" + [guid]::NewGuid())) -Force
New-Item -ItemType Directory -Path (Join-Path $sh.FullName ".github\workflows") -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $sh.FullName "bun_environment.js") -Force | Out-Null
Set-Content -Path (Join-Path $sh.FullName ".github\workflows\shai-hulud-workflow.yml") -Value "# shai-hulud"
$r2 = Invoke-Scan -Dir $sh.FullName -UserProfile $sh.FullName
Remove-Item -Recurse -Force $sh

if ($r2.Out -match 'CRITICAL: Shai-Hulud payload file present: bun_environment\.js') {
    Pass "Detects Shai-Hulud payload file bun_environment.js"
} else {
    Fail "Did not detect bun_environment.js"; Write-Host $r2.Out
}
if ($r2.Exit -ne 0) {
    Pass "Shai-Hulud payload -> non-zero exit ($($r2.Exit))"
} else {
    Fail "Should exit non-zero when Shai-Hulud payload present (got 0)"
}

# ─── Test 3: SANDWORM_MODE MCP signature IS detected ───
# Plant a poisoned MCP config under a temp USERPROFILE; ioc-scan.ps1 reads
# $env:USERPROFILE\.cursor\mcp.json among others.
$poison = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("scg-poison-" + [guid]::NewGuid())) -Force
New-Item -ItemType Directory -Path (Join-Path $poison.FullName ".cursor") -Force | Out-Null
Set-Content -Path (Join-Path $poison.FullName ".cursor\mcp.json") `
    -Value '{ "mcpServers": { "helper": { "tools": ["index_project", "lint_check", "scan_dependencies"] } } }'
$r3 = Invoke-Scan -Dir $poison.FullName -UserProfile $poison.FullName
Remove-Item -Recurse -Force $poison

if ($r3.Out -match 'SUSPECT: SANDWORM_MODE tool signature') {
    Pass "Detects SANDWORM_MODE MCP tool signature in mcp.json"
} else {
    Fail "Did not detect SANDWORM_MODE signature"; Write-Host $r3.Out
}
if ($r3.Exit -ne 0) {
    Pass "Poisoned MCP config -> non-zero exit ($($r3.Exit))"
} else {
    Fail "Should exit non-zero when MCP signature present (got 0)"
}

# ─── Results ───
Write-Host ""
Write-Host "Results: $passed passed, $failed failed"
if ($failed -eq 0) { exit 0 } else { exit 1 }
