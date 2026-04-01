---
user-invocable: true
name: supply-chain-guard
description: |
  Detect, assess, and respond to npm/yarn supply chain attacks.
  Scans for compromised packages, RAT artifacts, lockfile tampering,
  and suspicious postinstall scripts. Includes 8-gate verification framework.
triggers:
  - supply chain
  - malicious package
  - npm audit
  - compromised dependency
  - postinstall attack
category: security
version: "3.3"
lastUpdate: "2026-04-01"
author: Eris
license: "MIT"
prerequisites: ["python3", "npm or yarn", "osv-scanner(recommended)"]
---

# SCG — Supply Chain Guard v3

```
arch: DDD(domain/application/infrastructure)
enc:  AI-first compact — YAML+abbr, Claude interprets and expands
```

---

# §D — Domain Layer

## D.1 ThreatModel

```yaml
vec: "maintainer_compromise → phantom_dep → postinstall_rat"
kill_chain: [cred_theft, npm_publish, dep_inject, postinstall_exec, rat_drop, c2_beacon, persist]
bypass: "GitHub_Actions_CI/CD_skip — npm_CLI_direct_publish"
```

## D.2 KnownThreats

```yaml
T001_axios:
  d: "2026-03-31"
  pkg: [axios@1.14.1, axios@0.30.4]
  mal: [plain-crypto-js@4.2.1]
  attr: "UNC1069/DPRK-APT(GTIG)"
  tid: [GHSA-fw8c-xr5c-95f9, MAL-2026-2306]
  c2: {dom: sfrclak.com, ip: "142.11.206.73", port: 8000}
  ioc_fs:
    darwin: ["/Library/Caches/com.apple.act.mond", "~/Library/LaunchAgents/com.apple.act.mond.plist"]
    win32:  ["%PROGRAMDATA%\\wt.exe", "%TEMP%\\6202033.vbs", "%TEMP%\\6202033.ps1"]
    linux:  ["/tmp/ld.py", "/tmp/.npm-cache/"]
  persist:
    darwin: "LaunchAgent(com.apple.act.mond)"
    win32:  "schtasks(WindowsTerminalUpdate)"
    linux:  "crontab"
  disguise:
    darwin: "Apple_system_process"
    win32:  "Windows_Terminal(wt.exe)"
  safe: {latest: "1.14.0(exact) or >=1.14.2", legacy: "0.30.3(exact)"}

T002_event_stream:
  d: "2018-11"
  pkg: [event-stream@3.3.6]
  mal: [flatmap-stream]
  vec: "dep_injection→crypto_theft"

T003_typosquat:
  pkg: [crossenv, loadsh, crypto-js-esm]
  vec: "name_similarity→postinstall_exfil"

# ─── Maintenance ───
maintenance:
  principle: "KnownThreats freshness is critical. Do not let it go stale."
  update_trigger: "On new incident reports, update D.2 + I.3 + I.4 simultaneously"
  template: |
    T00N_name:
      d: "YYYY-MM-DD"
      pkg: [compromised@ver]
      mal: [malicious-dep]
      attr: "threat_actor"
      tid: [advisory_ids]
      c2: {dom: "", ip: "", port: 0}
      ioc_fs: {darwin: [], win32: [], linux: []}
      safe: {latest: "safe_ver"}
  staleness: "6 months without update → check latest npm advisories and update or tag as 'verified'"
```

## D.3 SeverityMatrix

```yaml
CRITICAL: "rat_artifact || malicious_pkg_installed"
HIGH:     "compromised_version_in_use"
MEDIUM:   "suspicious_postinstall"
LOW:      "lockfile_drift"
CLEAR:    "all_checks_passed"
```

## D.4 DevilGate(8)

8 gates in 4 categories. Each gate defines a question, check method, and pass criteria.

```yaml
# ── Dependency Poisoning ──
G1_direct_dep:
  question: "Are any direct dependencies at a compromised version?"
  check: "npm list <pkg> + npm audit (I.1)"
  pass: "All packages at safe versions"

G2_transitive_dep:
  question: "Are any transitive (indirect) dependencies compromised?"
  check: "npm list --all <pkg> + OSV.dev (I.2)"
  pass: "No compromised packages in transitive deps"

# ── Runtime Compromise ──
G3_rat_artifacts:
  question: "Are there RAT traces on the filesystem?"
  check: "IOC filesystem scan (I.4) — all OS targets"
  pass: "No artifacts on any platform"

G4_postinstall:
  question: "Are there suspicious postinstall scripts?"
  check: "grep postinstall in node_modules/*/package.json"
  pass: "Only legitimate ones (node-gyp, husky, esbuild, etc.)"

# ── Integrity ──
G5_lockfile:
  question: "Has the lockfile been tampered with?"
  check: "npm ci --dry-run (I.5)"
  pass: "Integrity hash consistency OK"

G6_provenance:
  question: "Is the package from a legitimate source?"
  check: "npm view <pkg> --json to verify publishedBy"
  pass: "From registry.npmjs.org, known maintainer"

# ── Environment ──
G7_network:
  question: "Are there suspicious outbound connections?"
  check: "lsof / netstat + DNS cache (I.4 network)"
  pass: "No connections matching D.2.c2 indicators"

G8_cicd:
  question: "Does CI/CD bypass postinstall and enforce frozen lockfile?"
  check: "Check CI config for --ignore-scripts / --frozen-lockfile"
  pass: "Hardened or N/A (local only)"
```

## D.5 DevilChain(4)

4 perspectives in serial. Each step applies its corresponding gates.

```yaml
chain:
  S1_dependency:  [G1_direct_dep, G2_transitive_dep]
  S2_runtime:     [G3_rat_artifacts, G4_postinstall]
  S3_integrity:   [G5_lockfile, G6_provenance]
  S4_environment: [G7_network, G8_cicd]

flow: "S1→S2→S3→S4 → any concern? fix→re-run entire chain → all PASS→converge"
```

## D.6 DevilLoop

```yaml
rule: "round_N: chain_all → concern? fix→round_N+1 : declare_clear"
max: 3  # escalate_to_user_if_not_converged
low_risk: "reason_annotated→ok_to_defer→converge"
```

## D.7 References

```yaml
refs:
  - {k: ja_zenn,     u: "zenn.dev/gunta/articles/0152eadf05d173",                              n: "JP early report"}
  - {k: elastic,     u: "elastic.co/security-labs/axios-one-rat-to-rule-them-all",              n: "Technical analysis (RAT disasm/C2/timeline)"}
  - {k: sans,        u: "sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan", n: "Enterprise IR procedures"}
  - {k: huntress,    u: "huntress.com/blog/supply-chain-compromise-axios-npm-package",          n: "YARA signatures"}
  - {k: elastic_det, u: "elastic.co/security-labs/axios-supply-chain-compromise-detections",    n: "SIEM detection rules (YARA/osquery/KQL)"}
  - {k: semgrep,     u: "semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/", n: "Static analysis rules / containment"}
  - {k: socradar,    u: "socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/",     n: "CISO guide with IOC/timeline"}
  - {k: wiz,         u: "wiz.io/blog/axios-npm-compromised-in-supply-chain-attack",            n: "Cloud impact / container scanning"}
```

---

# §A — Application Layer

## A.1 UseCases

```yaml
# ─── 2 modes: environment vs project ───
mode:
  env_scan:
    trigger: "'this PC', 'environment check', 'machine-wide'"
    scope: "IOC(fs+net) + find all lockfiles + axios/malicious batch grep"
    skip: [G4_postinstall, G5_lockfile, G6_provenance, G8_cicd]
    flow: "IOC → find package-lock.json -maxdepth 5 → L3 cross-scan → Devil(G1,G2,G3,G7)"
  project_scan:
    trigger: "'this project', 'npm audit', or package.json in cwd"
    scope: "L1+L2+L3 + IOC + lockfile + postinstall + provenance"
    skip: []
    flow: "A.2 ScanPipeline full → Devil Gate(8) all gates"

UC_scan:    "Phase1 → 3-layer detection(L1:audit, L2:osv, L3:static) + ioc_fs + lockfile"
UC_assess:  "Phase2 → SeverityMatrix → CRITICAL/HIGH/MEDIUM/LOW/CLEAR"
UC_respond: "Phase3 → severity-based response(isolate/kill/clean/fix/verify)"
UC_devil:   "Phase4 → Gate(8)×Chain(4)×Loop(max3) → converge_or_escalate"
```

## A.2 ScanPipeline

```
L1(npm_audit) →merge→ L2(osv_api) →merge→ L3(static_list)
                                            ↓
                                     IOC_FS_scan(all_os)
                                            ↓
                                     lockfile_integrity
                                            ↓
                                     assess(SeverityMatrix)
```

## A.3 ResponseProtocol

CRITICAL/HIGH responses involve destructive operations. **Always confirm with the user before executing.**
Present scan results and remediation plan → get user approval → execute.

```yaml
on_CRITICAL:
  confirm: true  # User confirmation required — never auto-execute
  seq: [net_isolate, kill_proc, rm_persist, rm_npm, reinstall, rescan_loop]
on_HIGH:
  confirm: true  # User confirmation required
  seq: [pin_version, override_pkg_json, npm_ci, verify]
on_MEDIUM:
  seq: [manual_review_postinstall, whitelist_or_remove]
on_LOW:
  seq: [npm_ci_resync]
```

## A.4 DevilExecution

```
round(N):
  S1(G1+G2) → S2(G3+G4) → S3(G5+G6) → S4(G7+G8)
  any_fail? → fix → round(N+1)
  all_pass? → "no concerns" → done
  N>=3?     → escalate(user)
```

---

# §I — Infrastructure Layer

## I.1 Scanner: npm_audit

```bash
npm audit --json 2>/dev/null | python3 -c "
import sys,json
try:
 d=json.load(sys.stdin);vs=d.get('vulnerabilities',{})
 if not vs: print('L1:CLEAR')
 else:
  for n,i in vs.items():
   s=i.get('severity','?');va=[v.get('title','?') if isinstance(v,dict) else v for v in i.get('via',[])]
   print(f'!!{s.upper()}:{n}—{va}')
except: print('L1:ERR—manual_check')
"
```

## I.2 Scanner: osv

Prefer osv-scanner CLI (Google official). Falls back to API if not installed.

```bash
# ─── preferred: osv-scanner CLI (fast, scans all deps at once) ───
# install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest
#   or: brew install osv-scanner
osv-scanner --lockfile=package-lock.json 2>/dev/null
_OSV_EXIT=$?
if [ $_OSV_EXIT -eq 127 ]; then
  echo "L2:osv-scanner not found — fallback to API"
fi
```

```bash
# ─── fallback: OSV.dev API (slow for 100+ deps, not recommended for CI) ───
python3 -c "
import json,urllib.request as ur
lk=json.load(open('package-lock.json'))
ps=lk.get('packages',lk.get('dependencies',{}));h=[]
for p,i in ps.items():
 n=i.get('name')or p.replace('node_modules/','');v=i.get('version','')
 if not n or not v:continue
 b=json.dumps({'package':{'name':n,'ecosystem':'npm'},'version':v}).encode()
 try:
  r=json.loads(ur.urlopen(ur.Request('https://api.osv.dev/v1/query',data=b,headers={'Content-Type':'application/json'}),timeout=5).read())
  if r.get('vulns'):h.append(f'{n}@{v}:{[x[\"id\"] for x in r[\"vulns\"][:3]]}')
 except:pass
print('L2:HITS:\\n'+' \\n'.join(h) if h else 'L2:CLEAR')
" 2>/dev/null
```

## I.3 Scanner: static_list

Source of truth is D.2 KnownThreats. When adding here, also update D.2.mal[] and D.2.pkg[].

```bash
# D.2 KnownThreats.mal[] + T003_typosquat.pkg[] materialized
_M=(plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm)
for p in "${_M[@]}";do npm list "$p" 2>/dev/null|grep -v empty&&echo "!!L3:$p";done
```

## I.4 Scanner: ioc_fs

IOC paths sourced from D.2 KnownThreats.ioc_fs. Auto-detects OS and runs platform-specific checks.

```bash
# — Auto-detect OS, run platform-specific checks —
_OS=$(uname -s)
echo "[IOC:fs] scanning $_OS..."

case "$_OS" in
  Darwin)
    ls /Library/Caches/com.apple.act.mond 2>/dev/null&&echo "!!C:darwin_rat_bin"
    ls ~/Library/LaunchAgents/com.apple.act.mond.plist 2>/dev/null&&echo "!!C:darwin_la"
    pgrep -f com.apple.act.mond 2>/dev/null&&echo "!!C:darwin_proc"
    ;;
  Linux)
    ls /tmp/ld.py 2>/dev/null&&echo "!!C:linux_rat"
    ls /tmp/.npm-cache/ 2>/dev/null&&echo "!!S:linux_stage"
    pgrep -f "python3 /tmp/ld.py" 2>/dev/null&&echo "!!C:linux_proc"
    crontab -l 2>/dev/null|grep -i "ld.py\|npm-cache"&&echo "!!C:linux_cron"
    ;;
esac

# network (all OS) — see D.2.c2
lsof -i -nP 2>/dev/null|grep -E '142\.11\.206\.73|sfrclak'&&echo "!!C:c2_active"
```

```powershell
# — win32 (PowerShell) — Windows only —
$ioc = @("$env:PROGRAMDATA\wt.exe","$env:TEMP\6202033.vbs","$env:TEMP\6202033.ps1")
foreach ($f in $ioc) { if (Test-Path $f) { Write-Host "!!C:win_$($f|Split-Path -Leaf)" } }
Get-Process wt -EA 0 | Where-Object {$_.Path -like "*ProgramData*"} | ForEach-Object { Write-Host "!!C:win_proc" }
schtasks /query /TN WindowsTerminalUpdate 2>$null && Write-Host "!!C:win_schtask"
netstat -an | Select-String "142.11.206.73" | ForEach-Object { Write-Host "!!C:c2_active" }
```

## I.4b Scanner: env_cross_scan

env_scan mode only. Cross-project batch detection of compromised packages.

```bash
# ─── env_scan: cross-project lockfile scan ───
_ROOT="${1:-$HOME/Develop}"
echo "=== env_cross_scan: $_ROOT ==="

# D.2 compromised versions (SOT: KnownThreats.pkg[])
_COMPROMISED='1\.14\.1\|0\.30\.4'
# D.2 malicious packages (SOT: KnownThreats.mal[] + T003.pkg[])
_MALICIOUS=(plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm)

# axios version check
find "$_ROOT" -name "package-lock.json" -not -path "*/node_modules/*" -maxdepth 5 2>/dev/null | while read f; do
  hit=$(grep -A2 '"axios"' "$f" 2>/dev/null | grep '"version"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | grep -E "$_COMPROMISED")
  [ -n "$hit" ] && echo "!!HIGH: $(dirname $f) — axios@$hit"
done

# malicious package check
for mal in "${_MALICIOUS[@]}"; do
  find "$_ROOT" -name "package-lock.json" -not -path "*/node_modules/*" -maxdepth 5 -exec grep -l "\"$mal\"" {} \; 2>/dev/null | while read f; do
    echo "!!CRITICAL: $mal in $(dirname $f)"
  done
done

echo "env_cross_scan: done"
```

## I.5 Scanner: lockfile_integrity

```bash
npm ci --dry-run 2>&1|tail -5
grep -c '"integrity"' package-lock.json 2>/dev/null
```

## I.6 Responder: critical_cleanup

Executes A.3.on_CRITICAL. IOC paths from D.2 KnownThreats, steps match A.3.seq.
**These commands are destructive. Always get user confirmation before executing.**

```bash
# ⚠️ DESTRUCTIVE — CONFIRM_BEFORE_EXEC
# S1:net_isolate — block D.2.c2.dom
echo "127.0.0.1 sfrclak.com"|sudo tee -a /etc/hosts
# S2:kill — darwin
pkill -f com.apple.act.mond 2>/dev/null
# S2:kill — linux
pkill -f "python3 /tmp/ld.py" 2>/dev/null
# S2:kill — win32(pwsh): Stop-Process -Name wt -Force -EA 0
# S3:rm_persist — darwin
launchctl remove com.apple.act.mond 2>/dev/null
rm -f ~/Library/LaunchAgents/com.apple.act.mond.plist /Library/Caches/com.apple.act.mond
# S3:rm_persist — linux
crontab -l|grep -v "ld.py\|npm-cache"|crontab -;rm -f /tmp/ld.py /tmp/.npm-cache/
# S3:rm_persist — win32(pwsh):
#   schtasks /Delete /TN WindowsTerminalUpdate /F
#   ri "$env:PROGRAMDATA\wt.exe","$env:TEMP\6202033.vbs","$env:TEMP\6202033.ps1" -Force
# S4:npm_clean
rm -rf node_modules package-lock.json;npm cache clean --force
# S5:reinstall
npm install&&npm ci
# S6:rescan → rerun A.2 pipeline, expect CLEAR
```

## I.7 Responder: version_pin

```json
{"overrides":{"axios":"1.14.0"}}
```
yarn: `"resolutions":{"axios":"1.14.0"}`

## I.8 Responder: cicd_harden

```bash
npm ci --ignore-scripts          # postinstall bypass
npm ci --frozen-lockfile          # lockfile strict (npm9+)
yarn install --frozen-lockfile    # yarn equiv
```

---

# §O — Output Format

```
SCG ──────────────────────────────────
[L1:audit]    CLEAR|!!sev
[L2:osv]      CLEAR|!!vuln-ids
[L3:static]   CLEAR|!!pkg
[IOC:fs]      CLEAR|!!C:artifact
[IOC:net]     CLEAR|!!C:c2
[LF:integ]    CLEAR|!!drift
─── Devil Gate(8) ────────────────────
G1:direct_dep  G2:transitive  G3:rat_fs
G4:postinstall G5:lockfile    G6:provenance
G7:network     G8:cicd
─── Devil Chain(R.N) ─────────────────
S1:dependency → S2:runtime → S3:integrity → S4:environment
─── Loop ─────────────────────────────
R.N → converge|continue
[VERDICT] CLEAR|HIGH|CRITICAL
───────────────────────────────────────
```
