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

> **SOT: `scripts/` directory.** Full implementations live in scripts. This section provides the essential command patterns so this skill works standalone without reading scripts.

## I.1 Scanner: npm_audit

```bash
npm audit --json | python3 -c "import sys,json; d=json.load(sys.stdin); vs=d.get('vulnerabilities',{}); [print(f'!!{i[\"severity\"].upper()}:{n}') for n,i in vs.items()] if vs else print('L1:CLEAR')"
```

**Full implementation:** `scripts/project-scan.sh` — L1 section

## I.2 Scanner: osv

```bash
# preferred (fast)
osv-scanner --lockfile=package-lock.json

# fallback (API, handles 429 rate limiting)
# POST https://api.osv.dev/v1/query {package:{name,ecosystem:"npm"},version} per dep
# On 429: stop, report L2:PARTIAL
```

**Install:** `brew install osv-scanner` or `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`

**Full implementation:** `scripts/project-scan.sh` — L2 section

## I.3 Scanner: static_list

```bash
# D.2 malicious packages — check if any are installed
for p in plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm; do
  npm list "$p" 2>/dev/null | grep -v empty | grep -q "$p" && echo "!!L3:$p"
done
```

When adding new threats, update D.2.mal[] and D.2.pkg[] simultaneously.

**Full implementation:** `scripts/project-scan.sh` — L3 section, `scripts/env-scan.sh` — Phase 4

## I.4 Scanner: ioc_fs

```bash
# Darwin
ls /Library/Caches/com.apple.act.mond ~/Library/LaunchAgents/com.apple.act.mond.plist 2>/dev/null
pgrep -f com.apple.act.mond

# Linux
ls /tmp/ld.py /tmp/.npm-cache/ 2>/dev/null
pgrep -f "python3 /tmp/ld.py"
crontab -l 2>/dev/null | grep -i "ld.py\|npm-cache"

# Network (all OS) — D.2.c2
lsof -i -nP 2>/dev/null | grep -E '142\.11\.206\.73|sfrclak'
```

IOC paths sourced from D.2 KnownThreats.ioc_fs. Windows: see `scripts/ioc-scan.ps1`.

**Full implementation:** `scripts/ioc-scan.sh`, `scripts/project-scan.sh` — IOC section

## I.4b Scanner: env_cross_scan

```bash
# Find all lockfiles, check for compromised axios versions + malicious packages
find "$ROOT" -name "package-lock.json" -not -path "*/node_modules/*" -maxdepth 5 | while read f; do
  grep -A1 '"node_modules/axios"' "$f" | grep '"version"' | grep -oE '[0-9.]+' | grep -E '1\.14\.1|0\.30\.4'
done
```

env_scan mode only. Default root: `$HOME`.

**Full implementation:** `scripts/env-scan.sh` — Phase 3-4

## I.5 Scanner: lockfile_integrity

```bash
npm ci --dry-run 2>&1 | tail -5        # check for errors
grep -c '"integrity"' package-lock.json  # count hashes
```

**Full implementation:** `scripts/project-scan.sh` — LF section

## I.6 Responder: critical_cleanup

Sequence: net_isolate → kill_proc → rm_persist → rm_npm → reinstall → rescan.

**Every step requires explicit user confirmation before executing.** Key commands:

```bash
echo "127.0.0.1 sfrclak.com" | sudo tee -a /etc/hosts  # block C2
pkill -f com.apple.act.mond                              # darwin
rm -f ~/Library/LaunchAgents/com.apple.act.mond.plist    # darwin persist
rm -rf node_modules package-lock.json && npm install     # clean reinstall
```

**Full implementation:** `scripts/respond.sh --critical`

## I.7 Responder: version_pin

```json
{"overrides":{"<package>":"<safe_version>"}}
```

yarn: `"resolutions"`. Accepts any package name and version.

**Full implementation:** `scripts/respond.sh --high <package> <safe_version>`

## I.8 Responder: cicd_harden

```bash
npm ci --ignore-scripts     # block postinstall
# npm ci already enforces lockfile integrity
```

**Full implementation:** See README.md — CI/CD Integration section

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
