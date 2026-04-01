# Supply Chain Guard (SCG)

> **Detect, assess, and respond to npm/yarn supply chain attacks.**

A Claude Code skill and standalone toolkit for defending npm/yarn projects against supply chain compromises. Built with real-world incident response in mind, including the [axios@1.14.1 RAT incident (2026-03-31)](https://elastic.co/security-labs/axios-one-rat-to-rule-them-all).

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [How SCG Differs from Existing Tools](#how-scg-differs-from-existing-tools)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [Threat Intelligence](#threat-intelligence)
- [Devil Gate Framework](#devil-gate-framework)
- [Standalone Scripts](#standalone-scripts)
- [CI/CD Integration](#cicd-integration)
- [Response Playbook](#response-playbook)
- [IOC Reference](#ioc-reference)
- [Disclaimer](#disclaimer)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [Integrity Verification](#integrity-verification)
- [License](#license)

---

## Why This Exists

On March 31, 2026, the widely-used `axios` npm package (v1.14.1 and v0.30.4) was compromised through a maintainer account takeover attributed to **UNC1069/DPRK-APT** (per Google Threat Intelligence Group). The attack injected a phantom dependency (`plain-crypto-js@4.2.1`) that deployed a cross-platform RAT via `postinstall` scripts, disguised as legitimate system processes.

**Supply Chain Guard (SCG)** was built during the incident to provide:

1. **Immediate detection** — Is my machine or project affected right now?
2. **Structured assessment** — How severe is it? What's the blast radius?
3. **Guided response** — Step-by-step remediation with safety confirmations
4. **Ongoing defense** — An 8-gate verification framework to prevent recurrence

---

## How SCG Differs from Existing Tools

SCG is not a replacement for existing security tools. It combines multiple detection layers with a structured verification framework and guided remediation — designed for use **during active incidents** or as a periodic check alongside your existing tooling.

| Tool | What it does | How SCG relates |
|------|-------------|-----------------|
| **`npm audit`** | Checks registry for known vulnerabilities | SCG includes npm audit as its L1 layer, then adds IOC filesystem/network scanning, malicious package detection, and a structured response workflow on top |
| **`osv-scanner`** | Scans lockfiles against Google's OSV database | SCG includes OSV as its L2 layer. osv-scanner doesn't check for RAT artifacts on your filesystem or active C2 connections |
| **Snyk / Socket.dev** | Commercial SaaS with real-time monitoring, PR checks, license scanning | SCG is free, local-first, no account required, no data sent to third parties. Designed for immediate incident response rather than ongoing monitoring |
| **Manual IR** | Ad-hoc investigation with custom scripts | SCG provides a repeatable framework (8 verification gates, convergence loop, severity matrix) instead of one-off checklists that vary per incident |

**When to use SCG:**
- A supply chain incident just dropped and you need to check your machines and projects **right now**
- You want a structured, repeatable process for verifying that a compromise has been fully addressed
- You need a lightweight check that runs locally without SaaS dependencies

**When to use something else:**
- You need continuous real-time monitoring → Snyk, Socket.dev
- You need license compliance scanning → Snyk, FOSSA
- You need coverage beyond npm/yarn → osv-scanner (supports pip, cargo, go, etc.)

---

## Architecture

SCG follows a **Domain-Driven Design (DDD)** architecture with three layers:

```
+-----------------------------------------------------+
|  Domain Layer                                        |
|  Threat models, known threats DB, severity matrix,   |
|  Devil Gate definitions                              |
+-----------------------------------------------------+
|  Application Layer                                   |
|  Use cases, scan pipeline, response protocols,       |
|  Devil execution loop                                |
+-----------------------------------------------------+
|  Infrastructure Layer                                |
|  Scanner scripts (npm audit, OSV, static list,       |
|  IOC filesystem, network, lockfile integrity)        |
+-----------------------------------------------------+
```

### Scan Pipeline

```
L1(npm audit) ──┐
                ├─→ merge ─→ L2(OSV.dev) ──┐
                │                           ├─→ merge ─→ L3(static list)
                │                           │                    │
                │                           │             IOC filesystem scan
                │                           │                    │
                │                           │             lockfile integrity
                │                           │                    │
                │                           │             assess(SeverityMatrix)
                │                           │                    │
                └───────────────────────────┘              ┌─────┴─────┐
                                                           │  VERDICT  │
                                                           └───────────┘
```

---

## Quick Start

### As a Claude Code Skill

Copy `SKILL.md` into your Claude Code skills directory:

```bash
# Global (all projects)
cp SKILL.md ~/.claude/skills/supply-chain-guard.md

# Or project-specific
mkdir -p .claude/skills
cp SKILL.md .claude/skills/supply-chain-guard.md
```

Then invoke in Claude Code:

```
> /supply-chain-guard
> "Check this project for supply chain issues"
> "Is my machine affected by the axios compromise?"
```

### As Standalone Scripts

```bash
# Environment-wide scan (IOC + all projects)  [READ-ONLY]
./scripts/env-scan.sh

# Project-specific scan (requires package.json in cwd)  [READ-ONLY]
./scripts/project-scan.sh

# IOC-only scan (filesystem + network artifacts)  [READ-ONLY]
./scripts/ioc-scan.sh

# Remediation (interactive, every action requires confirmation)
./scripts/respond.sh --critical              # Full RAT cleanup
./scripts/respond.sh --high axios 1.14.0     # Pin to safe version
```

> **Safety design:** All scan scripts are strictly read-only — they never modify, delete, or install anything. The remediation script (`respond.sh`) is the only script that performs destructive operations, and **every single action requires explicit `[y/N]` confirmation** with a default of NO.

---

## Scan Modes

### Environment Scan (`env_scan`)

Scans your entire development machine for compromise indicators.

| Check | Description |
|-------|-------------|
| **IOC: Filesystem** | RAT binaries, persistence mechanisms, staging files |
| **IOC: Network** | Active C2 connections (IP + domain) |
| **IOC: Process** | Running malicious processes |
| **Cross-project** | All `package-lock.json` files scanned for compromised versions |
| **Malicious packages** | Known malicious package names in any lockfile |

**Triggers:** "this PC", "environment check", "machine-wide"

### Project Scan (`project_scan`)

Deep scan of a single npm/yarn project.

| Layer | Scanner | Description |
|-------|---------|-------------|
| **L1** | `npm audit` | Known vulnerabilities via npm registry |
| **L2** | `osv-scanner` / OSV.dev API | Google's Open Source Vulnerability database |
| **L3** | Static list | Hardcoded known-malicious package check |
| **IOC** | Filesystem + Network | RAT artifact detection |
| **LF** | Lockfile integrity | `npm ci --dry-run` + integrity hash count |

**Triggers:** "this project", "npm audit", or `package.json` present in cwd

---

## Threat Intelligence

### Known Threats Database

| ID | Date | Package | Threat Actor | Vector |
|----|------|---------|-------------|--------|
| **T001** | 2026-03-31 | `axios@1.14.1`, `axios@0.30.4` | UNC1069/DPRK-APT | Maintainer compromise → phantom dep → RAT |
| **T002** | 2018-11 | `event-stream@3.3.6` | Unknown | Dependency injection → crypto theft |
| **T003** | Ongoing | `crossenv`, `loadsh`, `crypto-js-esm` | Various | Typosquatting → postinstall exfiltration |

### T001 Kill Chain (axios RAT)

```
Credential theft → npm publish (bypass CI) → Inject phantom dep (plain-crypto-js)
    → postinstall exec → RAT drop → C2 beacon (sfrclak.com:8000) → Persist
```

### Safe Versions

| Package | Safe | Compromised |
|---------|------|-------------|
| axios (latest) | `1.14.0` (exact) or `>=1.14.2` | `1.14.1` |
| axios (legacy) | `0.30.3` (exact) | `0.30.4` |

### Advisory IDs

- [GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9)
- [MAL-2026-2306](https://osv.dev/vulnerability/MAL-2026-2306)

---

## Devil Gate Framework

SCG uses an **8-gate verification framework** organized into 4 categories, executed as a serial chain with convergence loop.

### Gates

| # | Gate | Category | Question |
|---|------|----------|----------|
| G1 | Direct Dependency | Dependency Poisoning | Are any direct dependencies at a compromised version? |
| G2 | Transitive Dependency | Dependency Poisoning | Are any transitive (indirect) dependencies compromised? |
| G3 | RAT Artifacts | Runtime Compromise | Are there RAT traces on the filesystem? |
| G4 | Postinstall Scripts | Runtime Compromise | Are there suspicious `postinstall` scripts? |
| G5 | Lockfile Integrity | Integrity | Has the lockfile been tampered with? |
| G6 | Provenance | Integrity | Is the package from a legitimate source/maintainer? |
| G7 | Network | Environment | Are there suspicious outbound connections? |
| G8 | CI/CD Hardening | Environment | Does CI/CD bypass postinstall / enforce frozen lockfile? |

### Chain Execution

```
S1: Dependency (G1+G2)
  → S2: Runtime (G3+G4)
    → S3: Integrity (G5+G6)
      → S4: Environment (G7+G8)
        → Any fail? → Fix → Re-run entire chain
        → All pass? → "No concerns" → Done
        → 3 rounds without convergence? → Escalate to user
```

### Severity Matrix

| Level | Condition | Action |
|-------|-----------|--------|
| **CRITICAL** | RAT artifact found OR malicious package installed | Network isolate → Kill process → Remove persistence → Reinstall |
| **HIGH** | Compromised version in use | Pin safe version → Override → `npm ci` → Verify |
| **MEDIUM** | Suspicious postinstall script | Manual review → Whitelist or remove |
| **LOW** | Lockfile drift | `npm ci` resync |
| **CLEAR** | All checks passed | No action needed |

> **Safety:** CRITICAL/HIGH responses involve destructive operations. SCG always presents findings and asks for explicit user confirmation before executing remediation.

---

## Standalone Scripts

### `scripts/env-scan.sh`

Full environment scan. Checks IOC artifacts, scans all lockfiles under `$HOME` (configurable), and reports compromised packages.

```bash
./scripts/env-scan.sh [scan_root_dir]
# Default: $HOME
```

### `scripts/project-scan.sh`

Project-level scan. Run from a directory containing `package.json`.

```bash
cd my-project
/path/to/scripts/project-scan.sh
```

### `scripts/ioc-scan.sh`

IOC-only scan. Checks filesystem artifacts, running processes, and network connections against known C2 indicators. Cross-platform (macOS/Linux/Windows via PowerShell).

```bash
./scripts/ioc-scan.sh
```

### `scripts/respond.sh`

Interactive remediation. **Every destructive action requires `[y/N]` confirmation (default: NO).**

```bash
# CRITICAL: Full RAT cleanup (kill → remove → reinstall)
./scripts/respond.sh --critical

# HIGH: Pin compromised package to safe version
./scripts/respond.sh --high axios 1.14.0
./scripts/respond.sh --high event-stream 3.3.5
```

Steps in `--critical` mode:
1. Network isolate (block C2 domain via `/etc/hosts`)
2. Kill RAT processes
3. Remove persistence (LaunchAgents / crontab / scheduled tasks)
4. Delete `node_modules` and lockfile, clear npm cache
5. Reinstall dependencies
6. Prompt for verification scan

Each step checks whether action is actually needed (e.g., skips "kill" if no RAT process is running) and shows exactly what will be executed before asking for confirmation.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Supply Chain Guard
on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'yarn.lock'

jobs:
  scg-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies (hardened)
        run: npm ci --ignore-scripts

      - name: Run SCG project scan
        run: |
          chmod +x ./scripts/project-scan.sh
          ./scripts/project-scan.sh

      - name: Run IOC scan
        run: |
          chmod +x ./scripts/ioc-scan.sh
          ./scripts/ioc-scan.sh
```

### Hardening Recommendations

```bash
# Always use in CI:
npm ci --ignore-scripts          # Block postinstall execution
# npm ci already enforces lockfile integrity by design (errors on mismatch)

# Yarn equivalent:
yarn install --frozen-lockfile --ignore-scripts
```

> **Pin actions by SHA, not tag.** The example above uses `actions/checkout@v4` for readability, but tags can be moved. In production, pin to a full commit SHA to prevent action supply chain attacks:
> ```yaml
> - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
> - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af  # v4.1.0
> ```

---

## Response Playbook

### If CRITICAL (RAT detected)

> **Do not panic.** Follow these steps in order. Each step requires your explicit confirmation.

1. **Network Isolate** — Block C2 domain via `/etc/hosts`
2. **Kill Processes** — Terminate RAT processes (`com.apple.act.mond`, `ld.py`, `wt.exe`)
3. **Remove Persistence** — Delete LaunchAgents, crontabs, scheduled tasks
4. **Clean npm** — Remove `node_modules` and `package-lock.json`, clear npm cache
5. **Reinstall** — Fresh `npm install && npm ci`
6. **Rescan** — Re-run full pipeline, expect CLEAR

### If HIGH (compromised version installed)

1. **Pin safe version** using respond.sh:
   ```bash
   ./scripts/respond.sh --high axios 1.14.0
   ```
   This adds `overrides` (npm) or `resolutions` (yarn) to package.json, reinstalls, and prompts for verification.

2. **Or manually** in `package.json`:
   ```json
   { "overrides": { "axios": "1.14.0" } }
   ```
   Yarn: `{ "resolutions": { "axios": "1.14.0" } }`

3. **Reinstall**: `npm ci`
4. **Verify**: Re-run scan

---

## IOC Reference

### Filesystem Artifacts

| Platform | Path | Type |
|----------|------|------|
| macOS | `/Library/Caches/com.apple.act.mond` | RAT binary |
| macOS | `~/Library/LaunchAgents/com.apple.act.mond.plist` | Persistence |
| Windows | `%PROGRAMDATA%\wt.exe` | RAT binary (disguised as Windows Terminal) |
| Windows | `%TEMP%\6202033.vbs` | Dropper |
| Windows | `%TEMP%\6202033.ps1` | Dropper |
| Linux | `/tmp/ld.py` | RAT script |
| Linux | `/tmp/.npm-cache/` | Staging directory |

### Persistence Mechanisms

| Platform | Mechanism | Identifier |
|----------|-----------|------------|
| macOS | LaunchAgent | `com.apple.act.mond` |
| Windows | Scheduled Task | `WindowsTerminalUpdate` |
| Linux | Crontab entry | References `ld.py` or `.npm-cache` |

### Network Indicators

| Type | Value |
|------|-------|
| C2 Domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 Port | `8000` |

### Disguise Techniques

| Platform | Disguised As |
|----------|-------------|
| macOS | Apple system process (`com.apple.act.mond`) |
| Windows | Windows Terminal (`wt.exe` in ProgramData) |

---

## Output Format

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

---

## References

| Source | Description |
|--------|-------------|
| [Zenn (JP)](https://zenn.dev/gunta/articles/0152eadf05d173) | Japanese early report |
| [Elastic Security Labs](https://elastic.co/security-labs/axios-one-rat-to-rule-them-all) | Technical analysis (RAT disassembly, C2 protocol, timeline) |
| [SANS](https://sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan) | Enterprise IR procedures |
| [Huntress](https://huntress.com/blog/supply-chain-compromise-axios-npm-package) | YARA signatures |
| [Elastic Detections](https://elastic.co/security-labs/axios-supply-chain-compromise-detections) | SIEM detection rules (YARA/osquery/KQL) |
| [Semgrep](https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/) | Static analysis rules, containment guide |
| [SOCRadar](https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/) | CISO guide with IOC timeline |
| [Wiz](https://wiz.io/blog/axios-npm-compromised-in-supply-chain-attack) | Cloud impact analysis, container scanning |

---

## Disclaimer

SCG is a detection tool, not a security guarantee. Being upfront about what it can and cannot do is part of the design.

**This software is provided "as-is" without warranty of any kind.** By using Supply Chain Guard, you acknowledge and agree to the following:

- **Not a substitute for professional security.** SCG is a supplementary detection tool, not a comprehensive security solution. It does not replace professional incident response, endpoint detection and response (EDR) software, or security audits.
- **No guarantee of detection.** A `CLEAR` verdict means no matches were found against the tool's known threat patterns. **It does not mean your system or project is free from compromise.** Novel, unknown, or modified attacks may not be detected.
- **No guarantee of remediation.** The remediation steps provided (`respond.sh`) address known indicators of specific threats. They may not fully remove all traces of a sophisticated compromise. If you suspect active compromise, engage a professional incident response team.
- **Use at your own risk.** The authors are not liable for any damages, data loss, or security incidents arising from the use or inability to use this tool. This includes but is not limited to: false negatives (missed detections), false positives (incorrect detections), or unintended consequences of running remediation scripts.
- **Not legal or compliance advice.** This tool does not satisfy regulatory, compliance, or legal requirements for security scanning. Consult appropriate professionals for compliance needs.

---

## Limitations

Understanding what SCG **cannot** do is as important as knowing what it can.

### Detection Boundaries

| What SCG checks | What SCG does NOT check |
|-----------------|------------------------|
| Known compromised package versions (hardcoded DB) | Zero-day supply chain attacks with no public advisory |
| Known malicious package names | Typosquats not yet in the static list |
| Specific IOC file paths for known threats | Arbitrary malware dropped to non-standard paths |
| Specific C2 IP addresses and domains | C2 infrastructure that has been rotated or changed |
| `postinstall` scripts in direct dependencies | Obfuscated malicious code within legitimate-looking scripts |

### Threat Database Freshness

The Known Threats database (`D.2` in SKILL.md) is **manually maintained**. It is not connected to any live threat feed. There is inherent latency between a new supply chain incident being discovered and this database being updated.

- **Last updated:** 2026-04-01
- **Coverage:** 3 threat families (T001-T003)

Always cross-reference with live sources such as [npm advisories](https://github.com/advisories), [OSV.dev](https://osv.dev/), and vendor security blogs listed in the [References](#references) section.

### False Positive Risk

The following IOC paths may, in rare cases, conflict with legitimate software:

| IOC Path | Potential False Positive |
|----------|------------------------|
| `/tmp/.npm-cache/` | Legitimate npm caching in non-standard configurations |
| `/tmp/ld.py` | Unrelated Python scripts with the same filename |
| Process name `wt.exe` | Legitimate Windows Terminal if located in ProgramData |

**Always verify IOC findings before running remediation.** The `ioc-scan.sh` script reports findings for human review — it does not take any action. The `respond.sh` script requires explicit confirmation for every destructive action (default: NO) precisely because of this risk.

### Network Scanning Limitations

- `lsof`-based network checks only detect **currently active** connections. A C2 beacon that connects intermittently may not be active at scan time.
- DNS cache checks are best-effort and OS-dependent. Cleared caches will not show historical connections.
- Encrypted or tunneled C2 traffic cannot be detected by port/IP matching alone.

### Scope

- **npm/yarn only.** Does not cover pip, cargo, go modules, or other package ecosystems.
- **Known threats only.** This is a pattern-matching tool, not a behavioral analysis engine.
- **Point-in-time scan.** Results reflect the state at the moment of execution. Continuous monitoring requires repeated execution or integration with CI/CD.

---

## Contributing

This repository does not accept pull requests. If you discover a new supply chain threat or have suggestions, please [open an Issue](https://github.com/eris-ths/supply-chain-guard/issues) with advisory references and details.

---

## Integrity Verification

Verify that your copy of SCG has not been tampered with. Compare these SHA-256 checksums against your local files:

<!-- CHECKSUMS-START -->
```
67ac6216cbe18fdf7050fd267bce4157c016e5c60cd4f84f63b8cf71e80ae3b9  scripts/env-scan.sh
cbf260276b8cf028ff582579c1edc8a8890078261e69c4b616070b0c720e7b08  scripts/project-scan.sh
0c084824c180bc8cfac7daf596677eda7d5d1b0c5888f7600bf7272d22678b72  scripts/ioc-scan.sh
6b7641f9b3dd252ccce49af93a811b04689cd021ff7a302878a39e0d607598f6  scripts/ioc-scan.ps1
72a067ff9f608b4fcc04c379a779b7be182165a833df36fe84420d7ab8150438  scripts/respond.sh
2af237bc7ffd2080d1eb53636abd088b7ed2e927ccbed201f675c2c165044c29  SKILL.md
```
<!-- CHECKSUMS-END -->

To verify:

```bash
shasum -a 256 scripts/*.sh scripts/*.ps1 SKILL.md
```

> **Note:** These checksums correspond to the latest release. If you have modified any files locally, the checksums will differ. When SCG is updated, this section is updated alongside the code changes.

---

## License

[MIT](LICENSE)

---

**Built by [Eris](https://github.com/eris-ths)** — because your dependencies shouldn't be someone else's attack surface.
