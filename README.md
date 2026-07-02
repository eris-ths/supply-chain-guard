# Supply Chain Guard (SCG)

> **An incident-response toolkit for npm/yarn and Python (pip/poetry/uv) supply chain attacks — free, local, dependency-free.**

SCG is **not** a scanning engine that competes with commercial tools on coverage. It is a Claude Code skill and standalone shell toolkit that does three things well: **(1)** gives you a fast, repeatable *first response* when a specific incident drops ("is my machine affected right now?"), **(2)** orchestrates existing OSS scanners (`npm audit`, `osv-scanner`, `pip-audit`) into one structured pass, and **(3)** documents hard-won *design-hygiene* lessons — especially for AI development environments — that generic scanners don't cover.

It was built and hardened during real incidents, including:

- **[axios@1.14.1 RAT incident (2026-03-31)](https://elastic.co/security-labs/axios-one-rat-to-rule-them-all)** — npm maintainer account takeover (UNC1069/DPRK-APT) injecting a phantom dependency RAT
- **[Starlette BadHost (CVE-2026-48710, 2026-05-22)](https://cryptobriefing.com/starlette-badhost-vulnerability-ai-agents/)** — Python HTTP framework Host header path injection → SSRF/RCE, affecting FastAPI, vLLM, LiteLLM, and the broader AI agent ecosystem

## What's new in v4 (2026-05-27)

- **Python supply chain scan** — `scripts/project-scan-py.sh` with pip-audit / osv-scanner / CVE-flagged version detection
- **CVE-flagged version layer (L3-CVE)** — track known vulnerable versions of legitimate packages with strict semver-spec evaluation (BadHost CVE-2026-48710 included out of the box)
- **Design hygiene guideline** — stdio-first MCP transport, version pin discipline, GCP default compute SA editor hardening (see SKILL.md §D.7 DesignHygiene)
- **Guild-CLI Devil lense integration** — invoke SCG as a Devil lense from guild-cli workflows (see "Guild-CLI Devil Integration" below)

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [How SCG Differs from Existing Tools](#how-scg-differs-from-existing-tools)
- [What SCG Is (and Isn't)](#what-scg-is-and-isnt)
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

## What SCG Is (and Isn't)

We'd rather be honest about the boundaries than oversell. SCG is three things:

1. **An incident-response playbook, as code.** When a named incident drops (axios RAT, Shai-Hulud, a fresh CVE), SCG turns "am I affected, and if so what do I do?" into an executable checklist — 8 verification gates, a severity matrix, and a remediation script where *every* destructive action needs explicit `[y/N]` confirmation. This is its primary value: the fast, structured *first response* that commercial monitoring tools aren't shaped for.

2. **An orchestrator of existing OSS scanners.** The L1/L2 layers wrap `npm audit` / `pip-audit` / `osv-scanner`. Most of the raw detection power is borrowed; SCG's contribution is bundling them into one pass, adding filesystem/IOC checks the registry tools don't do, and making the output readable and actionable.

3. **Documentation of real design-hygiene lessons** (SKILL.md §D.7) — things we actually hit or investigated: MCP transport choice, GCP default-SA hardening, install-time execution vectors, and threats that target AI dev tooling (Shai-Hulud reading `.claude/settings.json`, SANDWORM_MODE poisoning MCP configs). This niche — supply-chain hygiene for AI-assisted development — is where SCG is genuinely differentiated.

### What SCG is deliberately NOT

- **Not a coverage competitor.** The threat database (`SKILL.md` D.2, the L3 static lists) is **hand-maintained** — it holds the incidents we've read about, not the tens of thousands of malicious packages a live commercial feed tracks. A hand-curated list *cannot* keep pace with the real rate of new threats, and we don't pretend it does.
- **Not a behavioral analysis engine.** SCG matches known patterns. Obfuscated payloads and true zero-days with no public advisory are out of scope by construction.
- **Not continuous monitoring.** It's a point-in-time check you run during an incident or as a periodic sweep — not a service watching your dependency graph.

### Where SCG is headed

Because a hand-curated database can't win on coverage, we're intentionally investing where SCG is *hard to replace* rather than where it will always lose:

- **Deeper incident-response playbooks** (#1) — better first-response ergonomics, more incident templates.
- **AI-development-environment hygiene** (#3) — detection and guidance for threats aimed at Claude Code / Cursor / MCP servers and similar tooling, which commercial supply-chain scanners largely don't address.

The static threat DB (#2) will keep getting updated when notable incidents land, but it is explicitly **not** the direction we're trying to compete on.

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

The same 5-layer pipeline applies to both ecosystems with ecosystem-specific scanners at each layer:

```
L1 ──→ L2 ──→ L3 ──→ IOC ──→ LF ──→ assess(SeverityMatrix) ──→ VERDICT
```

| Layer | npm/yarn (`project-scan.sh`) | Python (`project-scan-py.sh`) |
|-------|------------------------------|-------------------------------|
| **L1** | `npm audit` | `pip-audit` |
| **L2** | `osv-scanner` / OSV.dev API | `osv-scanner` |
| **L3** | Static list (malicious + typosquat) | Static list (malicious / typosquat + CVE-flagged versions) |
| **IOC** | Filesystem + Network artifacts | Filesystem + Process artifacts (Python-flavored) |
| **LF** | `npm ci --dry-run` + integrity count | Lockfile integrity (uv.lock / poetry.lock / requirements*.txt) |

Both pipelines feed the same SeverityMatrix and Devil Gate Framework.

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

# npm/yarn project scan (requires package.json in cwd)  [READ-ONLY]
./scripts/project-scan.sh

# Python project scan (requires pyproject.toml / requirements*.txt / poetry.lock / uv.lock in cwd)  [READ-ONLY, added in v4]
./scripts/project-scan-py.sh

# IOC-only scan (filesystem + network artifacts)  [READ-ONLY]
./scripts/ioc-scan.sh

# Remediation (interactive, every action requires confirmation)
./scripts/respond.sh --critical              # Full RAT cleanup (npm + Python)
./scripts/respond.sh --high axios 1.14.0     # Pin npm package to safe version
./scripts/respond.sh --high urllib3 2.7.0    # Pin Python package (auto-detects pip/poetry/uv)
```

> **Python remediation is conservative by design.** For npm, `--high` applies the
> override automatically. For Python it *guides*: it detects your manager
> (pip/poetry/uv), prints the exact pin command, and applies only the safe step —
> lockfile-mutating and venv-rebuild commands are shown for you to run. This avoids
> a false positive triggering a collateral force-reinstall across the fragmented
> Python packaging ecosystem.

For a polyglot repository (npm + Python), run both project scanners sequentially from the relevant subdirectories.

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

### Project Scan — npm/yarn (`project_scan`)

Deep scan of a single npm/yarn project. Run from a directory containing `package.json`.

| Layer | Scanner | Description |
|-------|---------|-------------|
| **L1** | `npm audit` | Known vulnerabilities via npm registry |
| **L2** | `osv-scanner` / OSV.dev API | Google's Open Source Vulnerability database |
| **L3** | Static list | Hardcoded known-malicious package check |
| **IOC** | Filesystem + Network | RAT artifact detection |
| **LF** | Lockfile integrity | `npm ci --dry-run` + integrity hash count |

**Triggers:** "this project", "npm audit", or `package.json` present in cwd

### Project Scan — Python (`project_scan_py`, added in v4)

Deep scan of a single Python project. Run from a directory containing `pyproject.toml`, `requirements*.txt`, `poetry.lock`, or `uv.lock`.

| Layer | Scanner | Description |
|-------|---------|-------------|
| **L1** | `pip-audit` | Known vulnerabilities via PyPI Advisory DB (optional — SKIP if not installed; `pip install pip-audit` recommended) |
| **L2** | `osv-scanner` | Google's Open Source Vulnerability database against `uv.lock` / `poetry.lock` / `requirements*.txt` (optional — SKIP if not installed) |
| **L3-MAL** | Static malicious list (`_L3_LIST`) | Known hijacked / typosquat package names. Matches PEP 621 list, Poetry inline, and requirements-style declarations (see [PR #4](https://github.com/eris-ths/supply-chain-guard/pull/4)). FAIL on hit |
| **L3-CVE** | Static CVE-flagged version list (`_L3_CVE_LIST`) | Known vulnerable versions of legitimate packages (e.g., `starlette<1.0.1` for [BadHost CVE-2026-48710](https://cryptobriefing.com/starlette-badhost-vulnerability-ai-agents/)). Strict semver-spec evaluation via Python's `packaging` library. FAIL on confirmed match. Warns if a package is declared but no lockfile is present (cannot evaluate version) |
| **IOC** | Filesystem + Process | Python-flavored artifact check (rogue scripts, suspicious processes) |
| **LF** | Lockfile integrity | Verifies `uv.lock` / `poetry.lock` / `requirements*.txt` parses cleanly and contains pinned versions |

**Triggers:** "this project" with Python files present, or any of `pyproject.toml` / `requirements*.txt` / `poetry.lock` / `uv.lock` in cwd

> **Dependencies note:** L1 (`pip-audit`) and L2 (`osv-scanner`) gracefully SKIP with a hint when their respective CLI is absent. L3 is the always-on layer and does not require any external tool, but accurate L3-CVE evaluation needs `pip install packaging`.

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
./scripts/respond.sh --high axios 1.14.0        # npm
./scripts/respond.sh --high event-stream 3.3.5  # npm
./scripts/respond.sh --high urllib3 2.7.0       # python (pip/poetry/uv auto-detected)
```

Steps in `--critical` mode:
1. Network isolate (block C2 domain via `/etc/hosts`)
2. Kill RAT processes
3. Remove persistence (LaunchAgents / crontab / scheduled tasks)
4. Delete `node_modules` and lockfile, clear npm cache
   - **4b (Python):** purge pip cache (safe, auto); venv-rebuild shown as manual steps
5. Reinstall dependencies
6. Prompt for verification scan (`project-scan.sh` and/or `project-scan-py.sh`)

Each step checks whether action is actually needed (e.g., skips "kill" if no RAT process is running) and shows exactly what will be executed before asking for confirmation.

For **HIGH** mode, npm applies the override automatically; Python is guided (detect manager → print pin command → apply only the safe step). See the Python remediation note in [Quick Start](#quick-start).

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
| [NVD CVE-2026-48710](https://nvd.nist.gov/vuln/detail/CVE-2026-48710) | **Primary** — NVD canonical entry (published 2026-05-26, CVSS 3.1 base 6.5 MEDIUM, AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) |
| [GHSA-86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr) | **Primary** — GitHub Security Advisory on `Kludex/starlette` (published 2026-05-21): "Missing Host header validation poisons request.url.path, bypassing path-based security checks" |
| [Starlette v1.0.1 release notes](https://github.com/Kludex/starlette/releases/tag/1.0.1) | **Primary** — fix release (published 2026-05-21). Pin `starlette>=1.0.1` (and `fastapi>=0.119` for transitive resolution) |
| [Starlette BadHost coverage (KuCoin)](https://kucoin.com/news/flash/starlette-vulnerability-exposes-millions-of-ai-agents-to-hackers) | Secondary — Python ecosystem impact, AI agents framing |
| [BadHost AI agent analysis (CryptoBriefing)](https://cryptobriefing.com/starlette-badhost-vulnerability-ai-agents/) | Secondary — FastAPI / vLLM / LiteLLM downstream impact framing |

---

## Guild-CLI Devil Integration

If you use [guild-cli](https://github.com/eris-ths/guild-cli) (or any project that exposes a Devil lense workflow), SCG can be invoked as one of the security lenses during a review pass.

### Recommended invocation pattern

```bash
# Inside a guild-cli review session, in the project root:
~/path/to/supply-chain-guard/scripts/project-scan.sh       # for npm/yarn projects
~/path/to/supply-chain-guard/scripts/project-scan-py.sh    # for Python projects

# Capture the scan output as evidence for a judgment:
SCG_OUTPUT=$(~/path/to/supply-chain-guard/scripts/project-scan.sh 2>&1 || true)

# (a) Record it as a new judgment (fast-track — no prior review needed):
gate fast-track --from "$USER" \
  --action "SCG supply-chain scan (Devil lense)" \
  --reason "$SCG_OUTPUT"

# (b) Or attach it as the Devil lense on an existing review request <id>:
gate review <id> --lense devil --verdict concern --note "$SCG_OUTPUT"
```

> Flag notes (verified against guild-cli): `gate review` **requires** an
> existing `<id>`, `--lense` (guild-cli spells it "lense"), and `--verdict`
> (`ok` / `concern` / `reject`). It has no `--area` flag. To log a fresh
> finding with no prior review object, use `gate fast-track` as in (a).

### Why pair SCG with Devil

Devil's Advocate ("壊しにいく") and SCG share the same posture: **assume the worst, scan systematically, then converge**. SCG provides the supply-chain dimension of a Devil pass — what the project's dependencies might be doing behind your back — alongside other lenses (security / correctness / architecture / user / operations).

### Limitations of the Devil pairing

- SCG runs read-only; the Devil lense won't push fixes. Use `respond.sh` separately when remediation is required (with explicit user confirmation)
- SCG output may exceed Devil context budgets in large repos; pipe through `tail -50` if needed
- For polyglot repos, run both `project-scan.sh` and `project-scan-py.sh` and merge findings

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

- **Last updated:** 2026-05-27 (v4: Python support, BadHost CVE-2026-48710 added)
- **Coverage:** 3 npm threat families (T001-T003) + 4 Python hijacked/typosquat entries + 1 Python CVE-flagged version entry (BadHost)
- **Python coverage scope (v4):** primarily lockfile-based scanning (uv.lock / poetry.lock / requirements.txt). The CVE-flagged version layer is **best-effort** — it only flags packages that match `_L3_CVE_LIST` entries with strict semver-spec evaluation, and depends on `packaging` being installed for accurate version matching

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

- **npm/yarn and Python (pip/poetry/uv).** Does not cover cargo, go modules, or other package ecosystems.
- **Known threats only.** This is a pattern-matching tool, not a behavioral analysis engine.
- **Point-in-time scan.** Results reflect the state at the moment of execution. Continuous monitoring requires repeated execution or integration with CI/CD.

---

## Integrity Verification

Verify that your copy of SCG has not been tampered with. Compare these SHA-256 checksums against your local files:

<!-- CHECKSUMS-START -->
```
67ac6216cbe18fdf7050fd267bce4157c016e5c60cd4f84f63b8cf71e80ae3b9  scripts/env-scan.sh
da01f8362563b55b1553f923a748f07d24f24522366e0545e6ba0c09801f8e54  scripts/project-scan.sh
77e7ebba6d44ea020e511a49bc2cbc974d01495de40d35e8dfb7fcc93008954b  scripts/project-scan-py.sh
82aaa4ed898ce354addc064ccf84cca9a498ef4e90fe58613e1110146577609f  scripts/ioc-scan.sh
72ed333838b5584c3b1faf889edc81b0e3195c27396c3b36c62aaebf5f952117  scripts/ioc-scan.ps1
0e6b30e57c959180e22e0ba16f860e9fdc7304045947995084703fb14381d12e  scripts/respond.sh
a44be79d909058c9d216e7cbc5cca736cf8816a492c8d35a6b90c74c042abf5b  SKILL.md
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
