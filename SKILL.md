---
user-invocable: true
name: supply-chain-guard
description: |
  npm/yarn サプライチェーン攻撃の検知・防御スキル。
  依存パッケージの汚染チェック、RAT痕跡スキャン、lockfile整合性検証、Devil Gate統合。
  「サプライチェーン」「supply chain」「npm汚染」「依存パッケージ攻撃」「パッケージ乗っ取り」で発動。
triggers:
  - サプライチェーン
  - supply chain
  - npm汚染
  - 依存パッケージ攻撃
  - パッケージ乗っ取り
  - malicious package
  - npm audit
category: security
version: "3.2"
lastUpdate: "2026-04-01"
author: Eris
license: "MIT"
rarity: rare
capability: quality-guard
activation: contextual
prerequisites: ["python3", "npm or yarn", "osv-scanner(recommended)"]
---

# SCG — Supply Chain Guard v3

```
arch: DDD(domain/application/infrastructure)
enc:  AI-first compact — YAML+abbr, Claude展開前提
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

# ─── 更新運用 ───
maintenance:
  principle: "KnownThreats は鮮度が命。腐る台帳にしない"
  update_trigger: "新規インシデント報道時にエリスが D.2 + I.3 + I.4 を同時更新"
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
  staleness: "6ヶ月更新なし → 最新npm advisoryを1回チェックして更新 or 「確認済み」タグ"
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

8ゲートを4カテゴリに分類。各ゲートに問い(question)・検証手段(check)・合格基準(pass)を定義。

```yaml
# ── Dependency Poisoning（依存汚染） ──
G1_direct_dep:
  question: "直接依存に侵害バージョンはないか？"
  check: "npm list <pkg> + npm audit (I.1)"
  pass: "全パッケージが安全バージョン"

G2_transitive_dep:
  question: "間接依存（依存の依存）に汚染はないか？"
  check: "npm list --all <pkg> + OSV.dev (I.2)"
  pass: "transitive にも汚染パッケージなし"

# ── Runtime Compromise（実行時汚染） ──
G3_rat_artifacts:
  question: "ファイルシステムにRAT痕跡はないか？"
  check: "IOC ファイルスキャン (I.4) — 全OS対象"
  pass: "全プラットフォームで痕跡なし"

G4_postinstall:
  question: "不審な postinstall スクリプトはないか？"
  check: "node_modules/*/package.json の postinstall grep"
  pass: "正当なもののみ（node-gyp, husky, esbuild 等）"

# ── Integrity（整合性） ──
G5_lockfile:
  question: "lockfile は改ざんされていないか？"
  check: "npm ci --dry-run (I.5)"
  pass: "integrity hash 整合性OK"

G6_provenance:
  question: "パッケージの出所は正規か？"
  check: "npm view <pkg> --json で publishedBy 確認"
  pass: "registry.npmjs.org 由来、既知メンテナー"

# ── Environment（環境） ──
G7_network:
  question: "不審な外部通信の兆候はないか？"
  check: "lsof / netstat + DNS cache (I.4 network)"
  pass: "D.2.c2 に該当する接続なし"

G8_cicd:
  question: "CI/CD は postinstall バイパス・lockfile 厳密モードか？"
  check: "CI設定ファイルで --ignore-scripts / --frozen-lockfile 確認"
  pass: "ハードニング済み or N/A（ローカルのみ）"
```

## D.5 DevilChain(4)

4視点を直列で回す。各ステップで対応する Gate を適用。

```yaml
chain:
  S1_dependency:  [G1_direct_dep, G2_transitive_dep]
  S2_runtime:     [G3_rat_artifacts, G4_postinstall]
  S3_integrity:   [G5_lockfile, G6_provenance]
  S4_environment: [G7_network, G8_cicd]

flow: "S1→S2→S3→S4 → 懸念あれば修正→Chain全体を再走 → 全PASS→収束"
```

## D.6 DevilLoop

```yaml
rule: "round_N: chain_all → concern? fix→round_N+1 : declare_clear"
max: 3  # escalate_to_user_if_not_converged
low_risk: "reason_annotated→ok_to_defer→converge"
record: "entity=devil_sc_{proj}_{date} type=debug_pattern|decision"
```

## D.7 References

```yaml
refs:
  - {k: ja_zenn,    u: "zenn.dev/gunta/articles/0152eadf05d173",                              n: "JP速報"}
  - {k: elastic,    u: "elastic.co/security-labs/axios-one-rat-to-rule-them-all",              n: "技術分析(RAT逆アセ/C2/timeline)"}
  - {k: sans,       u: "sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan", n: "企業IR手順"}
  - {k: huntress,   u: "huntress.com/blog/supply-chain-compromise-axios-npm-package",          n: "YARA sig"}
  - {k: elastic_det,u: "elastic.co/security-labs/axios-supply-chain-compromise-detections",    n: "SIEM検知rule(YARA/osquery/KQL)"}
  - {k: semgrep,    u: "semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/", n: "静的解析rule/封じ込め"}
  - {k: socradar,   u: "socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/",     n: "CISO向けIOC/timeline"}
  - {k: wiz,        u: "wiz.io/blog/axios-npm-compromised-in-supply-chain-attack",            n: "クラウド影響/コンテナscan"}
```

---

# §A — Application Layer

## A.1 UseCases

```yaml
# ─── 2モード: 環境 vs プロジェクト ───
mode:
  env_scan:
    trigger: "「このPCで」「環境チェック」「マシン全体」"
    scope: "IOC(fs+net) + find全lockfile横断 + axios/malicious一括grep"
    skip: [G4_postinstall, G5_lockfile, G6_provenance, G8_cicd]
    flow: "IOC → find package-lock.json -maxdepth 5 → L3横断 → Devil(G1,G2,G3,G7)"
  project_scan:
    trigger: "「このプロジェクト」「npm audit」+ cwd にpackage.json"
    scope: "L1+L2+L3 + IOC + lockfile + postinstall + provenance"
    skip: []
    flow: "A.2 ScanPipeline フル → Devil Gate(8) 全ゲート"

UC_scan:    "Phase1 → 3層検知(L1:audit, L2:osv, L3:static) + ioc_fs + lockfile"
UC_assess:  "Phase2 → SeverityMatrix適用 → CRITICAL/HIGH/MEDIUM/LOW/CLEAR"
UC_respond: "Phase3 → severity別対応(isolate/kill/clean/fix/verify)"
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

CRITICAL/HIGH の対応は破壊的操作を含む。**必ずユーザーに確認を取ってから実行すること。**
スキャン結果と対応案を提示 → ユーザー承認 → 実行、の順序を厳守する。

```yaml
on_CRITICAL:
  confirm: true  # ユーザー確認必須 — 自動実行禁止
  seq: [net_isolate, kill_proc, rm_persist, rm_npm, reinstall, rescan_loop]
on_HIGH:
  confirm: true  # ユーザー確認必須
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
  all_pass? → "懸念なし" → record(entity) → done
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

osv-scanner CLI（Google公式）優先。未インストール時は API fallback。

```bash
# ─── preferred: osv-scanner CLI（高速・全依存一括） ───
# install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest
#   or: brew install osv-scanner
osv-scanner --lockfile=package-lock.json 2>/dev/null
_OSV_EXIT=$?
if [ $_OSV_EXIT -eq 127 ]; then
  echo "L2:osv-scanner not found — fallback to API"
fi
```

```bash
# ─── fallback: OSV.dev API（依存100+件では遅い、CI非推奨） ───
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

SOT は D.2 KnownThreats。ここに追記する時は D.2.mal[] と D.2.pkg[] にも必ず追記。

```bash
# D.2 KnownThreats.mal[] + T003_typosquat.pkg[] の実体化
_M=(plain-crypto-js flatmap-stream crossenv loadsh crypto-js-esm)
for p in "${_M[@]}";do npm list "$p" 2>/dev/null|grep -v empty&&echo "!!L3:$p";done
```

## I.4 Scanner: ioc_fs

IOC パスは D.2 KnownThreats.ioc_fs が SOT。OS 自動判定で該当プラットフォームのみ実行。

```bash
# — OS自動判定・該当プラットフォームのみ実行 —
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

# network(全OS共通) — D.2.c2 参照
lsof -i -nP 2>/dev/null|grep -E '142\.11\.206\.73|sfrclak'&&echo "!!C:c2_active"
```

```powershell
# — win32（PowerShell）— Windows環境でのみ使用 —
$ioc = @("$env:PROGRAMDATA\wt.exe","$env:TEMP\6202033.vbs","$env:TEMP\6202033.ps1")
foreach ($f in $ioc) { if (Test-Path $f) { Write-Host "!!C:win_$($f|Split-Path -Leaf)" } }
Get-Process wt -EA 0 | Where-Object {$_.Path -like "*ProgramData*"} | ForEach-Object { Write-Host "!!C:win_proc" }
schtasks /query /TN WindowsTerminalUpdate 2>$null && Write-Host "!!C:win_schtask"
netstat -an | Select-String "142.11.206.73" | ForEach-Object { Write-Host "!!C:c2_active" }
```

## I.4b Scanner: env_cross_scan

env_scan モード専用。全プロジェクト横断で compromised pkg を一括検出。

```bash
# ─── env_scan: 全lockfile横断スキャン ───
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

A.3.on_CRITICAL を実行。IOC は D.2 KnownThreats、手順は A.3.seq に対応。
**以下のコマンドは破壊的操作を含む。必ずユーザー承認後に実行すること。**

```bash
# ⚠️ DESTRUCTIVE — CONFIRM_BEFORE_EXEC
# S1:net_isolate — D.2.c2.dom をブロック
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
