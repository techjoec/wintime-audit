# WinTimeHealth — Design (FINAL, v1 implementation contract)

Status: locked after adversarial multi-agent review (2026-07-11). This file is
the implementation contract: parallel component builders must follow the
signatures and semantics here exactly. Deviations require editing this file
first.

## 1. Purpose

PowerShell module `WinTimeHealth`: audits Windows Time service (W32Time)
**configuration** (`Get-WinTimeConfig`), **live health**
(`Get-WinTimeHealth`), and captures **baselines**
(`Export-WinTimeConfigBaseline`) across a multi-domain AD forest, concurrently,
over SMB remote registry (winreg named pipe, TCP/445) + UDP/123 SNTP — no
WinRM. Scale target ~6 domains / ~350 DCs. Output rule: nobody reads 350
records — group by finding, collapse the clean.

## 2. Module layout

```
WinTimeHealth/
├── WinTimeHealth.psd1        # PS 5.1+, Desktop+Core, explicit exports, FormatsToProcess
├── WinTimeHealth.psm1        # dot-sources Public/+Private/, loads DB, guards (see §12)
├── Data/W32TimeKeys.yaml     # canonical database (schema_version 2)
├── Formats/WinTimeHealth.Format.ps1xml
├── Public/    Get-WinTimeConfig.ps1, Get-WinTimeHealth.ps1, Export-WinTimeConfigBaseline.ps1
├── Private/   (one function per file, names below)
└── Tests/     Pester 5 (see §11)
```

Private function inventory (contracts in later sections):
`ConvertFrom-SimpleYaml`, `Get-W32TimeDatabase`, `Resolve-W32TimeExpectation`,
`Resolve-WinTimeTarget`, `Invoke-WinTimeScan`, `Get-WinTimeRegistryWorker`,
`Compare-W32TimeConfig`, `ConvertFrom-RegFile`, `ConvertTo-RegFile`,
`Invoke-NtpQuery`, `Invoke-WinTimeHealthEvaluation`, `New-WinTimeHtmlReport`,
`Write-WinTimeSummary`, `Write-WinTimeReportFile`, `ConvertTo-WinTimeCsvSafe`,
`Connect-WinTimeAdminShare`, `Disconnect-WinTimeAdminShare`.

The repo-root `W32TimeKeys.yaml` moves to `Data/` when the module lands
(single canonical copy).

## 3. Output & stream contract (DECIDED)

- **Success stream = records only.** `Get-WinTimeConfig` emits
  `WinTime.ConfigRecord` objects; `Get-WinTimeHealth` emits
  `WinTime.HealthRecord`; `Export-WinTimeConfigBaseline` emits
  `System.IO.FileInfo` (one per file written). Never mix types on the pipeline.
- **Scan failures** → non-terminating `Write-Error` per unreachable server,
  with the `WinTime.ScanStatus` object as `TargetObject` and
  FullyQualifiedErrorId `ScanFailure,<CmdletName>`. `-ErrorVariable` therefore
  collects machine-readable failure objects.
- **Console pyramid** (§10) is host-channel UX: written by
  `Write-WinTimeSummary` via `Write-Host` (documented PSSA suppression — it is
  the host channel by design, wraps Write-Information). Suppress with
  `-NoSummary`. Printed once, after the scan completes; records stream to the
  pipeline as they arrive; `Write-Progress` covers the interim.
- **Report files**: `-CsvPath <path>` and `-HtmlPath <path>` (both optional,
  independent, may be combined; replaces earlier -AsCsv/-AsHtml/-OutFile
  design). Overwriting an existing file requires `-Force` (consistent with
  Export). When any scan failures occurred and `-CsvPath` given, also write
  `<base>.failures.csv`. Paths resolved via
  `$PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath()`.
- **JSON**: documented pattern `… | ConvertTo-Json -Depth 6` (no switch).
- Every record carries `RunId` (one GUID per invocation) and `Timestamp`
  (ISO-8601, invariant).

### WinTime.ConfigRecord
`Server, Domain, Role (Dc|RootPdce), OsBuild, KeyPath, ValueName, Type, Data,
Expected, ExpectedSource (Baseline|MSDefault|Policy), Status (Match|Drift|
NotSet|Missing|PdceExempt|Ignored|Undocumented), IsDrift (bool), Class
(config|internal|diagnostic|unknown), GpoBacked (bool), PolicyApplied (bool),
Note, RunId, Timestamp`
- `IsDrift = Status -in Drift, Missing`. The console drift counts use exactly
  this predicate. (`Where-Object IsDrift` is the documented one-liner.)
- Absent value + no baseline ⇒ `NotSet` (service uses default; not drift).
  Absent + baseline defines it ⇒ `Missing` (drift).
- **Policy-effective expectation**: when the policy twin defines the value,
  the effective expectation IS the policy value (`ExpectedSource=Policy`,
  `PolicyApplied=$true`); operational≠policy ⇒ `Drift` with Note
  "operational value diverges from applied GPO". Otherwise expectation =
  baseline if provided else role/OS-resolved MS default. When a drift value
  equals a documented `gpo_default`, append Note hint "matches GPO preset for
  '<policy>' — likely a GPO applying".
- `Data`/`Expected` for REG_MULTI_SZ are string[]; the CSV projection joins
  with `|`.
- DWORD/QWORD normalized **unsigned** (`[uint32]`/`[uint64]`) at the single
  choke point before compare/serialization; reports render decimal (hex in
  parens for values ≥ 0x80000000). Pester case: 0xFFFFFFFF round-trip.

### WinTime.ScanStatus
`Server, Domain, Success, Attempts, LastError, ErrorClass
(Timeout|Transport|AccessDenied|AuthFailure|RemoteRegistryDisabled|Unknown),
DurationMs, OsBuild, RunId, Timestamp`

### WinTime.HealthRecord
`Server, Domain, Role (Dc|RootPdce), Check, Status (Pass|Warn|Fail|Error|
Blocked|NotApplicable), Detail (self-sufficient human string), Data
(hashtable; CSV projection flattens to compact JSON), RunId, Timestamp`
- `Blocked` = prerequisite failed (Detail names the blocking check);
  `NotApplicable` = check doesn't apply to this target. One root cause per
  server in the console; no Fail cascades.
- Transports are independent: UDP checks still run when the registry scan
  failed, and vice versa.

### Format.ps1xml
Default table view for ConfigRecord: `Server, ValueName, Status, Data,
Expected, ExpectedSource` (KeyPath in the list view). HealthRecord table:
`Server, Check, Status, Detail`. List views carry all properties. `[OutputType()]`
declared on all cmdlets.

## 4. Public cmdlet surface (DECIDED)

Shared targeting (Get-WinTimeConfig + Get-WinTimeHealth only — **not**
Export):
```
-Forest                                   # explicit whole-forest anchor (default behavior)
-IncludedDomains/-ExcludedDomains <string[]>          # wildcards, -like, case-insensitive
-IncludedSites/-ExcludedSites <string[]>              # [SupportsWildcards()]
-IncludedDomainControllers/-ExcludedDomainControllers <string[]>
-Credential <PSCredential>
-ThrottleLimit <int> = 32   [ValidateRange(1,128)]
-RetryCount <int> = 3       [ValidateRange(0,10)]     # user-specified default: 3
-TimeoutSeconds <int> = 30  [ValidateRange(5,300)]    # per-attempt budget, best-effort (§7)
-CsvPath <string> / -HtmlPath <string> / -Force / -NoSummary
```
Precedence: Included* builds the candidate set (absent = all), then Excluded*
removes — **Exclude always wins**. `-IncludedDomainControllers` accepts
pipeline-by-property-name with `[Alias('Server','ComputerName','DnsHostName')]`
(accumulate in `process{}`, fan out in `end{}`) so the failures CSV re-runs via
`Import-Csv failures.csv | Get-WinTimeConfig`.

### Get-WinTimeConfig extras
```
-RootPDCEBaselineFile <file.reg>   -DCBaselineFile <file.reg>
```
- When only `-DCBaselineFile` given, auto-load sibling `<base>.pdce.reg` if it
  exists (Write-Verbose).
- Reads per server: `Services\W32Time` (recursive, from the SERVICE ROOT — the
  DB now covers root values), `SOFTWARE\Policies\Microsoft\W32Time`
  (recursive), `SOFTWARE\Microsoft\Windows NT\CurrentVersion` (build/product),
  `SYSTEM\CurrentControlSet\Control\SystemInformation` (hypervisor detection).
- Forest-root PDCe only gets `pdce-exempt` handling (status `PdceExempt`);
  child-domain PDCes are ordinary DCs. If PDCe detection fails: loud warning,
  exemptions disabled, Note on affected records.
- **Undocumented promotion rule**: Status=Undocumented is record-only EXCEPT
  the security subset promoted to the console pyramid: (a) any subkey under
  `TimeProviders\` not in the DB, (b) any value name matching `*Dll*` anywhere
  in either tree, (c) any policy-twin value not known to the DB. Test with a
  synthetic `TimeProviders\Evil` tree.

### Get-WinTimeHealth extras
```
-IncludedHealthChecks/-ExcludedHealthChecks <string[]>   # static ValidateSet, literal names
-NtpSamples <int> = 4          -NtpTimeoutMilliseconds <int> = 1500
-OffsetWarnMilliseconds = 500  -OffsetFailMilliseconds = 5000
-StratumDepthSlack <int> = 1   -LastSyncWarnSeconds = 0 (auto)  -LastSyncFailSeconds = 0 (auto)
-KnownReliableTimeServers <string[]>    # declared GTIMESERV hosts; suppresses hierarchy warns
```
NTP transport has its own timeout (`-NtpTimeoutMilliseconds`), independent of
`-TimeoutSeconds` (worker envelope only).

### Export-WinTimeConfigBaseline
```
Set 'Named': -DomainControllers <string[]> (mandatory, exact FQDNs, pipeline-by-property-name)
Set 'All'  : -ExportAllDCs (mandatory switch)
Both: -OutFile <string> (mandatory), -Force (file overwrite ONLY — covers companion too),
      -Credential, -ThrottleLimit, -RetryCount, -TimeoutSeconds
[CmdletBinding(SupportsShouldProcess)] — -WhatIf resolves targets and reports
intended file paths without scanning.
```
- **Consensus**: all `compare: exact` values must agree across non-PDCe
  targets **per OS cohort**; values with `defaults_overrides` (OS-divergent
  defaults) are EXCLUDED from the baseline with a loud warning naming them
  (they're audited against per-OS MS defaults instead). Disagreement ⇒
  terminating error, FullyQualifiedErrorId
  `BaselineConsensusFailure,Export-WinTimeConfigBaseline`, TargetObject =
  disagreeing ConfigRecord set, message = mini drift report. `-Force` does NOT
  override consensus.
- **Content policy**: baseline contains ONLY `class: config` values plus
  internal-with-`compare: exact` tamper values (ServiceDll, DllName,
  ObjectName, ImagePath…). Never `compare: ignore` values or
  `internal_subtrees` (no runtime clock state in a mergeable .reg).
- PDCe auto-detected: its `pdce-exempt` values → companion
  `<name>.pdce.reg` (single-source: warn "review by hand"). Non-PDCe copies of
  pdce-exempt values are consensus-checked into the DC baseline like exact.
- First line of every generated .reg: `; WinTimeHealth AUDIT BASELINE — do not
  merge into a registry` + provenance comments (source DC(s), UTC timestamp,
  OS builds, module+schema version, current PDCe fqdn).

## 5. Database contract (schema_version 2)

As in `Data/W32TimeKeys.yaml` header. Additions from review:
- `defaults_overrides` (build-ranged, machine-readable) — resolver applies
  when OsBuild known; unknown build ⇒ base defaults + Note.
- Service root-key entries (Start, Type, ErrorControl, ObjectName, ImagePath,
  DisplayName, Description, FailureActions, DependOnService) and VMIC
  DllName/InputProvider are present so nothing common surfaces as
  Undocumented noise.
- `Resolve-W32TimeExpectation -Entry <db> -Role <Dc|RootPdce> -OsBuild <int?>`
  → `@{Expected; Source}` centralizes role/OS/pdce resolution.
- Path comparisons are **OrdinalIgnoreCase** everywhere (registry semantics).
- Loader validates schema_version == 2 (throw with upgrade message otherwise)
  and hex `0x…` scalars parse to unsigned.

## 6. Discovery & PDCe (DECIDED)

- One LDAP query per forest against the config NC — NOT per-DC .NET calls:
  `DirectorySearcher` rooted at `CN=Sites,CN=Configuration,<forestRootDN>`,
  filter `(&(objectClass=server)(dNSHostName=*))`, attributes `dNSHostName`,
  `serverReference` — yields DC + site (RDN two above) + domain (from
  serverReference DN) in one round trip. **Never touch
  DomainController.SiteName** (per-DC RPC bind, no timeout, minutes at scale).
- Forest handle: `DirectoryContext(Forest[, user, password])` →
  `Forest.GetForest()`; root PDCe: `.RootDomain.PdcRoleOwner.Name`; domain
  list from `.Domains`. `-Credential` flows into every DirectoryContext.
- RODC tagging: one LDAP query per domain
  (`(&(objectCategory=computer)(primaryGroupID=521))`), used by Stratum (+1
  expected depth) and reporting. Domain depth (distance from forest root)
  computed from the domain DN chain for the stratum band.
- Stale/decommissioned DCs still in the config NC will appear and report as
  UNREACHABLE — documented behavior (it surfaces metadata cruft; that's a
  feature).
- `Resolve-WinTimeTarget` returns
  `[pscustomobject] @{ ComputerName(fqdn); Domain; Site; IsRootPdce; IsRodc;
  DomainDepth }[]` — one canonical FQDN string used for EVERYTHING
  (IPC$ session, OpenRemoteBaseKey, ServiceController, NTP) per target.

## 7. Scan engine & credentials (DECIDED)

**ThreadJob**: NOT in RequiredModules (PS 7.6 renamed the in-box module to
Microsoft.PowerShell.ThreadJob; a name pin breaks somewhere). At module load:
`Get-Command Start-ThreadJob` else throw with `Install-Module ThreadJob
-Scope CurrentUser` guidance (5.1).

**Worker** (`Get-WinTimeRegistryWorker` returns a fully self-contained
scriptblock; no module-state references; receives
`($Target, $ReadSpec, $Options)` clones — treat all inputs read-only):
1. TCP/445 preflight: `TcpClient.ConnectAsync().Wait(2000)` — fail fast,
   ErrorClass=Transport.
2. Registry read per attempt runs on a nested `[powershell]::Create()`
   instance with `BeginInvoke`; wait `AsyncWaitHandle.WaitOne(TimeoutSeconds)`;
   on timeout ABANDON it (record Timeout; native winreg calls are
   uninterruptible — bounded thread leak documented; SMB client timeout
   (~60 s) eventually frees it). Never `Thread.Abort`; `Stop()` best-effort
   fire-and-forget.
3. Retry loop: attempts = 1+RetryCount, backoff 1s/2s/4s… **transport-class
   errors only**. `SecurityException`/`UnauthorizedAccessException`/logon
   errors (1326/1331/1907/1219) are TERMINAL first-occurrence
   (ErrorClass=AccessDenied|AuthFailure) — retrying sprays lockouts.
4. Preflight-ok + `IOException` on winreg open ⇒ ErrorClass=
   RemoteRegistryDisabled, LastError "winreg pipe unavailable — RemoteRegistry
   likely Disabled on <fqdn>" (modern default is trigger-start, so this means
   deliberately disabled).
5. Values captured as `@{Kind=<RegistryValueKind string>; Data=…}` via
   `GetValueKind` + `GetValue(..., DoNotExpandEnvironmentNames)`; Unknown/None
   kinds captured raw without throwing; null subkey ⇒ empty hashtable.
   Returns `@{ ComputerName; Success; Attempts; Error; ErrorClass; DurationMs;
   Tree }` (Tree: `hashtable[path][name] = @{Kind;Data}`).
6. Workers never Write-Progress/Write-Host. Orchestrator owns the single
   progress bar, polls job states, enforces per-job ceiling
   `TimeoutSeconds×attempts + backoffSum + 15s grace` via `Wait-Job -Timeout`
   + `Stop-Job` as bookkeeping; **every target is accounted for in the output
   even when the watchdog fires** (totals must always add up).
7. Run-abort guard: ≥5 consecutive AuthFailure results ⇒ stop dispatching,
   terminating error ("credential appears invalid — aborting before lockout").

**Credentials over SMB (DECIDED: v1 implements the session path)**:
- No `-Credential` ⇒ caller's context, zero session management.
- With `-Credential`: per target, `Connect-WinTimeAdminShare` establishes an
  IPC$ session under the alternate credential before the registry hop, keyed
  by the SAME canonical FQDN. Mechanism: `New-SmbMapping -RemotePath
  \\<fqdn>\IPC$` (in-box both editions, in-process — password never on a
  command line); fallback WNetAddConnection2 P/Invoke if IPC$ mapping is
  rejected. Pre-check `Get-SmbConnection -ServerName <fqdn>`: same user ⇒
  reuse, never tear down (not ours); different user ⇒ terminal per-host error
  ("1219 conflict: disconnect existing session to <fqdn> or run without
  -Credential") — no retry.
- Cleanup: orchestrator tracks every session IT created (concurrent bag);
  `finally` in Invoke-WinTimeScan (runs on Ctrl+C) disconnects all tracked
  sessions. Sessions it didn't create are never touched.
- ScanStatus per-domain auth-failure grouping in the summary (distinct from
  unreachable) — surfaces cross-domain rights asymmetry.

## 8. Health engine (DECIDED: two-phase)

Phase 1: registry trees via the SAME `Invoke-WinTimeScan` (skipped when all
selected checks are registry-free). Service **Status** queried via
`ServiceController('w32time', fqdn)` inside the worker (svcctl rides the same
445 session); **StartType read from the registry tree** (Start value — no
.NET-version dependency).
Phase 2: orchestrator-driven SNTP sampling — bounded concurrency (~64
outstanding), per target `-NtpSamples` mode-3 NTPv3 client packets from
ephemeral ports (never bind 123), randomized T1, validate replies (mode 4,
version 3/4, originate echoes our T1, sane length); best sample =
minimum-delay. Timestamps: capture `DateTime.UtcNow` once per run, derive all
T1/T4 from a QPC Stopwatch offset (monotonic; admin-host absolute error
cancels in differential offset). Forest-root PDCe (+
`-KnownReliableTimeServers`) is ALWAYS queried as hidden reference even when
filtered out of targets, re-sampled every ~60 s during long runs; if
unreachable ⇒ Offset=Error (Detail says reference dead), Stratum degrades to
absolute rules only.
`Invoke-NtpQuery` implementation notes: explicit `ReceiveTimeout`; catch
SocketException 10054 ⇒ "port closed — w32time down or NtpServer provider
disabled", 10060 ⇒ "no reply (filtered UDP/123, service stopped, or
RequireSecureTimeSyncRequests=1 — unverified)"; big-endian conversion helpers;
KoD/LI=3/stratum-0 recognized. No UDP reply is **Status=Error, never Fail**;
when the config tree shows `RequireSecureTimeSyncRequests=1`, that becomes the
primary hint (semantics pending lab verification — doc reading says plain
unauthenticated queries still get answers).

Check catalog (ValidateSet, FINAL):
| Check | Logic (summary) |
| --- | --- |
| Service | Pass = SCM Running AND registry Start∈{2,3} (3 = Manual + domain-join trigger-start, the real out-of-box default on every role incl. DCs per MS KB2385818; 2 = Automatic, the MS high-accuracy hardening — neither alone is drift) AND ObjectName=LocalService. Warn = Running+nonstandard Start value, or DelayedAutostart, or nonstandard identity (tamper hint). Fail = not running/disabled. NotApplicable = no W32Time key (Samba). |
| NtpQuery | Pass = ≥1 valid reply. Warn = replies but >50% probe loss. Error = zero replies (taxonomy above). Blocks: Offset/Stratum/Source/LastSync. |
| Offset | offset=((T2−T1)+(T3−T4))/2 of best sample; report OffsetVsPdce = offset_DC − offset_PDCe. Warn/Fail at -Offset*Milliseconds. PDCe itself: NotApplicable. |
| Stratum | Fail = stratum 0, >15, or LI=3. Warn = outside band expected = pdceStratum + DomainDepth ± Slack (+1 RODC), or ≤ PDCe's ("DC syncing outside hierarchy") unless in -KnownReliableTimeServers. |
| Source | Registry layer: Fail = Type=NoSync or NtpClient Enabled=0. Pass = NT5DS (non-root-PDCe) / NTP+peers (root PDCe). Warn = NTP on non-PDCe (mis-scoped PDCe GPO — classic) unless known-reliable. NTP layer: refid regimes (IPv4 upstream / MD5-hash for v6 / ASCII tag stratum-1 / 0 = unsync-or-VMIC); Warn on LOCL. |
| LastSync | age = T3 − ReferenceTimestamp (same reply — pure server clock). Warn > 2×2^MaxPollInterval (per-server effective value; auto), Fail > ClockHoldoverPeriod (7800 fallback when value absent pre-1709). |
| Announce | Bitmask decode. Root PDCe: Pass=5, Warn=10 ("set 5 per MS convention"), Fail=no timeserv bits. Others: Pass=10, Warn=AlwaysReliable set (time hijack risk) unless known-reliable. |
| Vmic | Hypervisor from SystemInformation key. NotApplicable = physical. Hyper-V guest DC: Fail = Enabled=1 AND build<14393 host-sync pattern; Info otherwise (post-2016 boot/resume-only). Detection keys on refid+manufacturer, not stratum. |
| RefidLoop | Fleet-wide: map DC→refid(IPv4); cycle detection over the directed graph; Fail = DCs on a cycle with no external upstream; Warn = refid matches no forest DC and no PDCe peer (unknown upstream; emitted once here, suppressed in Source). |
| SecureTimeSeeding | Effective UtilizeSslTimeData=1 on DC ⇒ Info (pre-2025 default) with MS-2025-default-0 note; Warn when SecureTimeLimits state shows STS actively steering a DC (estimate divergence). |

## 9. .reg parser/writer

As before (v5 header, all hex(x) layouts, continuations, escapes, `@=`), plus:
- **REGEDIT4 rejected** with clear "re-export as v5" error (ANSI payload
  semantics not worth carrying).
- Deletion syntax (`[-key]`, `"name"=-`) rejected — baselines have no delete
  semantics.
- Generic `hex(X)` captured as raw bytes with the kind preserved.
- Comments only when `;` is first non-whitespace char; continuation only on
  hex data lines (trailing `\`); never inside quoted strings.
- Encoding: writer UTF-16LE+BOM via `[IO.File]::WriteAllText` (identical both
  editions); parser sniffs BOM (UTF-16LE/UTF-8) else ANSI.
- Parser returns `@{ Tree; Provenance }` — provenance parsed from leading `;`
  comments. `Get-WinTimeConfig` warns when baseline age >180 days, module/
  schema mismatch, OS-cohort mismatch, or provenance PDCe ≠ current PDCe
  (FSMO transfer).

## 10. Console UX + report safety

Pyramid as previously agreed (header incl. baseline age/source → totals →
per-domain table (Scanned/Clean/Drift/Failed + AuthFailed) → drift-by-setting
→ promoted-Undocumented security section (§4) → unreachable). Drift grouping
key = `(KeyPath\ValueName, Expected+ExpectedSource, FoundValue)` — one
sub-line per distinct found value; role/OS-scoped expectations annotated
(`expected 5 [PDCe] / 10 [DC]`); counts use IsDrift. `(+N more, see
<file>.csv)` only when a CSV was written, else `(+N more — re-run with
-CsvPath)`.

Safety (all Pester-tested):
- **HTML**: every interpolated string through
  `[System.Net.WebUtility]::HtmlEncode`; no external resources; test with
  `<script>` in value name+data.
- **CSV**: `ConvertTo-WinTimeCsvSafe` guards fields starting `= + - @` or
  containing control chars (OWASP formula-injection: prefix `'`); test with
  `=cmd|…`.
- **Encoding**: single `Write-WinTimeReportFile` helper —
  `[IO.File]::WriteAllText($path, $text, UTF8Encoding($true))` (BOM, both
  editions identical); CSV text built via `ConvertTo-Csv`.
- **Culture**: all numeric/date serialization InvariantCulture; filenames
  `yyyyMMdd-HHmmss`; timestamps ISO-8601; comparisons OrdinalIgnoreCase; a
  Pester context runs under de-DE culture.
- **Glyphs**: Unicode pyramid glyphs only when the host is UTF-capable
  (`[Console]::OutputEncoding` check); ASCII fallback (`X`, `!`, `=`).

## 11. Tests (Pester 5, cross-platform)

Everything except live registry/AD/UDP: YAML parser vs JSON snapshot of the
real DB; DB integrity (fields, enums, gpo blocks, defaults roles, ValidateSet
↔ catalog parity, hex parse to unsigned); .reg writer↔parser roundtrip (all
kinds, escapes, unicode, continuation) + real regedit fixture + REGEDIT4/
deletion rejection; compare logic (defaults/baseline/pdce/policy-effective/
undocumented/missing/promotion rule/0xFFFFFFFF/multi-value grouping); target
filter precedence; CSV/HTML injection; culture (de-DE); expectation resolver
(defaults_overrides by build). Mock discovery objects for filter tests.

## 12. Load-time guards & packaging (2026 hygiene)

At import: PS ≥5.1; `Start-ThreadJob` resolvable (else actionable throw);
LanguageMode == FullLanguage (else throw — CLM/WDAC PAWs can't run the .NET
core anyway; document); non-Windows ⇒ module loads (for tests) but scan
cmdlets throw early with a clear message; DB schema_version check.
Manifest: explicit exports, Desktop+Core, PSData (Tags/LicenseUri/ProjectUri),
FileList includes Data+Formats. PSScriptAnalyzer settings checked in
(PSUseCompatibleSyntax 5.1+7.4; documented Write-Host suppression). Comment-
based help with examples on all public cmdlets. SemVer + CHANGELOG.
Phase 2 (post-v1): Authenticode signing, CI matrix (win 5.1/7.4 + ubuntu),
PSGallery publish via PSResourceGet, platyPS docs.
**Ban on 5.1-breaking syntax**: no ternary, `??`, `&&`/`||` pipeline chains,
`Join-String`, `ForEach-Object -Parallel`, `Test-Json`, `clean` blocks.
OrderedDictionary: use `.Contains()`. No `Date.Now`-culture formatting.

## 13. Operational posture (documented in README/help)

The scan's telemetry signature (IPC$ + winreg + svcctl to every DC, optionally
with alternate creds) resembles lateral-movement recon; MDI/EDR will notice.
Docs: pre-register the admin host with the SOC, run from a designated host,
expect 4624/5145 on every DC; optional `-ThrottleLimit` reduction for quiet
runs. Output files are recon-grade inventory — handle accordingly. Tier-0
credential posture: PSCredential only, never persisted, never on a command
line. UDP/123 reachability from the admin host to all sites is required for
full health coverage (else those checks report Error, not Fail).

## 14. Non-goals (v1)

No remediation/write path; no WinRM/CIM fallback; DC-focused targeting (DB
retains member/standalone defaults for future use); no RODC-specific scan
logic beyond tagging; perf-counter offset transport (noted v2 path for the
Offset check).
