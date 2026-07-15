# WinTimeHealth

A PowerShell module that audits the Windows Time service (`W32Time`) across a
multi-domain Active Directory forest — configuration drift, live sync health,
and baseline capture — over SMB remote registry and SNTP. No WinRM, no RSAT,
no agents to deploy. Built to scan hundreds of domain controllers concurrently
and report exceptions, not noise.

```powershell
# Not yet published to the PowerShell Gallery (see Status below) — import from a checkout:
Import-Module ./WinTimeHealth/WinTimeHealth.psd1

Get-WinTimeConfig -Forest -CsvPath .\config.csv
Get-WinTimeHealth -Forest -HtmlPath .\health.html
```

## Why

`W32Time` has ~70 registry values spread across five subkeys, a Group Policy
twin tree that doesn't always write where you'd guess, and one host per forest
(the root PDC emulator) that is *supposed* to look different from every other
DC. Auditing it by hand across a real forest means either trusting `w32tm
/query` output DC-by-DC or writing a one-off script that hardcodes a handful
of settings someone remembered to check. WinTimeHealth instead drives
everything off a maintained reference database of the documented registry
surface, so the audit logic has no hardcoded per-key knowledge and stays
correct as Microsoft's guidance evolves.

## Cmdlets

| Cmdlet | What it does |
| --- | --- |
| `Get-WinTimeConfig` | Scans the `W32Time` registry tree (and its Group Policy twin) on every targeted DC, resolves the effective expected value for each setting — applied policy, then a supplied baseline, then the documented Microsoft default for that role/OS — and reports drift. |
| `Get-WinTimeHealth` | Live signal sweep: service state, NTP reachability, offset from the forest-root PDC emulator, stratum sanity, sync source, time-since-last-sync, announce flags, VM host-sync posture, referenceID sync-loop detection, and secure time seeding — 10 checks total, selectable individually. |
| `Export-WinTimeConfigBaseline` | Captures a consensus configuration from known-good reference DCs into a portable, regedit-compatible `.reg` file (plus a separate file for the PDC emulator's legitimately-different settings), for `Get-WinTimeConfig` to compare the rest of the forest against later. |

All three discover their targets the same way: one LDAP query against the
forest's configuration naming context, then `-Included*`/`-Excluded*` filters
(domains, sites, domain controllers — wildcards supported) narrow it down.
Every `Get-*` cmdlet streams typed record objects and writes nothing to disk
unless you ask for `-CsvPath`/`-HtmlPath`; a compact console summary groups
findings *by setting*, not by server, so a misconfigured GPO shows up as one
line with a server count instead of 40 identical-looking rows.

## Examples

```powershell
# Forest-wide config audit against documented Microsoft defaults
Get-WinTimeConfig -Forest -CsvPath .\w32time-config.csv

# Compare against a captured golden baseline instead of MS defaults
Get-WinTimeConfig -DCBaselineFile .\dc-baseline.reg -HtmlPath .\report.html

# Re-scan only the servers that failed last time
Import-Csv .\scan.failures.csv | Get-WinTimeConfig -RetryCount 5 -NoSummary

# One child domain, alternate credential, drift only
Get-WinTimeConfig -IncludedDomains 'emea.*' -Credential (Get-Credential) |
    Where-Object IsDrift

# Full health sweep
Get-WinTimeHealth -Forest -CsvPath .\health.csv

# Just offset/stratum, tighter failure threshold
Get-WinTimeHealth -IncludedHealthChecks Offset, Stratum -OffsetFailMilliseconds 1000

# Capture a baseline from two known-good DCs
Export-WinTimeConfigBaseline -DomainControllers dc1.corp.example.com, dc2.corp.example.com -OutFile .\dc-baseline.reg

# Preview a forest-wide baseline export without writing anything
Export-WinTimeConfigBaseline -ExportAllDCs -OutFile .\forest-baseline.reg -WhatIf
```

`Get-Help Get-WinTimeConfig -Full` (and the same for the other two cmdlets)
has the complete parameter reference and more examples.

## How it decides what's "wrong"

For every registry value, `Get-WinTimeConfig` resolves an expected value in
this order:

1. **Applied Group Policy** — if the value's policy twin is set under
   `HKLM\SOFTWARE\Policies\Microsoft\W32Time\...`, that's authoritative, and a
   local value that disagrees is drift.
2. **Your baseline** — if you passed `-DCBaselineFile`/`-RootPDCEBaselineFile`,
   those captured values are the expectation.
3. **The documented Microsoft default** — otherwise, the reference database's
   per-role (DC / member / standalone), per-OS-build default.

The forest-root PDC emulator is auto-detected and its legitimately-different
settings (`Type`, `NtpServer`, `AnnounceFlags`) are never flagged against the
DC baseline unless you supply a PDCe-specific baseline for it. Values the
service manages itself (`ServiceDll`, `LastKnownGoodTime`, and similar) are
excluded from drift comparison, though a few of them are still compared as
tamper checks. Anything found in the registry that isn't in the database at
all is reported as `Undocumented` — and promoted into the console summary
when it looks security-relevant (an unrecognized time-provider subkey, a
`*Dll*` value, an unrecognized policy value).

## Repository layout

| Path | Purpose |
| --- | --- |
| `WinTimeHealth/` | The module: `Public/` (3 cmdlets), `Private/` (17 supporting functions — discovery, scan engine, comparison, NTP client, .reg parser/writer, report rendering), `Data/W32TimeKeys.yaml` (the reference database), `Formats/`, `Tests/` (Pester 5). |
| `docs/DESIGN.md` | The implementation contract: object model, cmdlet parameter surface, scan-engine and credential-handling semantics, health-check definitions, `.reg` format details, output-safety requirements. Start here to understand *why* something works the way it does. |
| `docs/SOURCES.md` | Where the database's facts come from, and how to refresh it when Microsoft updates its documentation. |
| `CHANGELOG.md` | Keep-a-Changelog format. |

## The reference database

`WinTimeHealth/Data/W32TimeKeys.yaml` is the single source of truth the
module runs on — no registry key names or default values are hardcoded in
the cmdlets. Each of its ~70 entries records:

- registry path, value name, and type
- **class**: `config` (admin-settable), `internal` (service-managed — a
  handful are still compared as tamper checks), or `diagnostic`
- **per-role defaults**: domain controller, domain member, standalone, and
  the forest-root PDC emulator, plus build-range overrides where Microsoft's
  default has changed across OS versions (e.g. Server 2025)
- **GPO mapping**: the policy's registry twin path (verified against the real
  `w32time.admx`, not just the coarser Group Policy documentation table) and
  the value the policy presets when enabled — several presets differ from the
  out-of-box OS default, which the module calls out explicitly
- **compare policy**: `exact`, `pdce-exempt`, or `ignore`, which is what lets
  the comparison engine stay free of hardcoded per-key logic

The underlying facts come from Microsoft's public documentation, but every
description is paraphrased in the database's own wording rather than copied,
so the whole file is MIT-licensed along with the rest of the repository; see
`docs/SOURCES.md` for full attribution and how to refresh it as Microsoft's
docs change.

## Status

Implemented and passing its full test suite (Pester, PSScriptAnalyzer clean)
in a Linux development sandbox. It has **not yet been exercised against a
real Windows/Active Directory environment** — remote registry access, SMB
credential handling, and live NTP queries are logic-verified but unproven end
to end on actual domain controllers. Not yet published to the PowerShell
Gallery. Treat a first run as a pilot: start against a handful of DCs before
pointing it at the whole forest.

## License

MIT — see `LICENSE`. The reference database restates public factual
information from Microsoft documentation; see `docs/SOURCES.md` for
attribution.
