# Changelog

All notable changes to the WinTimeHealth module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- `Get-WinTimeConfig`: forest-wide W32Time configuration audit over SMB remote
  registry (winreg named pipe, TCP/445, no WinRM) - streams
  `WinTime.ConfigRecord` objects, compares against applied GPO policy,
  supplied `.reg` baselines or role/OS-resolved Microsoft defaults, promotes
  undocumented security-relevant values, and prints a grouped drift summary.
- `Get-WinTimeHealth`: two-phase live health engine (registry + SNTP UDP/123)
  with the check catalog Service, NtpQuery, Offset, Stratum, Source,
  LastSync, Announce, Vmic, RefidLoop and SecureTimeSeeding; offsets are
  measured differentially against the forest-root PDCe reference.
- `Export-WinTimeConfigBaseline`: consensus baseline capture from reference
  DCs into an auditable non-mergeable `.reg` file with provenance comments,
  plus a `.pdce.reg` companion for forest-root PDCe-specific values.
- Canonical W32Time registry key database (`Data/W32TimeKeys.yaml`,
  schema_version 2) with per-role and OS-build-conditional defaults, GPO twin
  mapping and comparison semantics.
- Concurrent ThreadJob scan engine with transport-only retries,
  auth-failure lockout protection, per-target IPC$ credential sessions and
  full per-target accounting.
- Injection-safe CSV (OWASP formula guard) and self-contained HTML reports;
  `<base>.failures.csv` companion for one-line re-runs via
  `Import-Csv ... | Get-WinTimeConfig`.
- Default table/list views (`Formats/WinTimeHealth.Format.ps1xml`), console
  summary pyramid with UTF/ASCII glyph fallback, PSScriptAnalyzer settings
  (PSUseCompatibleSyntax 5.1/7.4) and a cross-platform Pester 5 test suite.

[0.1.0]: https://github.com/example/wintime-audit/releases/tag/v0.1.0
