# Sources

The `W32TimeKeys.yaml` database is derived from public Microsoft Learn
documentation (facts restated in original wording). The upstream markdowns are
**not committed** — MS doc content is CC BY 4.0, and keeping this repo purely
MIT avoids mixed licensing. Working snapshots may be downloaded into
`docs/ms-src/` (gitignored) when refreshing the database.

Last verified: **2026-07-11** against `MicrosoftDocs/windowsserverdocs` @ `main`
(doc `ms.date: 09/18/2025`).

| Topic | Source |
| --- | --- |
| Registry reference, GPO mappings, per-role defaults | [Windows Time Service Tools and Settings](https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) |
| Architecture, domain hierarchy, PDC emulator behavior | [How the Windows Time Service Works](https://learn.microsoft.com/windows-server/networking/windows-time-service/how-the-windows-time-service-works) |
| Accuracy improvements, VMICTimeProvider guidance | [Accurate Time for Windows Server 2016](https://learn.microsoft.com/windows-server/networking/windows-time-service/accurate-time) |
| High-accuracy configuration | [Configuring Systems for High Accuracy](https://learn.microsoft.com/windows-server/networking/windows-time-service/configuring-systems-for-high-accuracy) |
| 2016 algorithm changes | [Windows Server 2016 Improvements](https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-server-2016-improvements) |

Markdown originals: <https://github.com/MicrosoftDocs/windowsserverdocs/tree/main/WindowsServerDocs/networking/windows-time-service>

**GPO `policy_path` authority**: the element `key` attributes in `w32time.admx`
(verified against two independent mirrors — nsacyber/Windows-Secure-Host-Baseline
and mxk/windows-secure-group-policy — and MS Learn's ADMX_W32Time policy CSP page),
NOT the coarser Group Policy mapping table in Tools-and-Settings. Notably the ADMX
gives `NtpServer`/`Type` explicit key overrides to `Policies\...\W32time\Parameters`,
while all Global Configuration Settings elements (including the Chain* values and
`RequireSecureTimeSyncRequests`, whose operational home is `TimeProviders\NtpServer`)
write under `Policies\...\W32time\Config`.

## Updating

1. Re-download the markdowns into `docs/ms-src/` (gitignored) and use the
   upstream repo's git history to see what changed since `verified:`.
2. Apply factual changes to `W32TimeKeys.yaml`, bump its `verified:` date.
3. Note anything version-specific under the affected key's `os:` map.

Entries not present in the primary Tools-and-Settings registry table are
marked as such in their `notes:` field and sourced individually:

| Entry | Source |
| --- | --- |
| `Services\W32Time\Start` (Manual + domain-join trigger-start on every role incl. DCs) | Microsoft Support [KB2385818](https://learn.microsoft.com/troubleshoot/windows-client/active-directory/w32time-not-start-on-workgroup) — "W32Time doesn't start on a workgroup computer" |
| `TimeProviders\NtpServer\Enabled` dc default (dcpromo turns it on) | Official W32Time team blog (archived), ["Configuring a Standalone NtpServer"](https://learn.microsoft.com/archive/blogs/w32time/configuring-a-standalone-ntpserver) |
| `TimeProviders\VMICTimeProvider\DllName` / `InputProvider` | A real `w32tm /query /configuration` output on a Microsoft Q&A thread ("VMIC Time Provider not found"), plus the Microsoft Community Hub AskDS blog ["Synchronizing Time on Virtualized AD DS Environments"](https://techcommunity.microsoft.com/blog/askds/synchronizing-time-on-virtualized-ad-ds-environments---vmictimeprovider-vs-ad/4210695) |
| `Services\W32Time` root install values (`Type`, `ErrorControl`, `ObjectName`, `ImagePath`, `DisplayName`, `Description`) | **Not documented by Microsoft for W32Time specifically** (confirmed absent even from the older archived [Windows Server 2003 registry-entries reference](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773263(v=ws.10))) — these are generic Windows service-installation artifacts. Corroborated only by independent non-Microsoft sources; treat with correspondingly lower confidence than the rest of the database. |
| Runtime subtrees (`SecureTimeLimits`, etc.) | Observed behavior, not documented. |
