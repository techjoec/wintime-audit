function New-WinTimeHtmlReport {
    <#
    .SYNOPSIS
    Generates the self-contained WinTimeHealth HTML report and writes it to
    disk.

    .DESCRIPTION
    Builds a single self-contained HTML document (inline CSS only, no external
    resources, no script; collapsible sections use the native <details>
    element) mirroring the console pyramid: header, totals, per-domain table,
    drift grouped by setting with collapsible per-finding server lists,
    promoted undocumented findings, unreachable servers, and the full records
    tables (capped at 5000 rows each, with a note when truncated).

    Safety (DESIGN section 10): every interpolated value passes through
    [System.Net.WebUtility]::HtmlEncode; the document is assembled with
    System.Text.StringBuilder; light/dark theming via prefers-color-scheme.
    The file is written through Write-WinTimeReportFile (UTF-8 BOM; existing
    files require -Force).

    .PARAMETER Model
    The summary model hashtable (same contract as Write-WinTimeSummary).

    .PARAMETER ConfigRecords
    Optional WinTime.ConfigRecord objects for the full records table.

    .PARAMETER HealthRecords
    Optional WinTime.HealthRecord objects for the full records table.

    .PARAMETER Path
    Destination file path for the HTML report.

    .PARAMETER Force
    Overwrite an existing file (passed through to Write-WinTimeReportFile).

    .OUTPUTS
    System.IO.FileInfo. The report file that was written.

    .EXAMPLE
    New-WinTimeHtmlReport -Model $model -ConfigRecords $records -Path .\audit.html -Force
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private helper; file overwrite safety is the FileExists/-Force contract enforced by Write-WinTimeReportFile (DESIGN section 10).')]
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Model,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ConfigRecords,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$HealthRecords,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [switch]$Force
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $rowCap = 5000

    # Safe dictionary getter (Contains works on Hashtable and OrderedDictionary).
    $getValue = {
        param($Table, $Key, $Default)
        if (($null -ne $Table) -and ($Table -is [System.Collections.IDictionary]) -and $Table.Contains($Key) -and ($null -ne $Table[$Key])) {
            return $Table[$Key]
        }
        return $Default
    }

    # Record property getter safe under StrictMode.
    $getProperty = {
        param($Record, $Name)
        if ($null -eq $Record) { return $null }
        if ($Record -is [System.Collections.IDictionary]) {
            if ($Record.Contains($Name)) { return $Record[$Name] }
            return $null
        }
        $property = $Record.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
        return $null
    }

    # EVERY interpolated value goes through this (DESIGN section 10).
    $encode = {
        param($Value)
        if ($null -eq $Value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    # Flattens record data for display: arrays join '|', hashtables to compact
    # JSON, large unsigned values decimal with hex in parens (DESIGN section 3),
    # dates ISO-8601, everything else invariant scalar text.
    $formatData = {
        param($Value)
        if ($null -eq $Value) { return '' }
        if ($Value -is [string]) { return $Value }
        if ($Value -is [System.Collections.IDictionary]) {
            return (ConvertTo-Json -InputObject $Value -Compress -Depth 6)
        }
        if ($Value -is [datetime]) { return $Value.ToString('o', $invariant) }
        if ($Value -is [System.DateTimeOffset]) { return $Value.ToString('o', $invariant) }
        if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($element in $Value) {
                if ($null -eq $element) {
                    $parts.Add('')
                } elseif ($element -is [string]) {
                    $parts.Add($element)
                } else {
                    $parts.Add([string]::Format($invariant, '{0}', $element))
                }
            }
            return ($parts -join '|')
        }
        if (($Value -is [uint32]) -or ($Value -is [uint64]) -or ($Value -is [int64])) {
            if ($Value -ge 2147483648) {
                return [string]::Format($invariant, '{0} (0x{1:X})', $Value, $Value)
            }
            return [string]::Format($invariant, '{0}', $Value)
        }
        return [string]::Format($invariant, '{0}', $Value)
    }

    # Whitelist mapping of Status text to a CSS class; class attribute values
    # are never derived from raw data.
    $statusClass = {
        param($Status)
        $statusText = [string]$Status
        if (($statusText -eq 'Drift') -or ($statusText -eq 'Missing') -or ($statusText -eq 'Fail') -or ($statusText -eq 'Error')) { return 'bad' }
        if (($statusText -eq 'Warn') -or ($statusText -eq 'Blocked') -or ($statusText -eq 'Undocumented')) { return 'warn' }
        if (($statusText -eq 'Match') -or ($statusText -eq 'Pass')) { return 'ok' }
        return 'muted'
    }

    $title = [string](& $getValue $Model 'Title' 'WinTimeHealth report')
    $forestName = [string](& $getValue $Model 'ForestName' '(unknown forest)')
    $timestamp = [string](& $getValue $Model 'Timestamp' '')
    $baselineDescription = [string](& $getValue $Model 'BaselineDescription' '')
    $pdceFqdn = [string](& $getValue $Model 'PdceFqdn' '')
    $pdceDetected = [bool](& $getValue $Model 'PdceDetected' $false)
    $csvPath = & $getValue $Model 'CsvPath' $null

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en">')
    [void]$builder.AppendLine('<head>')
    [void]$builder.AppendLine('<meta charset="utf-8" />')
    [void]$builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
    [void]$builder.AppendLine('<title>' + (& $encode $title) + '</title>')
    [void]$builder.AppendLine('<style>')
    [void]$builder.AppendLine(':root { color-scheme: light dark; --bg:#ffffff; --fg:#1b1f24; --muted:#6a737d; --line:#d0d7de; --card:#f6f8fa; --bad:#b42318; --warn:#9a6700; --ok:#1a7f37; }')
    [void]$builder.AppendLine('@media (prefers-color-scheme: dark) { :root { --bg:#0f1419; --fg:#e6edf3; --muted:#8b949e; --line:#30363d; --card:#161b22; --bad:#ff7b72; --warn:#d29922; --ok:#3fb950; } }')
    [void]$builder.AppendLine('* { box-sizing: border-box; }')
    [void]$builder.AppendLine('body { margin:1.5rem auto; max-width:75rem; padding:0 1rem; background:var(--bg); color:var(--fg); font-family:"Segoe UI",Arial,sans-serif; font-size:15px; line-height:1.45; }')
    [void]$builder.AppendLine('h1 { font-size:1.4rem; margin-bottom:0.2rem; }')
    [void]$builder.AppendLine('h2 { font-size:1.1rem; margin-top:1.6rem; border-bottom:1px solid var(--line); padding-bottom:0.2rem; }')
    [void]$builder.AppendLine('p.meta { color:var(--muted); margin:0.15rem 0; }')
    [void]$builder.AppendLine('table { border-collapse:collapse; margin:0.6rem 0 1rem; width:100%; }')
    [void]$builder.AppendLine('th, td { border:1px solid var(--line); padding:0.25rem 0.55rem; text-align:left; font-size:0.85rem; vertical-align:top; }')
    [void]$builder.AppendLine('th { background:var(--card); }')
    [void]$builder.AppendLine('.num { text-align:right; }')
    [void]$builder.AppendLine('.bad { color:var(--bad); font-weight:600; }')
    [void]$builder.AppendLine('.warn { color:var(--warn); font-weight:600; }')
    [void]$builder.AppendLine('.ok { color:var(--ok); font-weight:600; }')
    [void]$builder.AppendLine('.muted { color:var(--muted); }')
    [void]$builder.AppendLine('.note { color:var(--muted); font-style:italic; }')
    [void]$builder.AppendLine('details { margin:0.5rem 0; border:1px solid var(--line); border-radius:6px; padding:0.4rem 0.7rem; background:var(--card); }')
    [void]$builder.AppendLine('summary { cursor:pointer; font-weight:600; }')
    [void]$builder.AppendLine('details p { margin:0.5rem 0 0.2rem; word-break:break-word; }')
    [void]$builder.AppendLine('.scroll { overflow-x:auto; }')
    [void]$builder.AppendLine('code { font-family:Consolas,monospace; font-size:0.85em; }')
    [void]$builder.AppendLine('</style>')
    [void]$builder.AppendLine('</head>')
    [void]$builder.AppendLine('<body>')

    # --- Header ---
    [void]$builder.AppendLine('<h1>' + (& $encode $title) + '</h1>')
    [void]$builder.AppendLine('<p class="meta">Forest: ' + (& $encode $forestName) + ' &middot; Run: ' + (& $encode $timestamp) + '</p>')
    if ($baselineDescription.Length -gt 0) {
        [void]$builder.AppendLine('<p class="meta">Baseline: ' + (& $encode $baselineDescription) + '</p>')
    }
    if ($pdceDetected) {
        [void]$builder.AppendLine('<p class="meta">Forest-root PDCe: ' + (& $encode $pdceFqdn) + '</p>')
    } else {
        [void]$builder.AppendLine('<p class="warn">PDCe not detected - PdceExempt handling disabled.</p>')
    }

    # --- Totals ---
    $totals = & $getValue $Model 'Totals' @{}
    $serversWithDrift = [int](& $getValue $totals 'ServersWithDrift' 0)
    [void]$builder.AppendLine('<h2>Totals</h2>')
    [void]$builder.AppendLine('<div class="scroll"><table>')
    [void]$builder.AppendLine('<tr><th>Targets</th><th>Scanned</th><th>Failed</th><th>Auth failed</th><th>Servers with drift</th></tr>')
    [void]$builder.AppendLine('<tr>' +
        '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $totals 'Targets' 0)))) + '</td>' +
        '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $totals 'Scanned' 0)))) + '</td>' +
        '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $totals 'Failed' 0)))) + '</td>' +
        '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $totals 'AuthFailed' 0)))) + '</td>' +
        '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', $serversWithDrift))) + '</td>' +
        '</tr>')
    [void]$builder.AppendLine('</table></div>')

    # --- Per-domain table ---
    $domainRows = @(& $getValue $Model 'DomainRows' @())
    if ($domainRows.Count -gt 0) {
        [void]$builder.AppendLine('<h2>Domains</h2>')
        [void]$builder.AppendLine('<div class="scroll"><table>')
        [void]$builder.AppendLine('<tr><th>Domain</th><th>DCs</th><th>Scanned</th><th>Clean</th><th>Drift</th><th>Failed</th></tr>')
        foreach ($row in $domainRows) {
            $rowDrift = [int](& $getValue $row 'Drift' 0)
            [void]$builder.AppendLine('<tr>' +
                '<td>' + (& $encode ([string](& $getValue $row 'Domain' ''))) + '</td>' +
                '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $row 'Dcs' 0)))) + '</td>' +
                '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $row 'Scanned' 0)))) + '</td>' +
                '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $row 'Clean' 0)))) + '</td>' +
                '<td class="num ' + $(if ($rowDrift -gt 0) { 'bad' } else { 'ok' }) + '">' + (& $encode ([string]::Format($invariant, '{0}', $rowDrift))) + '</td>' +
                '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $row 'Failed' 0)))) + '</td>' +
                '</tr>')
        }
        [void]$builder.AppendLine('</table></div>')
    }

    # --- Drift by setting (collapsible per-finding server lists) ---
    $driftGroups = @(& $getValue $Model 'DriftGroups' @())
    [void]$builder.AppendLine('<h2>Drift by setting</h2>')
    if ($driftGroups.Count -eq 0) {
        [void]$builder.AppendLine('<p class="ok">No drift detected.</p>')
    } else {
        foreach ($group in $driftGroups) {
            $expected = & $formatData (& $getValue $group 'Expected' '')
            $found = & $formatData (& $getValue $group 'Found' '')
            $roleScope = [string](& $getValue $group 'RoleScope' '')
            $servers = @(& $getValue $group 'Servers' @())
            $moreCount = [int](& $getValue $group 'MoreCount' 0)
            $gpoHint = [string](& $getValue $group 'GpoHint' '')

            $summaryLine = '<span class="bad">' + (& $encode ([string](& $getValue $group 'Key' ''))) + '</span>' +
                ' - expected ' + (& $encode $expected) +
                ' (' + (& $encode ([string](& $getValue $group 'ExpectedSource' ''))) + ')'
            if ($roleScope.Length -gt 0) { $summaryLine = $summaryLine + ' ' + (& $encode $roleScope) }
            $summaryLine = $summaryLine + ' - found ' + (& $encode $found) +
                ' on ' + (& $encode ([string]::Format($invariant, '{0}', ($servers.Count + $moreCount)))) + ' server(s)'

            [void]$builder.AppendLine('<details>')
            [void]$builder.AppendLine('<summary>' + $summaryLine + '</summary>')
            $encodedServers = foreach ($server in $servers) { & $encode $server }
            [void]$builder.AppendLine('<p>' + ($encodedServers -join ', ') + '</p>')
            if ($moreCount -gt 0) {
                [void]$builder.AppendLine('<p class="note">+' + (& $encode ([string]::Format($invariant, '{0}', $moreCount))) + ' more server(s) not listed - see the CSV export.</p>')
            }
            if ($gpoHint.Length -gt 0) {
                [void]$builder.AppendLine('<p class="note">Hint: ' + (& $encode $gpoHint) + '</p>')
            }
            [void]$builder.AppendLine('</details>')
        }
    }

    # --- Promoted undocumented findings ---
    $promotedFindings = @(& $getValue $Model 'PromotedFindings' @())
    if ($promotedFindings.Count -gt 0) {
        [void]$builder.AppendLine('<h2>Undocumented values (security review)</h2>')
        [void]$builder.AppendLine('<div class="scroll"><table>')
        [void]$builder.AppendLine('<tr><th>Server</th><th>Key path</th><th>Value name</th><th>Reason</th></tr>')
        foreach ($finding in $promotedFindings) {
            [void]$builder.AppendLine('<tr>' +
                '<td>' + (& $encode ([string](& $getValue $finding 'Server' ''))) + '</td>' +
                '<td><code>' + (& $encode ([string](& $getValue $finding 'KeyPath' ''))) + '</code></td>' +
                '<td><code>' + (& $encode ([string](& $getValue $finding 'ValueName' ''))) + '</code></td>' +
                '<td class="warn">' + (& $encode ([string](& $getValue $finding 'Reason' ''))) + '</td>' +
                '</tr>')
        }
        [void]$builder.AppendLine('</table></div>')
    }

    # --- Unreachable servers ---
    $unreachable = @(& $getValue $Model 'Unreachable' @())
    if ($unreachable.Count -gt 0) {
        [void]$builder.AppendLine('<h2>Unreachable servers</h2>')
        [void]$builder.AppendLine('<div class="scroll"><table>')
        [void]$builder.AppendLine('<tr><th>Server</th><th>Error</th><th>Attempts</th></tr>')
        foreach ($entry in $unreachable) {
            [void]$builder.AppendLine('<tr>' +
                '<td>' + (& $encode ([string](& $getValue $entry 'Server' ''))) + '</td>' +
                '<td class="bad">' + (& $encode ([string](& $getValue $entry 'Error' ''))) + '</td>' +
                '<td class="num">' + (& $encode ([string]::Format($invariant, '{0}', [int](& $getValue $entry 'Attempts' 0)))) + '</td>' +
                '</tr>')
        }
        [void]$builder.AppendLine('</table></div>')
    }

    # --- Full configuration records (capped) ---
    $configRows = @()
    if ($null -ne $ConfigRecords) { $configRows = @($ConfigRecords | Where-Object { $null -ne $_ }) }
    if ($configRows.Count -gt 0) {
        [void]$builder.AppendLine('<h2>Configuration records</h2>')
        if ($configRows.Count -gt $rowCap) {
            [void]$builder.AppendLine('<p class="note">Showing first ' +
                (& $encode ([string]::Format($invariant, '{0}', $rowCap))) + ' of ' +
                (& $encode ([string]::Format($invariant, '{0}', $configRows.Count))) +
                ' records - use the CSV export for the full set.</p>')
            $configRows = @($configRows | Select-Object -First $rowCap)
        }
        [void]$builder.AppendLine('<details open>')
        [void]$builder.AppendLine('<summary>' + (& $encode ([string]::Format($invariant, '{0} record(s)', $configRows.Count))) + '</summary>')
        [void]$builder.AppendLine('<div class="scroll"><table>')
        [void]$builder.AppendLine('<tr><th>Server</th><th>Domain</th><th>Key path</th><th>Value name</th><th>Type</th><th>Status</th><th>Data</th><th>Expected</th><th>Source</th><th>Note</th></tr>')
        foreach ($record in $configRows) {
            $recordStatus = & $getProperty $record 'Status'
            [void]$builder.AppendLine('<tr>' +
                '<td>' + (& $encode (& $getProperty $record 'Server')) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'Domain')) + '</td>' +
                '<td><code>' + (& $encode (& $getProperty $record 'KeyPath')) + '</code></td>' +
                '<td><code>' + (& $encode (& $getProperty $record 'ValueName')) + '</code></td>' +
                '<td>' + (& $encode (& $getProperty $record 'Type')) + '</td>' +
                '<td class="' + (& $statusClass $recordStatus) + '">' + (& $encode $recordStatus) + '</td>' +
                '<td>' + (& $encode (& $formatData (& $getProperty $record 'Data'))) + '</td>' +
                '<td>' + (& $encode (& $formatData (& $getProperty $record 'Expected'))) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'ExpectedSource')) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'Note')) + '</td>' +
                '</tr>')
        }
        [void]$builder.AppendLine('</table></div>')
        [void]$builder.AppendLine('</details>')
    }

    # --- Full health records (capped) ---
    $healthRows = @()
    if ($null -ne $HealthRecords) { $healthRows = @($HealthRecords | Where-Object { $null -ne $_ }) }
    if ($healthRows.Count -gt 0) {
        [void]$builder.AppendLine('<h2>Health records</h2>')
        if ($healthRows.Count -gt $rowCap) {
            [void]$builder.AppendLine('<p class="note">Showing first ' +
                (& $encode ([string]::Format($invariant, '{0}', $rowCap))) + ' of ' +
                (& $encode ([string]::Format($invariant, '{0}', $healthRows.Count))) +
                ' records - use the CSV export for the full set.</p>')
            $healthRows = @($healthRows | Select-Object -First $rowCap)
        }
        [void]$builder.AppendLine('<details open>')
        [void]$builder.AppendLine('<summary>' + (& $encode ([string]::Format($invariant, '{0} record(s)', $healthRows.Count))) + '</summary>')
        [void]$builder.AppendLine('<div class="scroll"><table>')
        [void]$builder.AppendLine('<tr><th>Server</th><th>Domain</th><th>Check</th><th>Status</th><th>Detail</th><th>Data</th></tr>')
        foreach ($record in $healthRows) {
            $recordStatus = & $getProperty $record 'Status'
            [void]$builder.AppendLine('<tr>' +
                '<td>' + (& $encode (& $getProperty $record 'Server')) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'Domain')) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'Check')) + '</td>' +
                '<td class="' + (& $statusClass $recordStatus) + '">' + (& $encode $recordStatus) + '</td>' +
                '<td>' + (& $encode (& $getProperty $record 'Detail')) + '</td>' +
                '<td>' + (& $encode (& $formatData (& $getProperty $record 'Data'))) + '</td>' +
                '</tr>')
        }
        [void]$builder.AppendLine('</table></div>')
        [void]$builder.AppendLine('</details>')
    }

    # --- Footer ---
    if ($csvPath) {
        [void]$builder.AppendLine('<p class="note">Full records CSV: <code>' + (& $encode $csvPath) + '</code></p>')
    }
    [void]$builder.AppendLine('<p class="note">Generated by WinTimeHealth. Report data is recon-grade inventory - handle accordingly.</p>')
    [void]$builder.AppendLine('</body>')
    [void]$builder.AppendLine('</html>')

    Write-Verbose ([string]::Format($invariant, 'New-WinTimeHtmlReport: {0} config record(s), {1} health record(s), {2} drift group(s).', $configRows.Count, $healthRows.Count, $driftGroups.Count))
    return (Write-WinTimeReportFile -Path $Path -Content $builder.ToString() -Force:$Force)
}
