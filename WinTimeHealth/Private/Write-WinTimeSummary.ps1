function Write-WinTimeSummary {
    <#
    .SYNOPSIS
    Renders the WinTimeHealth console summary pyramid to the host.

    .DESCRIPTION
    The single sanctioned Write-Host site in the module (DESIGN sections 3 and
    10): host-channel UX printed once after a scan completes. Renders, in
    order: header (title, forest, run timestamp, baseline provenance, PDCe),
    totals, per-domain table, drift grouped by setting, promoted undocumented
    security findings, and unreachable servers.

    Unicode glyphs are used only when the console output encoding is
    UTF-8/UTF-16 capable; otherwise ASCII fallbacks (X ! = -) are used.
    Colors are applied via Write-Host -ForegroundColor only (no ANSI escapes).
    Server name lists show the first 6 entries, then '(+N more, see <csv>)'
    when a CSV was written, else '(+N more - re-run with -CsvPath)'.

    .PARAMETER Model
    Summary model hashtable built by the calling cmdlet:
    @{ Title; ForestName; Timestamp; BaselineDescription; PdceFqdn;
       PdceDetected(bool);
       Totals = @{ Targets; Scanned; Failed; AuthFailed; ServersWithDrift };
       DomainRows = @( @{ Domain; Dcs; Scanned; Clean; Drift; Failed } ... );
       DriftGroups = @( @{ Key; Expected; ExpectedSource; RoleScope; Found;
                           Servers(string[]); MoreCount; GpoHint } ... );
       PromotedFindings = @( @{ Server; KeyPath; ValueName; Reason } ... );
       Unreachable = @( @{ Server; Error; Attempts } ... );
       CsvPath }

    .PARAMETER NoSummary
    Skip rendering entirely (cmdlets pass their -NoSummary switch through).

    .OUTPUTS
    None. Writes to the host channel only.

    .EXAMPLE
    Write-WinTimeSummary -Model $summaryModel -NoSummary:$NoSummary
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'DESIGN sections 3/10: the console pyramid is host-channel UX by design. This is the single sanctioned Write-Host site in the module, suppressible via -NoSummary.')]
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Model,

        [switch]$NoSummary
    )

    if ($NoSummary) { return }

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    # Safe dictionary getter (Contains works on Hashtable and OrderedDictionary
    # alike; DESIGN section 12). Returns $Default for absent or null entries.
    $getValue = {
        param($Table, $Key, $Default)
        if (($null -ne $Table) -and ($Table -is [System.Collections.IDictionary]) -and $Table.Contains($Key) -and ($null -ne $Table[$Key])) {
            return $Table[$Key]
        }
        return $Default
    }

    # Unicode glyphs only on a UTF-capable host (DESIGN section 10).
    $unicodeCapable = $false
    try {
        $outputEncoding = [System.Console]::OutputEncoding
        if ($null -ne $outputEncoding) {
            if (($outputEncoding.CodePage -eq 65001) -or
                ($outputEncoding -is [System.Text.UTF8Encoding]) -or
                ($outputEncoding -is [System.Text.UnicodeEncoding])) {
                $unicodeCapable = $true
            }
        }
    } catch {
        $unicodeCapable = $false  # no console attached: use the ASCII set
    }
    if ($unicodeCapable) {
        $glyphBad = [string][char]0x2716    # heavy multiplication X
        $glyphWarn = [string][char]0x26A0   # warning sign
        $glyphOk = [string][char]0x2713     # check mark
        $glyphDot = [string][char]0x2022    # bullet
    } else {
        $glyphBad = 'X'
        $glyphWarn = '!'
        $glyphOk = '='
        $glyphDot = '-'
    }

    $csvPath = & $getValue $Model 'CsvPath' $null

    # First 6 names, then the (+N more ...) tail per DESIGN section 10.
    $formatServerList = {
        param($Servers, $ExtraHidden)
        $names = @($Servers)
        $shown = @($names | Select-Object -First 6)
        $hidden = ($names.Count - $shown.Count) + [int]$ExtraHidden
        $text = $shown -join ', '
        if ($hidden -gt 0) {
            if ($csvPath) {
                $text = $text + [string]::Format($invariant, ' (+{0} more, see {1})', $hidden, $csvPath)
            } else {
                $text = $text + [string]::Format($invariant, ' (+{0} more - re-run with -CsvPath)', $hidden)
            }
        }
        return $text
    }

    # --- Header ---
    $title = [string](& $getValue $Model 'Title' 'WinTimeHealth')
    $forestName = [string](& $getValue $Model 'ForestName' '(unknown forest)')
    $timestamp = [string](& $getValue $Model 'Timestamp' '')
    $baselineDescription = [string](& $getValue $Model 'BaselineDescription' '')
    $pdceFqdn = [string](& $getValue $Model 'PdceFqdn' '')
    $pdceDetected = [bool](& $getValue $Model 'PdceDetected' $false)

    Write-Host ''
    Write-Host $title -ForegroundColor Cyan
    Write-Host ([string]::Format($invariant, 'Forest: {0}   Run: {1}', $forestName, $timestamp)) -ForegroundColor Cyan
    if ($baselineDescription.Length -gt 0) {
        Write-Host ([string]::Format($invariant, 'Baseline: {0}', $baselineDescription))
    }
    if ($pdceDetected) {
        Write-Host ([string]::Format($invariant, 'PDCe: {0}', $pdceFqdn))
    } else {
        Write-Host ([string]::Format($invariant, '{0} PDCe not detected - PdceExempt handling disabled', $glyphWarn)) -ForegroundColor Yellow
    }
    Write-Host ''

    # --- Totals ---
    $totals = & $getValue $Model 'Totals' @{}
    $targets = [int](& $getValue $totals 'Targets' 0)
    $scanned = [int](& $getValue $totals 'Scanned' 0)
    $failed = [int](& $getValue $totals 'Failed' 0)
    $authFailed = [int](& $getValue $totals 'AuthFailed' 0)
    $serversWithDrift = [int](& $getValue $totals 'ServersWithDrift' 0)

    $totalsLine = [string]::Format($invariant,
        'Targets: {0}   Scanned: {1}   Failed: {2} ({3} auth)   Servers with drift: {4}',
        $targets, $scanned, $failed, $authFailed, $serversWithDrift)
    if ($serversWithDrift -gt 0) {
        $totalsColor = 'Red'
    } elseif ($failed -gt 0) {
        $totalsColor = 'Yellow'
    } else {
        $totalsColor = 'Green'
    }
    Write-Host $totalsLine -ForegroundColor $totalsColor
    Write-Host ''

    # --- Per-domain table ---
    $domainRows = @(& $getValue $Model 'DomainRows' @())
    if ($domainRows.Count -gt 0) {
        $nameWidth = 6
        foreach ($row in $domainRows) {
            $domainName = [string](& $getValue $row 'Domain' '')
            if ($domainName.Length -gt $nameWidth) { $nameWidth = $domainName.Length }
        }
        $rowFormat = '{0,-' + $nameWidth.ToString($invariant) + '}{1,6}{2,9}{3,7}{4,7}{5,8}'
        Write-Host ([string]::Format($invariant, $rowFormat, 'Domain', 'DCs', 'Scanned', 'Clean', 'Drift', 'Failed')) -ForegroundColor Cyan
        foreach ($row in $domainRows) {
            $rowDrift = [int](& $getValue $row 'Drift' 0)
            $rowFailed = [int](& $getValue $row 'Failed' 0)
            $line = [string]::Format($invariant, $rowFormat,
                [string](& $getValue $row 'Domain' ''),
                [int](& $getValue $row 'Dcs' 0),
                [int](& $getValue $row 'Scanned' 0),
                [int](& $getValue $row 'Clean' 0),
                $rowDrift,
                $rowFailed)
            if ($rowDrift -gt 0) {
                $rowColor = 'Red'
            } elseif ($rowFailed -gt 0) {
                $rowColor = 'Yellow'
            } else {
                $rowColor = 'Green'
            }
            Write-Host $line -ForegroundColor $rowColor
        }
        Write-Host ''
    }

    # --- Drift grouped by setting ---
    $driftGroups = @(& $getValue $Model 'DriftGroups' @())
    Write-Host 'Drift by setting:' -ForegroundColor Cyan
    if ($driftGroups.Count -eq 0) {
        Write-Host ([string]::Format($invariant, ' {0} no drift detected', $glyphOk)) -ForegroundColor Green
    } else {
        foreach ($group in $driftGroups) {
            $key = [string](& $getValue $group 'Key' '')
            $expected = & $getValue $group 'Expected' ''
            if ($expected -is [System.Array]) { $expected = $expected -join '|' }
            $expectedSource = [string](& $getValue $group 'ExpectedSource' '')
            $roleScope = [string](& $getValue $group 'RoleScope' '')
            $found = & $getValue $group 'Found' ''
            if ($found -is [System.Array]) { $found = $found -join '|' }
            $servers = @(& $getValue $group 'Servers' @())
            $moreCount = [int](& $getValue $group 'MoreCount' 0)
            $gpoHint = [string](& $getValue $group 'GpoHint' '')

            $headLine = [string]::Format($invariant, ' {0} {1} - expected {2} ({3})', $glyphBad, $key, $expected, $expectedSource)
            if ($roleScope.Length -gt 0) { $headLine = $headLine + ' ' + $roleScope }
            Write-Host $headLine -ForegroundColor Red
            Write-Host ([string]::Format($invariant, '     found {0} on {1}: {2}',
                $found, ($servers.Count + $moreCount), (& $formatServerList $servers $moreCount)))
            if ($gpoHint.Length -gt 0) {
                Write-Host ([string]::Format($invariant, '     hint: {0}', $gpoHint)) -ForegroundColor Yellow
            }
        }
    }
    Write-Host ''

    # --- Promoted undocumented findings (security subset, DESIGN section 4) ---
    $promotedFindings = @(& $getValue $Model 'PromotedFindings' @())
    if ($promotedFindings.Count -gt 0) {
        Write-Host 'Undocumented values (security review):' -ForegroundColor Cyan
        foreach ($finding in $promotedFindings) {
            Write-Host ([string]::Format($invariant, ' {0} {1}  {2}\{3} - {4}',
                $glyphWarn,
                [string](& $getValue $finding 'Server' ''),
                [string](& $getValue $finding 'KeyPath' ''),
                [string](& $getValue $finding 'ValueName' ''),
                [string](& $getValue $finding 'Reason' ''))) -ForegroundColor Yellow
        }
        Write-Host ''
    }

    # --- Unreachable servers ---
    $unreachable = @(& $getValue $Model 'Unreachable' @())
    if ($unreachable.Count -gt 0) {
        Write-Host ([string]::Format($invariant, 'Unreachable ({0}):', $unreachable.Count)) -ForegroundColor Cyan
        $shownRows = @($unreachable | Select-Object -First 6)
        foreach ($entry in $shownRows) {
            Write-Host ([string]::Format($invariant, ' {0} {1} - {2} (after {3} attempts)',
                $glyphBad,
                [string](& $getValue $entry 'Server' ''),
                [string](& $getValue $entry 'Error' ''),
                [int](& $getValue $entry 'Attempts' 0))) -ForegroundColor Red
        }
        $hiddenRows = $unreachable.Count - $shownRows.Count
        if ($hiddenRows -gt 0) {
            if ($csvPath) {
                Write-Host ([string]::Format($invariant, '   (+{0} more, see {1})', $hiddenRows, $csvPath)) -ForegroundColor Red
            } else {
                Write-Host ([string]::Format($invariant, '   (+{0} more - re-run with -CsvPath)', $hiddenRows)) -ForegroundColor Red
            }
        }
        Write-Host ''
    }

    if ($csvPath) {
        Write-Host ([string]::Format($invariant, '{0} Full records: {1}', $glyphDot, $csvPath))
    }
}
