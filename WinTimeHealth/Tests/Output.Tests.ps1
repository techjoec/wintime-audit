# Output layer tests: CSV/HTML safety, report file encoding, console summary,
# format file integrity (DESIGN sections 3, 10, 11).
Set-StrictMode -Version Latest

BeforeAll {
    Set-StrictMode -Version Latest
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $moduleRoot (Join-Path 'Private' 'ConvertTo-WinTimeCsvSafe.ps1'))
    . (Join-Path $moduleRoot (Join-Path 'Private' 'Write-WinTimeReportFile.ps1'))
    . (Join-Path $moduleRoot (Join-Path 'Private' 'New-WinTimeHtmlReport.ps1'))
    . (Join-Path $moduleRoot (Join-Path 'Private' 'Write-WinTimeSummary.ps1'))
    $script:FormatFilePath = Join-Path $moduleRoot (Join-Path 'Formats' 'WinTimeHealth.Format.ps1xml')

    function Get-TestSummaryModel {
        param(
            [string]$CsvPath
        )
        $model = @{
            Title = 'WinTimeHealth configuration audit'
            ForestName = 'corp.example.com'
            Timestamp = '2026-07-11T10:00:00Z'
            BaselineDescription = 'dc-baseline.reg (captured 2026-07-01 from dc01)'
            PdceFqdn = 'pdc01.corp.example.com'
            PdceDetected = $true
            Totals = @{ Targets = 10; Scanned = 8; Failed = 2; AuthFailed = 1; ServersWithDrift = 3 }
            DomainRows = @(
                @{ Domain = 'corp.example.com'; Dcs = 6; Scanned = 5; Clean = 3; Drift = 2; Failed = 1 },
                @{ Domain = 'emea.corp.example.com'; Dcs = 4; Scanned = 3; Clean = 2; Drift = 1; Failed = 1 }
            )
            DriftGroups = @(
                @{
                    Key = 'W32Time\Config\MaxPosPhaseCorrection'
                    Expected = '172800'
                    ExpectedSource = 'Baseline'
                    RoleScope = '[DC]'
                    Found = '4294967295'
                    Servers = @('dc1', 'dc2', 'dc3', 'dc4', 'dc5', 'dc6', 'dc7', 'dc8')
                    MoreCount = 2
                    GpoHint = "matches GPO preset for 'Global Configuration Settings'"
                }
            )
            PromotedFindings = @(
                @{ Server = 'dc3.corp.example.com'; KeyPath = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Evil'; ValueName = 'ServiceDll'; Reason = 'unknown time provider subkey' }
            )
            Unreachable = @(
                @{ Server = 'dc9.corp.example.com'; Error = 'Timeout'; Attempts = 4 }
            )
        }
        if ($PSBoundParameters.ContainsKey('CsvPath') -and $CsvPath) {
            $model['CsvPath'] = $CsvPath
        } else {
            $model['CsvPath'] = $null
        }
        return $model
    }

    # Pseudo German culture: real de-DE when the runtime has ICU data,
    # otherwise an invariant clone with German separators (this environment
    # runs globalization-invariant, where de-DE cannot be constructed).
    function Get-TestGermanCulture {
        $culture = $null
        try { $culture = [System.Globalization.CultureInfo]::new('de-DE') } catch { $culture = $null }
        if ($null -eq $culture) { $culture = [System.Globalization.CultureInfo]::InvariantCulture }
        $culture = [System.Globalization.CultureInfo]$culture.Clone()
        $culture.NumberFormat.NumberDecimalSeparator = ','
        $culture.NumberFormat.NumberGroupSeparator = '.'
        return $culture
    }
}

Describe 'ConvertTo-WinTimeCsvSafe' {

    It 'prefixes a formula-injection payload with a single quote' {
        $record = [pscustomobject]@{ Server = 'dc1'; Data = '=cmd|/C calc' }
        $lines = ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Server', 'Data'
        $parsed = $lines | ConvertFrom-Csv
        $parsed.Data | Should -Be "'=cmd|/C calc"
    }

    It 'guards every OWASP leading character (<leader>)' -ForEach @(
        @{ Leader = '=' }, @{ Leader = '+' }, @{ Leader = '-' }, @{ Leader = '@' }
    ) {
        $record = [pscustomobject]@{ Field = ($Leader + 'payload') }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Field') | ConvertFrom-Csv
        $parsed.Field | Should -Be ("'" + $Leader + 'payload')
    }

    It 'does not quote-prefix harmless strings' {
        $record = [pscustomobject]@{ Field = 'NtpServer' }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Field') | ConvertFrom-Csv
        $parsed.Field | Should -Be 'NtpServer'
    }

    It 'strips CR, LF and TAB to spaces' {
        $record = [pscustomobject]@{ Note = "a`r`nb`tc" }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Note') | ConvertFrom-Csv
        $parsed.Note | Should -Be 'a  b c'
    }

    It 'joins MultiString data with a pipe' {
        $record = [pscustomobject]@{ Data = [string[]]@('0.pool.ntp.org,0x8', '1.pool.ntp.org,0x8') }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Data') | ConvertFrom-Csv
        $parsed.Data | Should -Be '0.pool.ntp.org,0x8|1.pool.ntp.org,0x8'
    }

    It 'flattens hashtable Data to compact JSON' {
        $record = [pscustomobject]@{ Data = @{ Offset = 12; Source = 'pdc01' } }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Data') | ConvertFrom-Csv
        $parsed.Data | Should -Match '^\{'
        $parsed.Data | Should -Match '"Offset":12'
        $parsed.Data | Should -Match '"Source":"pdc01"'
    }

    It 'renders numbers with InvariantCulture under a German culture' {
        $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
        try {
            [System.Globalization.CultureInfo]::CurrentCulture = Get-TestGermanCulture
            # Control probe: the German culture really is in effect.
            ([double]1234.5).ToString() | Should -Be '1234,5'
            $record = [pscustomobject]@{ OffsetMs = [double]1234.5; Dword = [uint32]4294967295 }
            $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'OffsetMs', 'Dword') | ConvertFrom-Csv
            $parsed.OffsetMs | Should -Be '1234.5'
            $parsed.Dword | Should -Be '4294967295'
        } finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $originalCulture
        }
    }

    It 'round-trips a 0xFFFFFFFF DWORD as unsigned decimal' {
        $record = [pscustomobject]@{ Data = [uint32]4294967295 }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Data') | ConvertFrom-Csv
        $parsed.Data | Should -Be '4294967295'
    }

    It 'renders DateTime values as ISO-8601' {
        $stamp = [datetime]::new(2026, 7, 11, 10, 30, 0, [System.DateTimeKind]::Utc)
        $record = [pscustomobject]@{ Timestamp = $stamp }
        $parsed = (ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'Timestamp') | ConvertFrom-Csv
        $parsed.Timestamp | Should -Be '2026-07-11T10:30:00.0000000Z'
    }

    It 'keeps the requested column order and fills missing properties with empty fields' {
        $record = [pscustomobject]@{ B = 'two'; A = 'one' }
        $lines = @(ConvertTo-WinTimeCsvSafe -InputObject @($record) -ColumnOrder 'A', 'B', 'C')
        $lines[0] | Should -Be '"A","B","C"'
        $parsed = $lines | ConvertFrom-Csv
        $parsed.A | Should -Be 'one'
        $parsed.B | Should -Be 'two'
        $parsed.C | Should -Be ''
    }

    It 'emits a header-only line for empty input' {
        $lines = @(ConvertTo-WinTimeCsvSafe -InputObject @() -ColumnOrder 'A', 'B')
        $lines.Count | Should -Be 1
        $lines[0] | Should -Be '"A","B"'
    }
}

Describe 'Write-WinTimeReportFile' {

    It 'writes UTF-8 with BOM and returns FileInfo' {
        $path = Join-Path $TestDrive 'report-bom.txt'
        $fileInfo = Write-WinTimeReportFile -Path $path -Content 'hello'
        $fileInfo | Should -BeOfType ([System.IO.FileInfo])
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes.Count | Should -BeGreaterOrEqual 3
        $bytes[0] | Should -Be 239  # 0xEF
        $bytes[1] | Should -Be 187  # 0xBB
        $bytes[2] | Should -Be 191  # 0xBF
    }

    It 'throws FileExists when the file exists and -Force is absent' {
        $path = Join-Path $TestDrive 'report-exists.txt'
        Set-Content -LiteralPath $path -Value 'original'
        { Write-WinTimeReportFile -Path $path -Content 'new' } |
            Should -Throw -ErrorId 'FileExists,Write-WinTimeReportFile'
        Get-Content -LiteralPath $path -Raw | Should -Match 'original'
    }

    It 'overwrites with -Force' {
        $path = Join-Path $TestDrive 'report-force.txt'
        Set-Content -LiteralPath $path -Value 'original'
        $null = Write-WinTimeReportFile -Path $path -Content 'replaced' -Force
        Get-Content -LiteralPath $path -Raw | Should -Match 'replaced'
        Get-Content -LiteralPath $path -Raw | Should -Not -Match 'original'
    }

    It 'joins an array of lines with newlines' {
        $path = Join-Path $TestDrive 'report-lines.txt'
        $null = Write-WinTimeReportFile -Path $path -Content @('line1', 'line2')
        @(Get-Content -LiteralPath $path).Count | Should -Be 2
    }
}

Describe 'New-WinTimeHtmlReport' {

    It 'encodes a script payload in value name and data' {
        $path = Join-Path $TestDrive 'inject.html'
        $payload = '<script>alert(1)</script>'
        $records = @(
            [pscustomobject]@{
                Server = 'dc1.corp.example.com'; Domain = 'corp.example.com'
                KeyPath = 'SYSTEM\CurrentControlSet\Services\W32Time\Config'
                ValueName = $payload; Type = 'REG_SZ'; Status = 'Undocumented'
                Data = $payload; Expected = $null; ExpectedSource = $null; Note = $null
            }
        )
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -ConfigRecords $records -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Not -Match '<script'
        $html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') | Should -BeTrue
    }

    It 'encodes hostile strings arriving through the summary model' {
        $path = Join-Path $TestDrive 'inject-model.html'
        $model = Get-TestSummaryModel
        $model['Title'] = '<script>alert(2)</script>'
        $model['DriftGroups'] = @(
            @{
                Key = '<script>alert(3)</script>'; Expected = '1'; ExpectedSource = 'Baseline'
                Found = '<img onerror=alert(4) src=x>'; Servers = @('<b>dc1</b>'); MoreCount = 0
                GpoHint = '<script>alert(5)</script>'
            }
        )
        $null = New-WinTimeHtmlReport -Model $model -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<img'
        $html | Should -Not -Match '<b>'
        $html.Contains('&lt;script&gt;alert(2)&lt;/script&gt;') | Should -BeTrue
        $html.Contains('&lt;script&gt;alert(3)&lt;/script&gt;') | Should -BeTrue
    }

    It 'references no external resources' {
        $path = Join-Path $TestDrive 'noext.html'
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel -CsvPath 'out.csv') -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Not -Match '(?i)(src|href)\s*=\s*["'']?\s*https?:'
        $html | Should -Not -Match '(?i)@import'
        $html | Should -Not -Match '(?i)url\s*\('
    }

    It 'mirrors the pyramid sections and uses details collapsibles' {
        $path = Join-Path $TestDrive 'sections.html'
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Match 'prefers-color-scheme'
        $html | Should -Match '<details>'
        $html | Should -Match 'Drift by setting'
        $html | Should -Match 'Undocumented values \(security review\)'
        $html | Should -Match 'Unreachable servers'
        $html.Contains('corp.example.com') | Should -BeTrue
        $html.Contains('pdc01.corp.example.com') | Should -BeTrue
    }

    It 'caps the records table at 5000 rows with a note' {
        $path = Join-Path $TestDrive 'cap.html'
        $records = foreach ($i in 1..5001) {
            [pscustomobject]@{
                Server = 'cap-test'; Domain = 'corp.example.com'
                KeyPath = 'SYSTEM\CurrentControlSet\Services\W32Time\Config'
                ValueName = 'Value' + $i; Type = 'REG_DWORD'; Status = 'Match'
                Data = [uint32]1; Expected = [uint32]1; ExpectedSource = 'MSDefault'; Note = ''
            }
        }
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -ConfigRecords $records -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Match 'Showing first 5000 of 5001'
        ([regex]::Matches($html, '>cap-test<')).Count | Should -Be 5000
    }

    It 'flattens MultiString and hashtable data and renders big DWORDs with hex' {
        $path = Join-Path $TestDrive 'flatten.html'
        $config = @(
            [pscustomobject]@{
                Server = 'dc1'; Domain = 'corp.example.com'; KeyPath = 'k'; ValueName = 'NtpServer'
                Type = 'REG_MULTI_SZ'; Status = 'Match'; Data = [string[]]@('s1', 's2')
                Expected = [uint32]4294967295; ExpectedSource = 'Baseline'; Note = ''
            }
        )
        $health = @(
            [pscustomobject]@{
                Server = 'dc1'; Domain = 'corp.example.com'; Check = 'Offset'; Status = 'Pass'
                Detail = 'offset 12ms'; Data = @{ OffsetMs = 12 }
            }
        )
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -ConfigRecords $config -HealthRecords $health -Path $path
        $html = Get-Content -LiteralPath $path -Raw
        $html.Contains('s1|s2') | Should -BeTrue
        $html.Contains('4294967295 (0xFFFFFFFF)') | Should -BeTrue
        $html | Should -Match '&quot;OffsetMs&quot;:12'
    }

    It 'honors Write-WinTimeReportFile overwrite semantics (-Force passthrough)' {
        $path = Join-Path $TestDrive 'force.html'
        $null = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -Path $path
        { New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -Path $path } |
            Should -Throw -ErrorId 'FileExists,Write-WinTimeReportFile'
        $result = New-WinTimeHtmlReport -Model (Get-TestSummaryModel) -Path $path -Force
        $result | Should -BeOfType ([System.IO.FileInfo])
    }
}

Describe 'Write-WinTimeSummary' {

    BeforeEach {
        $script:HostLines = [System.Collections.Generic.List[string]]::new()
        Mock -CommandName Write-Host -MockWith { $script:HostLines.Add([string]$Object) }
    }

    It 'emits nothing when -NoSummary is set' {
        Write-WinTimeSummary -Model (Get-TestSummaryModel) -NoSummary
        Should -Invoke -CommandName Write-Host -Exactly -Times 0
    }

    It 'renders the pyramid with unicode glyphs on a UTF-8 console' {
        $originalEncoding = [System.Console]::OutputEncoding
        try {
            [System.Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
            Write-WinTimeSummary -Model (Get-TestSummaryModel -CsvPath 'out.csv')
        } finally {
            [System.Console]::OutputEncoding = $originalEncoding
        }
        $text = $script:HostLines -join "`n"
        $text | Should -Match 'WinTimeHealth configuration audit'
        $text | Should -Match ([regex]::Escape('Forest: corp.example.com'))
        $text | Should -Match ([regex]::Escape('Baseline: dc-baseline.reg'))
        $text | Should -Match ([regex]::Escape('PDCe: pdc01.corp.example.com'))
        $text | Should -Match ([regex]::Escape('Targets: 10   Scanned: 8   Failed: 2 (1 auth)   Servers with drift: 3'))
        $text | Should -Match 'Domain\s+DCs\s+Scanned\s+Clean\s+Drift\s+Failed'
        $text | Should -Match 'emea\.corp\.example\.com'
        $text | Should -Match ([regex]::Escape('W32Time\Config\MaxPosPhaseCorrection - expected 172800 (Baseline) [DC]'))
        # 8 servers, 6 shown, +2 truncated +2 MoreCount = 4 hidden; CSV written.
        $text | Should -Match ([regex]::Escape('found 4294967295 on 10: dc1, dc2, dc3, dc4, dc5, dc6 (+4 more, see out.csv)'))
        $text | Should -Match ([regex]::Escape("hint: matches GPO preset for 'Global Configuration Settings'"))
        $text | Should -Match 'Undocumented values \(security review\)'
        $text | Should -Match ([regex]::Escape('TimeProviders\Evil\ServiceDll - unknown time provider subkey'))
        $text | Should -Match ([regex]::Escape('dc9.corp.example.com - Timeout (after 4 attempts)'))
        $text | Should -Match ([regex]::Escape('Full records: out.csv'))
        $text | Should -Match ([regex]::Escape([string][char]0x2716))
    }

    It 'falls back to ASCII glyphs on a non-UTF console' {
        $originalEncoding = [System.Console]::OutputEncoding
        try {
            [System.Console]::OutputEncoding = [System.Text.Encoding]::ASCII
            Write-WinTimeSummary -Model (Get-TestSummaryModel)
        } finally {
            [System.Console]::OutputEncoding = $originalEncoding
        }
        $text = $script:HostLines -join "`n"
        $text | Should -Not -Match ([regex]::Escape([string][char]0x2716))
        $text | Should -Not -Match ([regex]::Escape([string][char]0x26A0))
        @($script:HostLines | Where-Object { $_ -match '^ X ' }).Count | Should -BeGreaterThan 0
        # No CSV was written: the re-run hint variant must be used.
        $text | Should -Match ([regex]::Escape('(+4 more - re-run with -CsvPath)'))
    }

    It 'warns when PDCe detection failed' {
        $model = Get-TestSummaryModel
        $model['PdceDetected'] = $false
        $model['PdceFqdn'] = $null
        Write-WinTimeSummary -Model $model
        ($script:HostLines -join "`n") | Should -Match 'PDCe not detected - PdceExempt handling disabled'
    }

    It 'reports a clean run without drift lines' {
        $model = Get-TestSummaryModel
        $model['DriftGroups'] = @()
        $model['PromotedFindings'] = @()
        $model['Unreachable'] = @()
        $model['Totals'] = @{ Targets = 5; Scanned = 5; Failed = 0; AuthFailed = 0; ServersWithDrift = 0 }
        Write-WinTimeSummary -Model $model
        $text = $script:HostLines -join "`n"
        $text | Should -Match 'no drift detected'
        $text | Should -Not -Match 'Unreachable'
        $text | Should -Not -Match 'security review'
    }
}

Describe 'WinTimeHealth.Format.ps1xml' {

    It 'parses as XML and selects the three record types' {
        $xml = [xml](Get-Content -LiteralPath $script:FormatFilePath -Raw)
        $typeNames = @($xml.SelectNodes('//ViewSelectedBy/TypeName') | ForEach-Object { $_.InnerText })
        $typeNames | Should -Contain 'WinTime.ConfigRecord'
        $typeNames | Should -Contain 'WinTime.HealthRecord'
        $typeNames | Should -Contain 'WinTime.ScanStatus'
        # one table + one list view per type
        foreach ($typeName in 'WinTime.ConfigRecord', 'WinTime.HealthRecord', 'WinTime.ScanStatus') {
            @($typeNames | Where-Object { $_ -eq $typeName }).Count | Should -Be 2
        }
    }

    It 'defines the DESIGN table columns' {
        $xml = [xml](Get-Content -LiteralPath $script:FormatFilePath -Raw)
        $configColumns = @($xml.SelectNodes("//View[Name='WinTime.ConfigRecord.Table']//TableColumnItem/PropertyName") | ForEach-Object { $_.InnerText })
        ($configColumns -join ',') | Should -Be 'Server,ValueName,Status,Data,Expected,ExpectedSource'
        $healthColumns = @($xml.SelectNodes("//View[Name='WinTime.HealthRecord.Table']//TableColumnItem/PropertyName") | ForEach-Object { $_.InnerText })
        ($healthColumns -join ',') | Should -Be 'Server,Check,Status,Detail'
        $scanColumns = @($xml.SelectNodes("//View[Name='WinTime.ScanStatus.Table']//TableColumnItem/PropertyName") | ForEach-Object { $_.InnerText })
        ($scanColumns -join ',') | Should -Be 'Server,Success,Attempts,ErrorClass,LastError'
    }

    It 'has matching header and column counts in every table view' {
        $xml = [xml](Get-Content -LiteralPath $script:FormatFilePath -Raw)
        $tableViews = @($xml.SelectNodes('//View[TableControl]'))
        $tableViews.Count | Should -Be 3
        foreach ($view in $tableViews) {
            $headerCount = $view.SelectNodes('TableControl/TableHeaders/TableColumnHeader').Count
            $columnCount = $view.SelectNodes('TableControl/TableRowEntries/TableRowEntry/TableColumnItems/TableColumnItem').Count
            $columnCount | Should -Be $headerCount
        }
    }

    It 'loads via Update-FormatData' {
        { Update-FormatData -PrependPath $script:FormatFilePath -ErrorAction Stop } | Should -Not -Throw
    }
}
