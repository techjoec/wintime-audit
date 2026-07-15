function Get-WinTimeConfig {
    <#
    .SYNOPSIS
    Audits W32Time configuration across domain controllers of an Active
    Directory forest over SMB remote registry, comparing every documented
    value against baselines, applied policy or Microsoft defaults.

    .DESCRIPTION
    Discovers domain controllers with a single LDAP query against the forest
    configuration naming context, scans each DC's W32Time service key
    (recursive), the W32Time policy twin (recursive), the CurrentVersion key
    (OS build) and the SystemInformation key (hypervisor detection) over the
    winreg named pipe (TCP/445, no WinRM), then emits one WinTime.ConfigRecord
    per documented registry value and per undocumented value found inside the
    W32Time trees.

    Expectations cascade per value: an applied policy-twin value wins
    (ExpectedSource Policy), then a supplied baseline (Baseline), then the
    role/OS-resolved Microsoft default (MSDefault). Status is one of Match,
    Drift, NotSet, Missing, PdceExempt, Ignored or Undocumented; IsDrift is
    true exactly for Drift and Missing. The forest-root PDC emulator gets
    pdce-exempt handling; child-domain PDCes are ordinary DCs.

    Scan failures surface as non-terminating errors (FullyQualifiedErrorId
    ScanFailure,Get-WinTimeConfig) carrying a WinTime.ScanStatus object as
    TargetObject, so -ErrorVariable collects machine-readable failures. After
    the records stream, a grouped console summary pyramid is printed to the
    host (suppress with -NoSummary). Optional CSV/HTML reports are written
    with injection-safe encoding; when failures occurred and -CsvPath was
    given, a companion <base>.failures.csv is written for easy re-runs.

    Scanning requires Windows; the module imports on other platforms for
    tooling and tests only.

    .PARAMETER Forest
    Explicit whole-forest anchor. Scanning the entire forest is the default
    behavior; the switch exists to make that intent explicit in scripts.

    .PARAMETER IncludedDomains
    Wildcard patterns of DNS domain names to include (default: all domains).
    Matching is case-insensitive -like. Exclusions always win over inclusions.

    .PARAMETER ExcludedDomains
    Wildcard patterns of DNS domain names to exclude.

    .PARAMETER IncludedSites
    Wildcard patterns of AD site names to include (default: all sites).

    .PARAMETER ExcludedSites
    Wildcard patterns of AD site names to exclude.

    .PARAMETER IncludedDomainControllers
    Wildcard patterns (or exact FQDNs) of domain controllers to include.
    Accepts pipeline input by property name via the aliases Server,
    ComputerName and DnsHostName, so a failures CSV re-runs directly:
    Import-Csv scan.failures.csv | Get-WinTimeConfig.

    .PARAMETER ExcludedDomainControllers
    Wildcard patterns of domain controllers to exclude. Exclude always wins.

    .PARAMETER Credential
    Alternate credential. Establishes an IPC$ session per target before the
    registry hop; never persisted, never placed on a command line.

    .PARAMETER ThrottleLimit
    Maximum concurrent registry scan workers (1-128, default 32).

    .PARAMETER RetryCount
    Retries per target for transport-class failures only (0-10, default 3).
    Access-denied and authentication failures never retry (lockout safety).

    .PARAMETER TimeoutSeconds
    Best-effort per-attempt time budget for one registry read (5-300,
    default 30).

    .PARAMETER RootPDCEBaselineFile
    Optional .reg baseline for the forest-root PDC emulator's pdce-exempt
    values (typically produced by Export-WinTimeConfigBaseline as the
    .pdce.reg companion).

    .PARAMETER DCBaselineFile
    Optional .reg baseline for ordinary DC values. When given without
    -RootPDCEBaselineFile, a sibling <base>.pdce.reg companion is picked up
    automatically if present. Stale or mismatched baseline provenance (age
    over 180 days, module/schema mismatch, OS-cohort mismatch, FSMO transfer)
    produces warnings.

    .PARAMETER CsvPath
    Write all records to this CSV file (injection-guarded). When scan
    failures occurred, also writes <base>.failures.csv.

    .PARAMETER HtmlPath
    Write a self-contained HTML report to this path (all content
    HTML-encoded, no external resources).

    .PARAMETER Force
    Overwrite existing report files.

    .PARAMETER NoSummary
    Suppress the console summary pyramid.

    .EXAMPLE
    PS> Get-WinTimeConfig -Forest -CsvPath .\w32time-config.csv

    Scans every domain controller in the forest against Microsoft defaults,
    streams WinTime.ConfigRecord objects, writes the full record set to CSV
    and prints the grouped drift summary.

    .EXAMPLE
    PS> Get-WinTimeConfig -DCBaselineFile .\dc-baseline.reg -HtmlPath .\report.html

    Compares the forest against a golden baseline captured with
    Export-WinTimeConfigBaseline; the sibling dc-baseline.pdce.reg companion
    is loaded automatically for the forest-root PDCe when present.

    .EXAMPLE
    PS> Import-Csv .\scan.failures.csv | Get-WinTimeConfig -RetryCount 5 -NoSummary

    Re-runs only the servers that failed in a previous scan: the failures CSV
    'Server' column binds to -IncludedDomainControllers by property name.

    .EXAMPLE
    PS> Get-WinTimeConfig -IncludedDomains 'emea.*' -Credential (Get-Credential) | Where-Object IsDrift

    Scans the EMEA child domain under an alternate credential and keeps only
    drifting records (Status Drift or Missing) - the documented one-liner.

    .EXAMPLE
    PS> Get-WinTimeConfig -ExcludedSites 'Branch-*' | ConvertTo-Json -Depth 6

    Skips branch sites and serializes the record stream to JSON (the
    documented JSON pattern; there is no -AsJson switch).

    .OUTPUTS
    WinTime.ConfigRecord. Scan failures are non-terminating errors carrying a
    WinTime.ScanStatus TargetObject.
    #>
    [CmdletBinding()]
    [OutputType('WinTime.ConfigRecord')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Justification = 'Registry/server lookup tables require an explicit OrdinalIgnoreCase (or Ordinal) comparer per DESIGN.md; literal @{} hashtables use culture-aware case-insensitive comparison instead.')]
    param(
        [Parameter()]
        [switch]$Forest,

        [Parameter()]
        [SupportsWildcards()]
        [string[]]$IncludedDomains,

        [Parameter()]
        [SupportsWildcards()]
        [string[]]$ExcludedDomains,

        [Parameter()]
        [SupportsWildcards()]
        [string[]]$IncludedSites,

        [Parameter()]
        [SupportsWildcards()]
        [string[]]$ExcludedSites,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Server', 'ComputerName', 'DnsHostName')]
        [SupportsWildcards()]
        [string[]]$IncludedDomainControllers,

        [Parameter()]
        [SupportsWildcards()]
        [string[]]$ExcludedDomainControllers,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 32,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$RetryCount = 3,

        [Parameter()]
        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 30,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RootPDCEBaselineFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DCBaselineFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$HtmlPath,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$NoSummary
    )

    begin {
        Set-StrictMode -Version Latest
        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        # Pipeline-by-property-name accumulates here; fan-out happens in end{}.
        $pipelineDcs = New-Object 'System.Collections.Generic.List[string]'

        # ---- nested helpers (shared shapes; StrictMode-safe access) ---------

        # Hashtable field access with a default (worker results are hashtables).
        function Get-HashField {
            param($Table, [string]$Name, $Default)
            if (($null -ne $Table) -and ($Table -is [System.Collections.IDictionary]) -and $Table.Contains($Name) -and ($null -ne $Table[$Name])) {
                return $Table[$Name]
            }
            return $Default
        }

        # Registry-tree key lookup with OrdinalIgnoreCase path semantics.
        function Get-TreeKey {
            param([hashtable]$Tree, [string]$Path)
            if ($null -eq $Tree) { return $null }
            if ($Tree.ContainsKey($Path)) { return $Tree[$Path] }
            foreach ($key in $Tree.Keys) {
                if ([string]::Equals([string]$key, $Path, [System.StringComparison]::OrdinalIgnoreCase)) { return $Tree[$key] }
            }
            return $null
        }

        # Value lookup inside one key's name -> @{Kind;Data} map.
        function Get-TreeValueEntry {
            param([hashtable]$KeyValues, [string]$Name)
            if ($null -eq $KeyValues) { return $null }
            if ($KeyValues.ContainsKey($Name)) { return $KeyValues[$Name] }
            foreach ($key in $KeyValues.Keys) {
                if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $KeyValues[$key] }
            }
            return $null
        }

        # Extracts CurrentBuildNumber from a scanned tree; 0 when unknown.
        function Get-OsBuildFromTree {
            param([hashtable]$Tree)
            $currentVersion = Get-TreeKey -Tree $Tree -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            if ($null -eq $currentVersion) { return 0 }
            $entry = Get-TreeValueEntry -KeyValues $currentVersion -Name 'CurrentBuildNumber'
            if ($null -eq $entry -or -not ($entry -is [System.Collections.IDictionary]) -or -not $entry.Contains('Data')) { return 0 }
            $build = 0
            if ([int]::TryParse([string]$entry['Data'], [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$build)) {
                return $build
            }
            return 0
        }

        # Renders a record value for grouping/summary display (decimal with hex
        # in parens for values >= 0x80000000; multi-strings joined with '|').
        function Format-WinTimeValue {
            param($Value)
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            if ($null -eq $Value) { return '(absent)' }
            if ($Value -is [string]) { return $Value }
            if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
                $parts = New-Object 'System.Collections.Generic.List[string]'
                foreach ($element in $Value) { $parts.Add((Format-WinTimeValue -Value $element)) }
                return ($parts -join '|')
            }
            if (($Value -is [uint32]) -or ($Value -is [uint64]) -or ($Value -is [int]) -or ($Value -is [long])) {
                $big = [uint64]0
                try { $big = [uint64]$Value } catch { $big = [uint64]0 }
                # NB: the hex literal 0x80000000 parses as a negative Int32 in
                # PowerShell; comparing a [uint64] against it coerces down to
                # Int32 and the '-ge' is (almost) always true. Use the decimal
                # literal instead (matches New-WinTimeHtmlReport.ps1).
                if ($big -ge 2147483648) {
                    return [string]::Format($culture, '{0} (0x{1:X})', $Value, $big)
                }
                return [string]::Format($culture, '{0}', $Value)
            }
            if ($Value -is [datetime]) { return $Value.ToString('o', $culture) }
            return [string]::Format($culture, '{0}', $Value)
        }

        # Shortens a KeyPath for the console drift table.
        function Get-SettingDisplayName {
            param([string]$KeyPath, [string]$ValueName)
            $display = $KeyPath
            $servicePrefix = 'SYSTEM\CurrentControlSet\Services\'
            $policyPrefix = 'SOFTWARE\Policies\Microsoft\'
            if ($display.StartsWith($servicePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $display = $display.Substring($servicePrefix.Length)
            } elseif ($display.StartsWith($policyPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $display = 'Policies\' + $display.Substring($policyPrefix.Length)
            }
            return ($display + '\' + $ValueName)
        }

        # Emits provenance warnings for a parsed baseline (DESIGN section 9).
        function Test-BaselineProvenance {
            param(
                [hashtable]$Provenance,
                [string]$Label,
                [string]$CurrentPdce,
                [string]$CurrentModuleVersion,
                [string]$CurrentSchemaVersion,
                [datetime]$NowUtc
            )
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            if ($null -eq $Provenance) { return }
            $stampText = [string](Get-HashField -Table $Provenance -Name 'Timestamp' -Default '')
            if ($stampText.Length -gt 0) {
                $stamp = [System.DateTimeOffset]::MinValue
                if ([System.DateTimeOffset]::TryParse($stampText, $culture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$stamp)) {
                    $ageDays = ([System.DateTimeOffset]$NowUtc - $stamp).TotalDays
                    if ($ageDays -gt 180) {
                        Write-Warning ([string]::Format($culture, "{0}: baseline is {1:0} days old (captured {2}). Consider re-exporting a fresh baseline.", $Label, $ageDays, $stampText))
                    }
                } else {
                    Write-Warning ([string]::Format($culture, "{0}: baseline Timestamp '{1}' could not be parsed; age check skipped.", $Label, $stampText))
                }
            }
            $baselineModule = [string](Get-HashField -Table $Provenance -Name 'ModuleVersion' -Default '')
            if (($baselineModule.Length -gt 0) -and (-not [string]::Equals($baselineModule, $CurrentModuleVersion, [System.StringComparison]::OrdinalIgnoreCase))) {
                Write-Warning ([string]::Format($culture, "{0}: baseline was captured with module version {1}; this is {2}.", $Label, $baselineModule, $CurrentModuleVersion))
            }
            $baselineSchema = [string](Get-HashField -Table $Provenance -Name 'SchemaVersion' -Default '')
            if (($baselineSchema.Length -gt 0) -and (-not [string]::Equals($baselineSchema, $CurrentSchemaVersion, [System.StringComparison]::OrdinalIgnoreCase))) {
                Write-Warning ([string]::Format($culture, "{0}: baseline database schema version {1} differs from current {2}.", $Label, $baselineSchema, $CurrentSchemaVersion))
            }
            $baselinePdce = [string](Get-HashField -Table $Provenance -Name 'Pdce' -Default '')
            if (($baselinePdce.Length -gt 0) -and ($CurrentPdce.Length -gt 0) -and (-not [string]::Equals($baselinePdce, $CurrentPdce, [System.StringComparison]::OrdinalIgnoreCase))) {
                Write-Warning ([string]::Format($culture, "{0}: baseline provenance PDCe '{1}' differs from current forest-root PDCe '{2}' (FSMO transfer since capture?).", $Label, $baselinePdce, $CurrentPdce))
            }
        }
    }

    process {
        if ($PSBoundParameters.ContainsKey('IncludedDomainControllers') -and $null -ne $IncludedDomainControllers) {
            foreach ($name in $IncludedDomainControllers) {
                if (-not [string]::IsNullOrWhiteSpace($name)) { $pipelineDcs.Add($name.Trim()) }
            }
        }
    }

    end {
        if (-not $script:IsWindowsPlatform) {
            throw 'Get-WinTimeConfig: scanning requires Windows (SMB remote registry). The module imports on this platform for tests and tooling only.'
        }

        # ---- run anchor ------------------------------------------------------
        $runId = [guid]::NewGuid().ToString()
        $runStartUtc = [datetime]::UtcNow
        $timestamp = $runStartUtc.ToString('o', $invariant)

        $moduleVersion = '0.1.0'
        $thisModule = $MyInvocation.MyCommand.Module
        if ($null -ne $thisModule -and $null -ne $thisModule.Version) { $moduleVersion = $thisModule.Version.ToString() }

        # ---- resolve and pre-check report paths (fail before the scan) ------
        $csvResolved = $null
        $htmlResolved = $null
        if ($PSBoundParameters.ContainsKey('CsvPath')) {
            $csvResolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)
        }
        if ($PSBoundParameters.ContainsKey('HtmlPath')) {
            $htmlResolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HtmlPath)
        }
        foreach ($reportPath in @($csvResolved, $htmlResolved)) {
            if (($null -ne $reportPath) -and (Test-Path -LiteralPath $reportPath) -and (-not $Force)) {
                $exception = New-Object System.IO.IOException ([string]::Format($invariant, "File '{0}' already exists. Use -Force to overwrite.", $reportPath))
                $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'FileExists', [System.Management.Automation.ErrorCategory]::ResourceExists, $reportPath)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }

        # ---- discovery -------------------------------------------------------
        # -Forest is not forwarded: Resolve-WinTimeTarget has no such
        # parameter (it always anchors on the forest; -Forest only makes that
        # default explicit in the caller's script). Forwarding it would be an
        # unknown-parameter error.
        $resolveParams = @{}
        if ($PSBoundParameters.ContainsKey('IncludedDomains')) { $resolveParams['IncludedDomains'] = $IncludedDomains }
        if ($PSBoundParameters.ContainsKey('ExcludedDomains')) { $resolveParams['ExcludedDomains'] = $ExcludedDomains }
        if ($PSBoundParameters.ContainsKey('IncludedSites')) { $resolveParams['IncludedSites'] = $IncludedSites }
        if ($PSBoundParameters.ContainsKey('ExcludedSites')) { $resolveParams['ExcludedSites'] = $ExcludedSites }
        if ($pipelineDcs.Count -gt 0) { $resolveParams['IncludedDomainControllers'] = $pipelineDcs.ToArray() }
        if ($PSBoundParameters.ContainsKey('ExcludedDomainControllers')) { $resolveParams['ExcludedDomainControllers'] = $ExcludedDomainControllers }
        if ($PSBoundParameters.ContainsKey('Credential')) { $resolveParams['Credential'] = $Credential }

        # Resolve-WinTimeTarget returns ONE hashtable @{ Targets; RootPdce;
        # Warnings } - not a target array. RootPdce is resolved against the
        # whole forest regardless of the Included/Excluded filters, so it
        # identifies the PDCe correctly even when the PDCe itself is filtered
        # out of Targets (no second LDAP round-trip needed).
        $discovery = Resolve-WinTimeTarget @resolveParams
        $targets = @(Get-HashField -Table $discovery -Name 'Targets' -Default @())
        foreach ($discoveryWarning in @(Get-HashField -Table $discovery -Name 'Warnings' -Default @())) {
            Write-Warning ("Get-WinTimeConfig: {0}" -f $discoveryWarning)
        }
        if ($targets.Count -eq 0) {
            Write-Warning 'Get-WinTimeConfig: no domain controllers matched the targeting filters; nothing to scan.'
            return
        }

        # ---- forest-root PDCe detection --------------------------------------
        $pdceFqdn = [string](Get-HashField -Table $discovery -Name 'RootPdce' -Default '')
        $pdceDetected = ($pdceFqdn.Length -gt 0)
        if (-not $pdceDetected) {
            Write-Warning 'Get-WinTimeConfig: forest-root PDCe detection FAILED - PdceExempt handling is disabled; pdce-exempt values are compared as exact and affected records carry a Note.'
        }

        $forestName = '(unknown forest)'
        $pdceTargetMatch = $null
        if ($pdceDetected) {
            foreach ($target in $targets) {
                if ([string]::Equals([string]$target.ComputerName, $pdceFqdn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $pdceTargetMatch = $target
                    break
                }
            }
        }
        if ($null -ne $pdceTargetMatch) {
            $forestName = [string]$pdceTargetMatch.Domain
        } else {
            foreach ($target in $targets) {
                if ([int]$target.DomainDepth -eq 0) { $forestName = [string]$target.Domain; break }
            }
            if ($forestName -eq '(unknown forest)' -and $pdceDetected) {
                # PDCe filtered out of Targets and no root-domain DC present
                # either: fall back to the DNS-suffix convention (hostname's
                # domain part IS the AD DNS domain for a domain-joined DC).
                $dotIndex = $pdceFqdn.IndexOf('.')
                if ($dotIndex -gt 0 -and $dotIndex -lt ($pdceFqdn.Length - 1)) {
                    $forestName = $pdceFqdn.Substring($dotIndex + 1)
                }
            }
        }

        # ---- database and baselines -----------------------------------------
        $database = Get-W32TimeDatabase
        $schemaVersionText = [string](Get-HashField -Table $database -Name 'SchemaVersion' -Default '')

        $dcBaselineTree = $null
        $pdceBaselineTree = $null
        $dcProvenance = $null
        $baselineDescription = 'MS defaults (no baseline supplied)'

        if ($PSBoundParameters.ContainsKey('DCBaselineFile')) {
            $dcBaselinePath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DCBaselineFile)
            if (-not (Test-Path -LiteralPath $dcBaselinePath)) {
                $exception = New-Object System.IO.FileNotFoundException ([string]::Format($invariant, "DC baseline file '{0}' was not found.", $dcBaselinePath))
                $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'BaselineFileNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $dcBaselinePath)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            $parsedDc = ConvertFrom-RegFile -Path $dcBaselinePath
            $dcBaselineTree = $parsedDc['Tree']
            $dcProvenance = $parsedDc['Provenance']
            Test-BaselineProvenance -Provenance $dcProvenance -Label ('DC baseline ' + (Split-Path -Path $dcBaselinePath -Leaf)) -CurrentPdce $pdceFqdn -CurrentModuleVersion $moduleVersion -CurrentSchemaVersion $schemaVersionText -NowUtc $runStartUtc
            $baselineDescription = (Split-Path -Path $dcBaselinePath -Leaf)
            $dcStamp = [string](Get-HashField -Table $dcProvenance -Name 'Timestamp' -Default '')
            if ($dcStamp.Length -gt 0) {
                $baselineDescription = $baselineDescription + [string]::Format($invariant, ' (captured {0})', $dcStamp)
            }

            if (-not $PSBoundParameters.ContainsKey('RootPDCEBaselineFile')) {
                # Auto-companion pickup: <base>.pdce.reg next to the DC baseline.
                $companionPath = [System.IO.Path]::ChangeExtension($dcBaselinePath, 'pdce.reg')
                if (Test-Path -LiteralPath $companionPath) {
                    Write-Verbose ("Get-WinTimeConfig: auto-loading PDCe companion baseline '{0}'." -f $companionPath)
                    $parsedCompanion = ConvertFrom-RegFile -Path $companionPath
                    $pdceBaselineTree = $parsedCompanion['Tree']
                    Test-BaselineProvenance -Provenance $parsedCompanion['Provenance'] -Label ('PDCe baseline ' + (Split-Path -Path $companionPath -Leaf)) -CurrentPdce $pdceFqdn -CurrentModuleVersion $moduleVersion -CurrentSchemaVersion $schemaVersionText -NowUtc $runStartUtc
                    $baselineDescription = $baselineDescription + ' + ' + (Split-Path -Path $companionPath -Leaf)
                }
            }
        }
        if ($PSBoundParameters.ContainsKey('RootPDCEBaselineFile')) {
            $pdceBaselinePath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RootPDCEBaselineFile)
            if (-not (Test-Path -LiteralPath $pdceBaselinePath)) {
                $exception = New-Object System.IO.FileNotFoundException ([string]::Format($invariant, "Root PDCe baseline file '{0}' was not found.", $pdceBaselinePath))
                $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'BaselineFileNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $pdceBaselinePath)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            $parsedPdce = ConvertFrom-RegFile -Path $pdceBaselinePath
            $pdceBaselineTree = $parsedPdce['Tree']
            Test-BaselineProvenance -Provenance $parsedPdce['Provenance'] -Label ('PDCe baseline ' + (Split-Path -Path $pdceBaselinePath -Leaf)) -CurrentPdce $pdceFqdn -CurrentModuleVersion $moduleVersion -CurrentSchemaVersion $schemaVersionText -NowUtc $runStartUtc
            if ($baselineDescription -eq 'MS defaults (no baseline supplied)') {
                $baselineDescription = (Split-Path -Path $pdceBaselinePath -Leaf) + ' (PDCe only)'
            } else {
                $baselineDescription = $baselineDescription + ' + ' + (Split-Path -Path $pdceBaselinePath -Leaf)
            }
        }

        # ---- scan -------------------------------------------------------------
        $readSpec = @(
            @{ Path = 'SYSTEM\CurrentControlSet\Services\W32Time'; Recursive = $true },
            @{ Path = 'SOFTWARE\Policies\Microsoft\W32Time'; Recursive = $true },
            @{ Path = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Recursive = $false },
            @{ Path = 'SYSTEM\CurrentControlSet\Control\SystemInformation'; Recursive = $false }
        )
        $scanParams = @{
            Targets        = $targets
            ReadSpec       = $readSpec
            ThrottleLimit  = $ThrottleLimit
            RetryCount     = $RetryCount
            TimeoutSeconds = $TimeoutSeconds
        }
        if ($PSBoundParameters.ContainsKey('Credential')) { $scanParams['Credential'] = $Credential }
        # Invoke-WinTimeScan returns ONE hashtable @{ Results; Statuses }, not
        # a per-target array - Results is keyed by FQDN -> worker result.
        $scanOutcome = Invoke-WinTimeScan @scanParams
        $scanResultTable = [hashtable](Get-HashField -Table $scanOutcome -Name 'Results' -Default @{})
        $scanResults = @($scanResultTable.Values)

        # ---- per-target compare, streaming ------------------------------------
        $targetByName = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($target in $targets) { $targetByName[[string]$target.ComputerName] = $target }

        $allRecords = New-Object 'System.Collections.Generic.List[object]'
        $failures = New-Object 'System.Collections.Generic.List[object]'
        $successServers = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        $scannedBuilds = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($result in $scanResults) {
            $server = [string](Get-HashField -Table $result -Name 'ComputerName' -Default '')
            $target = $null
            if ($targetByName.ContainsKey($server)) { $target = $targetByName[$server] }
            if ($null -eq $target) {
                # Contract violation guard: never drop a result on the floor.
                $target = [pscustomobject]@{ ComputerName = $server; Domain = ''; Site = ''; IsRootPdce = $false; IsRodc = $false; DomainDepth = 0 }
            }
            $success = [bool](Get-HashField -Table $result -Name 'Success' -Default $false)
            $tree = Get-HashField -Table $result -Name 'Tree' -Default $null
            $osBuild = 0
            if ($null -ne $tree) { $osBuild = Get-OsBuildFromTree -Tree $tree }
            if ($osBuild -gt 0) { $scannedBuilds[$osBuild.ToString($invariant)] = $true }

            if ($success -and ($null -ne $tree)) {
                $successServers[$server] = $true
                $records = @(Compare-W32TimeConfig -Tree $tree -Target $target -Database $database `
                        -DcBaseline $dcBaselineTree -PdceBaseline $pdceBaselineTree `
                        -RootPdceDetected $pdceDetected -OsBuild $osBuild -RunId $runId -Timestamp $timestamp)
                foreach ($record in $records) {
                    $record            # stream to the pipeline as results arrive
                    [void]$allRecords.Add($record)
                }
            } else {
                $status = [pscustomobject]@{
                    PSTypeName = 'WinTime.ScanStatus'
                    Server     = $server
                    Domain     = [string]$target.Domain
                    Success    = $false
                    Attempts   = [int](Get-HashField -Table $result -Name 'Attempts' -Default 0)
                    LastError  = [string](Get-HashField -Table $result -Name 'Error' -Default '')
                    ErrorClass = [string](Get-HashField -Table $result -Name 'ErrorClass' -Default 'Unknown')
                    DurationMs = [int](Get-HashField -Table $result -Name 'DurationMs' -Default 0)
                    OsBuild    = $osBuild
                    RunId      = $runId
                    Timestamp  = $timestamp
                }
                [void]$failures.Add($status)
                Write-Error -Message ([string]::Format($invariant, 'W32Time registry scan failed for {0} [{1}]: {2}', $server, $status.ErrorClass, $status.LastError)) `
                    -ErrorId 'ScanFailure' -Category ConnectionError -TargetObject $status
            }
        }

        # OS-cohort mismatch warning for the DC baseline (DESIGN section 9).
        if ($null -ne $dcProvenance) {
            $provBuildsText = [string](Get-HashField -Table $dcProvenance -Name 'OsBuilds' -Default '')
            if ($provBuildsText.Length -gt 0) {
                $provBuilds = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($token in $provBuildsText.Split(',')) {
                    $trimmed = $token.Trim()
                    if ($trimmed.Length -gt 0) { $provBuilds[$trimmed] = $true }
                }
                $unknownBuilds = New-Object 'System.Collections.Generic.List[string]'
                foreach ($build in $scannedBuilds.Keys) {
                    if (-not $provBuilds.ContainsKey([string]$build)) { $unknownBuilds.Add([string]$build) }
                }
                if ($unknownBuilds.Count -gt 0) {
                    Write-Warning ([string]::Format($invariant, 'DC baseline OS cohort mismatch: scanned build(s) {0} are not covered by the baseline (captured from build(s) {1}). OS-divergent defaults may report as false drift.', ($unknownBuilds.ToArray() -join ', '), $provBuildsText))
                }
            }
        }

        # ---- summary model (DESIGN section 10) --------------------------------
        $driftRecords = @($allRecords | Where-Object { $_.IsDrift })
        $driftServerSet = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $driftRecords) { $driftServerSet[[string]$record.Server] = $true }

        # Drift grouping key: (KeyPath\ValueName, Expected+ExpectedSource, Found).
        $groupMap = New-Object 'System.Collections.Specialized.OrderedDictionary'
        $settingExpectations = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $driftRecords) {
            $settingName = Get-SettingDisplayName -KeyPath ([string]$record.KeyPath) -ValueName ([string]$record.ValueName)
            $expectedText = Format-WinTimeValue -Value $record.Expected
            $foundText = Format-WinTimeValue -Value $record.Data
            # ASCII Unit Separator (0x1F) as the field delimiter: settingName/
            # expectedText/foundText are free-text registry data (and
            # Format-WinTimeValue itself joins REG_MULTI_SZ elements with
            # '|'), so a plain '|'-joined key can collide between two
            # genuinely distinct drift findings and silently merge them into
            # one console/HTML bucket. 0x1F cannot appear in registry string
            # data or in any of these rendered fields.
            $groupKey = $settingName + [char]0x1F + $expectedText + [char]0x1F + [string]$record.ExpectedSource + [char]0x1F + $foundText

            if (-not $settingExpectations.ContainsKey($settingName)) {
                $settingExpectations[$settingName] = New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal)
            }
            $settingExpectations[$settingName][$expectedText] = $true

            if (-not $groupMap.Contains($groupKey)) {
                $groupMap[$groupKey] = @{
                    Key            = $settingName
                    Expected       = $expectedText
                    ExpectedSource = [string]$record.ExpectedSource
                    RoleScope      = ''
                    Found          = $foundText
                    Servers        = (New-Object 'System.Collections.Generic.List[string]')
                    Roles          = (New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase))
                    MoreCount      = 0
                    GpoHint        = ''
                }
            }
            $group = $groupMap[$groupKey]
            $group['Servers'].Add([string]$record.Server)
            $group['Roles'][[string]$record.Role] = $true
            $note = [string]$record.Note
            if (($group['GpoHint'].Length -eq 0) -and ($note.IndexOf('GPO', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                $group['GpoHint'] = $note
            }
        }
        $driftGroups = New-Object 'System.Collections.Generic.List[object]'
        foreach ($groupKey in $groupMap.Keys) {
            $group = $groupMap[$groupKey]
            # Role/OS-scoped annotation: only when the same setting drifted
            # against more than one distinct expectation (DESIGN section 10).
            if ($settingExpectations[[string]$group['Key']].Count -gt 1) {
                $roleLabels = New-Object 'System.Collections.Generic.List[string]'
                foreach ($role in $group['Roles'].Keys) {
                    if ([string]::Equals([string]$role, 'RootPdce', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $roleLabels.Add('PDCe')
                    } else {
                        $roleLabels.Add('DC')
                    }
                }
                $group['RoleScope'] = '[' + (($roleLabels | Sort-Object -Unique) -join '/') + ']'
            }
            $driftGroups.Add(@{
                    Key            = $group['Key']
                    Expected       = $group['Expected']
                    ExpectedSource = $group['ExpectedSource']
                    RoleScope      = $group['RoleScope']
                    Found          = $group['Found']
                    Servers        = $group['Servers'].ToArray()
                    MoreCount      = 0
                    GpoHint        = $group['GpoHint']
                })
        }
        $driftGroupsSorted = @($driftGroups.ToArray() | Sort-Object -Property @{ Expression = { @($_['Servers']).Count }; Descending = $true })

        # Promoted undocumented findings (security subset, DESIGN section 4).
        $promotedFindings = New-Object 'System.Collections.Generic.List[object]'
        foreach ($record in $allRecords) {
            if ([string]$record.Status -ne 'Undocumented') { continue }
            $promotedProperty = $record.PSObject.Properties['Promoted']
            if (($null -ne $promotedProperty) -and ([bool]$promotedProperty.Value)) {
                $promotedFindings.Add(@{
                        Server    = [string]$record.Server
                        KeyPath   = [string]$record.KeyPath
                        ValueName = [string]$record.ValueName
                        Reason    = [string]$record.Note
                    })
            }
        }

        # Per-domain rows.
        $domainNames = @($targets | ForEach-Object { [string]$_.Domain } | Sort-Object -Unique)
        $domainRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($domainName in $domainNames) {
            $domainTargets = @($targets | Where-Object { [string]::Equals([string]$_.Domain, $domainName, [System.StringComparison]::OrdinalIgnoreCase) })
            $domainScanned = 0
            $domainDrift = 0
            foreach ($target in $domainTargets) {
                $name = [string]$target.ComputerName
                if ($successServers.ContainsKey($name)) { $domainScanned++ }
                if ($driftServerSet.ContainsKey($name)) { $domainDrift++ }
            }
            $domainFailed = @($failures | Where-Object { [string]::Equals([string]$_.Domain, $domainName, [System.StringComparison]::OrdinalIgnoreCase) }).Count
            $domainRows.Add(@{
                    Domain  = $domainName
                    Dcs     = $domainTargets.Count
                    Scanned = $domainScanned
                    Clean   = ($domainScanned - $domainDrift)
                    Drift   = $domainDrift
                    Failed  = $domainFailed
                })
        }

        $authFailedCount = @($failures | Where-Object { ($_.ErrorClass -eq 'AccessDenied') -or ($_.ErrorClass -eq 'AuthFailure') }).Count
        $unreachable = New-Object 'System.Collections.Generic.List[object]'
        foreach ($failure in $failures) {
            $unreachable.Add(@{ Server = [string]$failure.Server; Error = [string]$failure.LastError; Attempts = [int]$failure.Attempts })
        }

        $summaryModel = @{
            Title               = 'WinTimeHealth - W32Time configuration audit'
            ForestName          = $forestName
            Timestamp           = $timestamp
            BaselineDescription = $baselineDescription
            PdceFqdn            = $pdceFqdn
            PdceDetected        = $pdceDetected
            Totals              = @{
                Targets          = $targets.Count
                Scanned          = $successServers.Count
                Failed           = $failures.Count
                AuthFailed       = $authFailedCount
                ServersWithDrift = $driftServerSet.Count
            }
            DomainRows          = $domainRows.ToArray()
            DriftGroups         = $driftGroupsSorted
            PromotedFindings    = $promotedFindings.ToArray()
            Unreachable         = $unreachable.ToArray()
            CsvPath             = $csvResolved
        }

        # ---- report files ------------------------------------------------------
        if ($null -ne $csvResolved) {
            $configColumns = @('Server', 'Domain', 'Role', 'OsBuild', 'KeyPath', 'ValueName', 'Type', 'Data', 'Expected', 'ExpectedSource', 'Status', 'IsDrift', 'Class', 'GpoBacked', 'PolicyApplied', 'Note', 'RunId', 'Timestamp')
            $csvLines = [string[]]@(ConvertTo-WinTimeCsvSafe -InputObject $allRecords.ToArray() -ColumnOrder $configColumns)
            $null = Write-WinTimeReportFile -Path $csvResolved -Content $csvLines -Force:$Force
            Write-Verbose ("Get-WinTimeConfig: wrote {0} record(s) to '{1}'." -f $allRecords.Count, $csvResolved)

            if ($failures.Count -gt 0) {
                $failuresPath = [System.IO.Path]::ChangeExtension($csvResolved, 'failures.csv')
                $failureColumns = @('Server', 'Domain', 'Success', 'Attempts', 'LastError', 'ErrorClass', 'DurationMs', 'OsBuild', 'RunId', 'Timestamp')
                $failureLines = [string[]]@(ConvertTo-WinTimeCsvSafe -InputObject $failures.ToArray() -ColumnOrder $failureColumns)
                $null = Write-WinTimeReportFile -Path $failuresPath -Content $failureLines -Force:$Force
                Write-Verbose ("Get-WinTimeConfig: wrote {0} failure(s) to '{1}' (re-run: Import-Csv '{1}' | Get-WinTimeConfig)." -f $failures.Count, $failuresPath)
            }
        }
        if ($null -ne $htmlResolved) {
            $null = New-WinTimeHtmlReport -Model $summaryModel -ConfigRecords $allRecords.ToArray() -Path $htmlResolved -Force:$Force
            Write-Verbose ("Get-WinTimeConfig: wrote HTML report to '{0}'." -f $htmlResolved)
        }

        Write-WinTimeSummary -Model $summaryModel -NoSummary:$NoSummary
    }
}
