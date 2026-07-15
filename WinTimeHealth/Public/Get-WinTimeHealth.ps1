function Get-WinTimeHealth {
    <#
    .SYNOPSIS
    Audits live W32Time health across the domain controllers of an Active
    Directory forest: service state, SNTP reachability, offset versus the
    forest-root PDCe, stratum hierarchy, sync source, sync age, announce
    flags, virtualization time sync, refid loops and Secure Time Seeding.

    .DESCRIPTION
    Runs the two-phase health engine (DESIGN.md section 8). Phase 1 collects
    registry trees (and service state) over SMB remote registry - only when a
    selected check needs registry data. Phase 2 sends mode-3 SNTPv3 client
    probes over UDP/123 with bounded concurrency; the forest-root PDCe is
    ALWAYS queried as the hidden reference clock even when targeting filters
    exclude it, and it is re-sampled during long runs so offsets are computed
    against a fresh reference.

    Emits one WinTime.HealthRecord per server per check with Status Pass,
    Warn, Fail, Error, Blocked or NotApplicable. Transports are independent:
    UDP checks still run when the registry scan failed, and vice versa; a
    dead UDP path reports Error (unproven), never Fail. Registry scan
    failures surface as non-terminating errors (FullyQualifiedErrorId
    ScanFailure,Get-WinTimeHealth) with a WinTime.ScanStatus TargetObject.
    A per-check console summary is printed afterwards (suppress with
    -NoSummary); optional CSV/HTML reports are injection-safe.

    .PARAMETER Forest
    Explicit whole-forest anchor (scanning the whole forest is the default).

    .PARAMETER IncludedDomains
    Wildcard patterns of DNS domain names to include. Exclude always wins.

    .PARAMETER ExcludedDomains
    Wildcard patterns of DNS domain names to exclude.

    .PARAMETER IncludedSites
    Wildcard patterns of AD site names to include.

    .PARAMETER ExcludedSites
    Wildcard patterns of AD site names to exclude.

    .PARAMETER IncludedDomainControllers
    Wildcard patterns (or exact FQDNs) of DCs to include. Accepts pipeline
    input by property name (aliases: Server, ComputerName, DnsHostName).

    .PARAMETER ExcludedDomainControllers
    Wildcard patterns of DCs to exclude. Exclude always wins.

    .PARAMETER Credential
    Alternate credential for the registry phase (IPC$ session per target).

    .PARAMETER ThrottleLimit
    Maximum concurrent registry scan workers (1-128, default 32).

    .PARAMETER RetryCount
    Registry retries for transport-class failures only (0-10, default 3).

    .PARAMETER TimeoutSeconds
    Best-effort per-attempt registry read budget (5-300, default 30). The
    NTP transport has its own independent timeout (-NtpTimeoutMilliseconds).

    .PARAMETER IncludedHealthChecks
    Checks to run (default: all). Literal names: Service, NtpQuery, Offset,
    Stratum, Source, LastSync, Announce, Vmic, RefidLoop, SecureTimeSeeding.

    .PARAMETER ExcludedHealthChecks
    Checks to skip. Exclude always wins over include.

    .PARAMETER NtpSamples
    SNTP probes per target (best sample = minimum delay). Default 4.

    .PARAMETER NtpTimeoutMilliseconds
    Receive timeout per SNTP probe. Default 1500.

    .PARAMETER OffsetWarnMilliseconds
    Warn threshold for |offset versus the PDCe reference|. Default 500.

    .PARAMETER OffsetFailMilliseconds
    Fail threshold for |offset versus the PDCe reference|. Default 5000.

    .PARAMETER StratumDepthSlack
    Allowed deviation from the expected stratum band (pdceStratum +
    DomainDepth, +1 for RODCs). Default 1.

    .PARAMETER LastSyncWarnSeconds
    Warn threshold for sync age; 0 (default) = auto: 2 x 2^MaxPollInterval
    using each server's effective value.

    .PARAMETER LastSyncFailSeconds
    Fail threshold for sync age; 0 (default) = auto: the server's
    ClockHoldoverPeriod (7800 fallback when absent).

    .PARAMETER KnownReliableTimeServers
    Declared GTIMESERV hosts. Suppresses out-of-hierarchy warnings (Stratum,
    Source, Announce AlwaysReliable) for these FQDNs.

    .PARAMETER CsvPath
    Write all health records to this CSV file; scan failures additionally go
    to <base>.failures.csv.

    .PARAMETER HtmlPath
    Write a self-contained, HTML-encoded report to this path.

    .PARAMETER Force
    Overwrite existing report files.

    .PARAMETER NoSummary
    Suppress the console summary.

    .EXAMPLE
    PS> Get-WinTimeHealth

    Full ten-check health sweep of every DC in the forest, with the
    per-check summary pyramid at the end.

    .EXAMPLE
    PS> Get-WinTimeHealth -IncludedHealthChecks Offset,Stratum -OffsetFailMilliseconds 1000

    Offset/stratum-only sweep with a tightened failure threshold; the
    registry phase is skipped entirely because neither check needs it.

    .EXAMPLE
    PS> Get-WinTimeHealth -IncludedDomains 'corp.example.com' -CsvPath .\health.csv |
            Where-Object { $_.Status -in 'Fail','Error' }

    Scans one domain, writes the full record set to CSV and keeps only the
    failing records on the pipeline.

    .EXAMPLE
    PS> Get-WinTimeHealth -ExcludedHealthChecks Vmic,SecureTimeSeeding -KnownReliableTimeServers 'gps01.corp.example.com'

    Skips the virtualization and STS checks and declares a GPS-disciplined
    GTIMESERV so its out-of-hierarchy topology does not raise warnings.

    .OUTPUTS
    WinTime.HealthRecord. Registry scan failures are non-terminating errors
    carrying a WinTime.ScanStatus TargetObject.
    #>
    [CmdletBinding()]
    [OutputType('WinTime.HealthRecord')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Justification = 'Server lookup tables require an explicit OrdinalIgnoreCase comparer per DESIGN.md; literal @{} hashtables use culture-aware case-insensitive comparison instead.')]
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
        [ValidateSet('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'Vmic', 'RefidLoop', 'SecureTimeSeeding')]
        [string[]]$IncludedHealthChecks,

        [Parameter()]
        [ValidateSet('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'Vmic', 'RefidLoop', 'SecureTimeSeeding')]
        [string[]]$ExcludedHealthChecks,

        [Parameter()]
        [ValidateRange(1, 16)]
        [int]$NtpSamples = 4,

        [Parameter()]
        [ValidateRange(100, 30000)]
        [int]$NtpTimeoutMilliseconds = 1500,

        [Parameter()]
        [ValidateRange(1, 86400000)]
        [int]$OffsetWarnMilliseconds = 500,

        [Parameter()]
        [ValidateRange(1, 86400000)]
        [int]$OffsetFailMilliseconds = 5000,

        [Parameter()]
        [ValidateRange(0, 15)]
        [int]$StratumDepthSlack = 1,

        [Parameter()]
        [ValidateRange(0, 31536000)]
        [int]$LastSyncWarnSeconds = 0,

        [Parameter()]
        [ValidateRange(0, 31536000)]
        [int]$LastSyncFailSeconds = 0,

        [Parameter()]
        [string[]]$KnownReliableTimeServers = @(),

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
        $pipelineDcs = New-Object 'System.Collections.Generic.List[string]'

        # Hashtable field access with a default (worker results are hashtables).
        function Get-HashField {
            param($Table, [string]$Name, $Default)
            if (($null -ne $Table) -and ($Table -is [System.Collections.IDictionary]) -and $Table.Contains($Name) -and ($null -ne $Table[$Name])) {
                return $Table[$Name]
            }
            return $Default
        }

        # IPv4 addresses of a DC, for Get-WinTimeRefidLoopFinding's -AllResults
        # 'Ips' field (maps a peer's NTP refid back to the owning DC). DNS
        # failures are swallowed - that node just takes no part in the graph.
        function Get-WinTimeHostIPv4Address {
            param([string]$Fqdn)
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($Fqdn)
                $ipv4 = New-Object 'System.Collections.Generic.List[string]'
                foreach ($address in $addresses) {
                    if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                        $ipv4.Add($address.ToString())
                    }
                }
                return $ipv4.ToArray()
            } catch {
                Write-Verbose ("Get-WinTimeHealth: IPv4 resolution failed for '{0}': {1}" -f $Fqdn, $_.Exception.Message)
                return @()
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
            throw 'Get-WinTimeHealth: scanning requires Windows (SMB remote registry / SNTP client engine). The module imports on this platform for tests and tooling only.'
        }

        $runId = [guid]::NewGuid().ToString()
        $runStartUtc = [datetime]::UtcNow
        $timestamp = $runStartUtc.ToString('o', $invariant)

        # ---- resolve check selection (Exclude always wins) --------------------
        $checkCatalog = @('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'Vmic', 'RefidLoop', 'SecureTimeSeeding')
        $selectedChecks = New-Object 'System.Collections.Generic.List[string]'
        foreach ($check in $checkCatalog) {
            $include = $true
            if ($PSBoundParameters.ContainsKey('IncludedHealthChecks') -and $null -ne $IncludedHealthChecks) {
                $include = ($IncludedHealthChecks -contains $check)
            }
            if ($include -and $PSBoundParameters.ContainsKey('ExcludedHealthChecks') -and $null -ne $ExcludedHealthChecks) {
                if ($ExcludedHealthChecks -contains $check) { $include = $false }
            }
            if ($include) { $selectedChecks.Add($check) }
        }
        if ($selectedChecks.Count -eq 0) {
            Write-Warning 'Get-WinTimeHealth: the check filters selected no health checks; nothing to do.'
            return
        }

        $registryChecks = @('Service', 'Announce', 'Vmic', 'Source', 'SecureTimeSeeding')
        $ntpChecks = @('NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'RefidLoop', 'Vmic')
        $needRegistry = $false
        foreach ($check in $registryChecks) { if ($selectedChecks.Contains($check)) { $needRegistry = $true; break } }
        if ((-not $needRegistry) -and $selectedChecks.Contains('LastSync') -and (($LastSyncWarnSeconds -eq 0) -or ($LastSyncFailSeconds -eq 0))) {
            # Auto thresholds derive from each server's MaxPollInterval /
            # ClockHoldoverPeriod, which live in the registry tree.
            $needRegistry = $true
        }
        $needNtp = $false
        foreach ($check in $ntpChecks) { if ($selectedChecks.Contains($check)) { $needNtp = $true; break } }

        # ---- resolve and pre-check report paths --------------------------------
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

        # ---- discovery ----------------------------------------------------------
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
            Write-Warning ("Get-WinTimeHealth: {0}" -f $discoveryWarning)
        }
        if ($targets.Count -eq 0) {
            Write-Warning 'Get-WinTimeHealth: no domain controllers matched the targeting filters; nothing to scan.'
            return
        }

        # ---- forest-root PDCe reference (hidden if filtered, DESIGN section 8) --
        $pdceFqdn = [string](Get-HashField -Table $discovery -Name 'RootPdce' -Default '')
        $pdceDetected = ($pdceFqdn.Length -gt 0)
        if (-not $pdceDetected) {
            Write-Warning 'Get-WinTimeHealth: forest-root PDCe detection FAILED - the Offset check loses its reference and Stratum degrades to absolute rules only.'
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

        # Database is mandatory for Invoke-WinTimeHealthEvaluation (policy twin
        # paths and role/OS defaults for the registry-backed checks).
        $database = Get-W32TimeDatabase

        # ---- phase 1: registry scan (only when a selected check needs it) -------
        $scanByServer = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        $failures = New-Object 'System.Collections.Generic.List[object]'
        if ($needRegistry) {
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
            # Invoke-WinTimeScan returns ONE hashtable @{ Results; Statuses },
            # not a per-target array - Results is keyed by FQDN -> worker result.
            $scanOutcome = Invoke-WinTimeScan @scanParams
            $scanResultTable = [hashtable](Get-HashField -Table $scanOutcome -Name 'Results' -Default @{})
            foreach ($result in @($scanResultTable.Values)) {
                $server = [string](Get-HashField -Table $result -Name 'ComputerName' -Default '')
                $scanByServer[$server] = $result
            }
        } else {
            Write-Verbose 'Get-WinTimeHealth: registry phase skipped - no selected check needs registry data.'
        }

        # ---- phase 2: SNTP sampling over bounded ThreadJob batches ---------------
        $ntpByServer = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        $pdceNtp = $null
        if ($needNtp) {
            $ntpCommand = Get-Command -Name Invoke-NtpQuery -CommandType Function -ErrorAction SilentlyContinue
            if ($null -eq $ntpCommand) {
                throw 'Get-WinTimeHealth: the Invoke-NtpQuery engine function is unavailable; the module did not load completely.'
            }
            # The jobs must be self-contained: ship the function DEFINITION into
            # each thread via the initialization script (DESIGN section 8).
            $ntpDefinition = 'function Invoke-NtpQuery {' + [System.Environment]::NewLine + $ntpCommand.Definition + [System.Environment]::NewLine + '}'
            $ntpInitialization = [scriptblock]::Create($ntpDefinition)
            $ntpBlock = {
                param([string]$Server, [int]$Samples, [int]$TimeoutMilliseconds, [datetime]$UtcAnchor, [System.Diagnostics.Stopwatch]$AnchorStopwatch)
                $outcome = @{ ComputerName = $Server; Result = $null; Error = $null }
                try {
                    $outcome['Result'] = Invoke-NtpQuery -ComputerName $Server -Samples $Samples -TimeoutMilliseconds $TimeoutMilliseconds -UtcAnchor $UtcAnchor -AnchorStopwatch $AnchorStopwatch
                } catch {
                    $outcome['Error'] = $_.Exception.Message
                }
                return $outcome
            }

            # Shared time base for every probe this run (DESIGN section 8): a
            # single UtcNow anchor plus a running Stopwatch, so every T1/T4
            # derives from the same admin-host clock and offsets stay
            # differential-comparable across targets and across re-samples.
            # ThreadJob runs threads in-process, so the live Stopwatch
            # reference is safe to share (concurrent .Elapsed reads only).
            $utcAnchor = [datetime]::UtcNow
            $anchorStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            $phase2Watch = [System.Diagnostics.Stopwatch]::StartNew()

            # Reference sample first: the PDCe is queried even when filtered out.
            if ($pdceDetected) {
                try {
                    $pdceNtp = Invoke-NtpQuery -ComputerName $pdceFqdn -Samples $NtpSamples -TimeoutMilliseconds $NtpTimeoutMilliseconds -UtcAnchor $utcAnchor -AnchorStopwatch $anchorStopwatch
                } catch {
                    Write-Warning ("Get-WinTimeHealth: reference SNTP query against PDCe {0} failed: {1}" -f $pdceFqdn, $_.Exception.Message)
                }
            }
            $lastReferenceSampleSeconds = 0.0

            $ntpConcurrency = 64   # bounded outstanding probes (DESIGN section 8)
            $jobsByServer = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($target in $targets) {
                $server = [string]$target.ComputerName
                if ($jobsByServer.ContainsKey($server)) { continue }
                if ($pdceDetected -and [string]::Equals($server, $pdceFqdn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    continue   # the reference sample doubles as the PDCe's own result
                }
                $jobsByServer[$server] = Start-ThreadJob -ScriptBlock $ntpBlock -InitializationScript $ntpInitialization `
                    -ArgumentList @($server, $NtpSamples, $NtpTimeoutMilliseconds, $utcAnchor, $anchorStopwatch) -ThrottleLimit $ntpConcurrency
            }

            # Watchdog ceiling: per-job budget times the number of throttle waves.
            $perJobSeconds = [Math]::Ceiling(($NtpSamples * $NtpTimeoutMilliseconds) / 1000.0) + 10
            $waves = [Math]::Ceiling([double]$jobsByServer.Count / $ntpConcurrency)
            if ($waves -lt 1) { $waves = 1 }
            $deadlineSeconds = ($perJobSeconds * $waves) + 30

            $progressActivity = 'Get-WinTimeHealth: SNTP sampling'
            try {
                while ($true) {
                    $pending = 0
                    foreach ($job in $jobsByServer.Values) {
                        if (($job.State -eq 'Running') -or ($job.State -eq 'NotStarted')) { $pending++ }
                    }
                    if ($pending -eq 0) { break }
                    if ($phase2Watch.Elapsed.TotalSeconds -gt $deadlineSeconds) {
                        Write-Warning ("Get-WinTimeHealth: SNTP watchdog fired after {0:0}s with {1} probe job(s) outstanding." -f $phase2Watch.Elapsed.TotalSeconds, $pending)
                        break
                    }
                    # Long run: re-sample the reference roughly every 60s and use
                    # the freshest result (DESIGN section 8).
                    if ($pdceDetected -and (($phase2Watch.Elapsed.TotalSeconds - $lastReferenceSampleSeconds) -gt 60)) {
                        $lastReferenceSampleSeconds = $phase2Watch.Elapsed.TotalSeconds
                        try {
                            $freshReference = Invoke-NtpQuery -ComputerName $pdceFqdn -Samples $NtpSamples -TimeoutMilliseconds $NtpTimeoutMilliseconds -UtcAnchor $utcAnchor -AnchorStopwatch $anchorStopwatch
                            if ($null -ne $freshReference) { $pdceNtp = $freshReference }
                        } catch {
                            Write-Verbose ("Get-WinTimeHealth: reference re-sample failed: {0}" -f $_.Exception.Message)
                        }
                    }
                    $done = $jobsByServer.Count - $pending
                    $percent = 100
                    if ($jobsByServer.Count -gt 0) { $percent = [int](100 * $done / $jobsByServer.Count) }
                    Write-Progress -Activity $progressActivity -Status ([string]::Format($invariant, '{0}/{1} servers probed', $done, $jobsByServer.Count)) -PercentComplete $percent
                    Start-Sleep -Milliseconds 500
                }
            } finally {
                Write-Progress -Activity $progressActivity -Completed
                foreach ($server in @($jobsByServer.Keys)) {
                    $job = $jobsByServer[$server]
                    $outcome = $null
                    if ($job.State -eq 'Completed') {
                        $outcome = Receive-Job -Job $job -ErrorAction SilentlyContinue
                    } else {
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                    }
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    # Every server is accounted for: $null marks 'no result'.
                    $ntpResult = $null
                    if ($null -ne $outcome) {
                        $ntpResult = Get-HashField -Table $outcome -Name 'Result' -Default $null
                        $jobError = [string](Get-HashField -Table $outcome -Name 'Error' -Default '')
                        if (($null -eq $ntpResult) -and ($jobError.Length -gt 0)) {
                            Write-Verbose ("Get-WinTimeHealth: SNTP probe of {0} threw: {1}" -f $server, $jobError)
                        }
                    }
                    $ntpByServer[$server] = $ntpResult
                }
            }
            if ($pdceDetected) { $ntpByServer[$pdceFqdn] = $pdceNtp }
        }

        # ---- evaluation ------------------------------------------------------------
        # Thresholds keys per the Invoke-WinTimeHealthEvaluation contract; it
        # reads exactly these six via ContainsKey and ignores unknown keys.
        $thresholds = @{
            OffsetWarnMilliseconds   = $OffsetWarnMilliseconds
            OffsetFailMilliseconds   = $OffsetFailMilliseconds
            StratumDepthSlack        = $StratumDepthSlack
            LastSyncWarnSeconds      = $LastSyncWarnSeconds
            LastSyncFailSeconds      = $LastSyncFailSeconds
            KnownReliableTimeServers = @($KnownReliableTimeServers)
        }
        $perTargetChecks = @($selectedChecks | Where-Object { $_ -ne 'RefidLoop' })
        $allRecords = New-Object 'System.Collections.Generic.List[object]'

        foreach ($target in $targets) {
            $server = [string]$target.ComputerName
            $scanResult = $null
            if ($needRegistry -and $scanByServer.ContainsKey($server)) { $scanResult = $scanByServer[$server] }
            $ntpResult = $null
            if ($needNtp -and $ntpByServer.ContainsKey($server)) { $ntpResult = $ntpByServer[$server] }

            # Registry scan failures surface exactly once, as ScanStatus errors;
            # the evaluation still runs (transports are independent).
            if ($needRegistry -and ($null -ne $scanResult) -and (-not [bool](Get-HashField -Table $scanResult -Name 'Success' -Default $false))) {
                $status = [pscustomobject]@{
                    PSTypeName = 'WinTime.ScanStatus'
                    Server     = $server
                    Domain     = [string]$target.Domain
                    Success    = $false
                    Attempts   = [int](Get-HashField -Table $scanResult -Name 'Attempts' -Default 0)
                    LastError  = [string](Get-HashField -Table $scanResult -Name 'Error' -Default '')
                    ErrorClass = [string](Get-HashField -Table $scanResult -Name 'ErrorClass' -Default 'Unknown')
                    DurationMs = [int](Get-HashField -Table $scanResult -Name 'DurationMs' -Default 0)
                    OsBuild    = 0
                    RunId      = $runId
                    Timestamp  = $timestamp
                }
                [void]$failures.Add($status)
                Write-Error -Message ([string]::Format($invariant, 'W32Time registry scan failed for {0} [{1}]: {2}', $server, $status.ErrorClass, $status.LastError)) `
                    -ErrorId 'ScanFailure' -Category ConnectionError -TargetObject $status
            }

            if ($perTargetChecks.Count -gt 0) {
                # ScmStatus comes from Get-WinTimeRegistryWorker's live
                # ServiceController('w32time', fqdn) query (DESIGN section 8:
                # "svcctl rides the same 445 session"), threaded through
                # Invoke-WinTimeScan's worker-result hashtable. It is $null
                # when the registry phase did not run for this server, the
                # scan failed, or the SCM query itself failed (e.g. the
                # service does not exist) - Invoke-WinTimeHealthEvaluation
                # degrades the Service check to Status=Error ("SCM query
                # failed") in that case rather than fabricating a Pass/Fail.
                $tree = Get-HashField -Table $scanResult -Name 'Tree' -Default $null
                $scmStatus = [string](Get-HashField -Table $scanResult -Name 'ScmStatus' -Default $null)
                if ([string]::IsNullOrEmpty($scmStatus)) { $scmStatus = $null }
                $records = @(Invoke-WinTimeHealthEvaluation -Target $target -Tree $tree -ScmStatus $scmStatus `
                        -Ntp $ntpResult -PdceNtp $pdceNtp -Checks $perTargetChecks `
                        -Thresholds $thresholds -Database $database -RunId $runId -Timestamp $timestamp)
                foreach ($record in $records) {
                    $record            # stream
                    [void]$allRecords.Add($record)
                }
            }
        }

        # Fleet-wide refid loop detection runs once over all NTP results, via
        # the dedicated Get-WinTimeRefidLoopFinding function (lives in the same
        # file as Invoke-WinTimeHealthEvaluation, which has no fleet mode of
        # its own). AllResults needs each DC's IPv4 addresses to map a peer's
        # refid back to the owning DC.
        if ($selectedChecks.Contains('RefidLoop')) {
            $allResultsForFleet = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($target in $targets) {
                $server = [string]$target.ComputerName
                $ntpForFleet = $null
                if ($ntpByServer.ContainsKey($server)) { $ntpForFleet = $ntpByServer[$server] }
                $allResultsForFleet[$server] = @{
                    Ntp    = $ntpForFleet
                    Target = $target
                    Ips    = (Get-WinTimeHostIPv4Address -Fqdn $server)
                }
            }
            if ($pdceDetected -and -not $allResultsForFleet.ContainsKey($pdceFqdn)) {
                $allResultsForFleet[$pdceFqdn] = @{
                    Ntp    = $pdceNtp
                    Target = $null
                    Ips    = (Get-WinTimeHostIPv4Address -Fqdn $pdceFqdn)
                }
            }
            $fleetRecords = @(Get-WinTimeRefidLoopFinding -AllResults $allResultsForFleet -RunId $runId -Timestamp $timestamp -KnownReliableTimeServers @($KnownReliableTimeServers))
            foreach ($record in $fleetRecords) {
                $record
                [void]$allRecords.Add($record)
            }
        }

        # ---- summary model (health flavor: per-check totals) -------------------------
        $issueServerSet = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $allRecords) {
            $recordStatus = [string]$record.Status
            if (($recordStatus -eq 'Fail') -or ($recordStatus -eq 'Error')) { $issueServerSet[[string]$record.Server] = $true }
        }

        $checkGroups = New-Object 'System.Collections.Generic.List[object]'
        foreach ($check in $selectedChecks) {
            foreach ($badStatus in @('Fail', 'Error', 'Warn')) {
                $matching = @($allRecords | Where-Object { ([string]$_.Check -eq $check) -and ([string]$_.Status -eq $badStatus) })
                if ($matching.Count -eq 0) { continue }
                $serverNames = @($matching | ForEach-Object { [string]$_.Server } | Sort-Object -Unique)
                $checkGroups.Add(@{
                        Key            = $check
                        Expected       = 'Pass'
                        ExpectedSource = 'HealthCheck'
                        RoleScope      = ''
                        Found          = $badStatus
                        Servers        = $serverNames
                        MoreCount      = 0
                        GpoHint        = [string]$matching[0].Detail
                    })
            }
        }

        $domainNames = @($targets | ForEach-Object { [string]$_.Domain } | Sort-Object -Unique)
        $domainRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($domainName in $domainNames) {
            $domainTargets = @($targets | Where-Object { [string]::Equals([string]$_.Domain, $domainName, [System.StringComparison]::OrdinalIgnoreCase) })
            $domainFailedNames = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($failure in $failures) {
                if ([string]::Equals([string]$failure.Domain, $domainName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $domainFailedNames[[string]$failure.Server] = $true
                }
            }
            $domainIssues = 0
            foreach ($target in $domainTargets) {
                if ($issueServerSet.ContainsKey([string]$target.ComputerName)) { $domainIssues++ }
            }
            $domainScanned = $domainTargets.Count - $domainFailedNames.Count
            $domainRows.Add(@{
                    Domain  = $domainName
                    Dcs     = $domainTargets.Count
                    Scanned = $domainScanned
                    Clean   = ($domainTargets.Count - $domainIssues)
                    Drift   = $domainIssues
                    Failed  = $domainFailedNames.Count
                })
        }

        $authFailedCount = @($failures | Where-Object { ($_.ErrorClass -eq 'AccessDenied') -or ($_.ErrorClass -eq 'AuthFailure') }).Count
        $unreachable = New-Object 'System.Collections.Generic.List[object]'
        foreach ($failure in $failures) {
            $unreachable.Add(@{ Server = [string]$failure.Server; Error = [string]$failure.LastError; Attempts = [int]$failure.Attempts })
        }

        $summaryModel = @{
            Title               = 'WinTimeHealth - W32Time health audit'
            ForestName          = $forestName
            Timestamp           = $timestamp
            BaselineDescription = ('Checks: ' + ($selectedChecks.ToArray() -join ', '))
            PdceFqdn            = $pdceFqdn
            PdceDetected        = $pdceDetected
            Totals              = @{
                Targets          = $targets.Count
                Scanned          = ($targets.Count - $failures.Count)
                Failed           = $failures.Count
                AuthFailed       = $authFailedCount
                ServersWithDrift = $issueServerSet.Count
            }
            DomainRows          = $domainRows.ToArray()
            DriftGroups         = $checkGroups.ToArray()
            PromotedFindings    = @()
            Unreachable         = $unreachable.ToArray()
            CsvPath             = $csvResolved
        }

        # ---- report files --------------------------------------------------------------
        if ($null -ne $csvResolved) {
            $healthColumns = @('Server', 'Domain', 'Role', 'Check', 'Status', 'Detail', 'Data', 'RunId', 'Timestamp')
            $csvLines = [string[]]@(ConvertTo-WinTimeCsvSafe -InputObject $allRecords.ToArray() -ColumnOrder $healthColumns)
            $null = Write-WinTimeReportFile -Path $csvResolved -Content $csvLines -Force:$Force
            Write-Verbose ("Get-WinTimeHealth: wrote {0} record(s) to '{1}'." -f $allRecords.Count, $csvResolved)

            if ($failures.Count -gt 0) {
                $failuresPath = [System.IO.Path]::ChangeExtension($csvResolved, 'failures.csv')
                $failureColumns = @('Server', 'Domain', 'Success', 'Attempts', 'LastError', 'ErrorClass', 'DurationMs', 'OsBuild', 'RunId', 'Timestamp')
                $failureLines = [string[]]@(ConvertTo-WinTimeCsvSafe -InputObject $failures.ToArray() -ColumnOrder $failureColumns)
                $null = Write-WinTimeReportFile -Path $failuresPath -Content $failureLines -Force:$Force
                Write-Verbose ("Get-WinTimeHealth: wrote {0} failure(s) to '{1}'." -f $failures.Count, $failuresPath)
            }
        }
        if ($null -ne $htmlResolved) {
            $null = New-WinTimeHtmlReport -Model $summaryModel -HealthRecords $allRecords.ToArray() -Path $htmlResolved -Force:$Force
            Write-Verbose ("Get-WinTimeHealth: wrote HTML report to '{0}'." -f $htmlResolved)
        }

        Write-WinTimeSummary -Model $summaryModel -NoSummary:$NoSummary
    }
}
