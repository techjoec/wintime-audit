function Export-WinTimeConfigBaseline {
    <#
    .SYNOPSIS
    Captures a consensus W32Time configuration baseline from reference domain
    controllers into an auditable (non-mergeable) .reg file, plus a
    .pdce.reg companion for forest-root PDCe-specific values.

    .DESCRIPTION
    Scans the named reference DCs (or every DC with -ExportAllDCs) over SMB
    remote registry and writes the agreed configuration to -OutFile.

    Content policy (DESIGN.md section 4): the baseline contains ONLY
    class 'config' values plus internal tamper-evidence values with
    compare 'exact' (ServiceDll, DllName, ObjectName, ImagePath, ...). It
    never contains compare 'ignore' values or internal state subtrees, so
    the file has no runtime clock state and is not meant to be merged.

    Consensus: every compare 'exact' value must agree across the non-PDCe
    reference DCs, evaluated per OS cohort (CurrentBuildNumber). Database
    entries with OS-divergent defaults (defaults_overrides) are EXCLUDED
    from the baseline with a loud warning naming them - those values are
    audited against per-OS Microsoft defaults instead. Any disagreement is a
    terminating error (FullyQualifiedErrorId
    BaselineConsensusFailure,Export-WinTimeConfigBaseline) whose TargetObject
    is the disagreeing record set and whose message is a mini drift report.
    -Force does NOT override consensus - it only covers file overwrites.

    When the forest-root PDC emulator is among the targets, its pdce-exempt
    values are written to a companion '<base>.pdce.reg' (single source -
    review by hand); non-PDCe copies of pdce-exempt values are
    consensus-checked into the DC baseline like exact values.

    Every generated file starts with '; WinTimeHealth AUDIT BASELINE - do
    not merge into a registry' and provenance comments (source DCs, UTC
    timestamp, OS builds, module and schema version, current PDCe FQDN) that
    Get-WinTimeConfig later validates for staleness.

    -WhatIf resolves the targets and reports the intended file paths without
    scanning anything.

    .PARAMETER DomainControllers
    (Set 'Named') Exact FQDNs of the reference DCs to capture from. Accepts
    pipeline input by property name (aliases: Server, ComputerName,
    DnsHostName). No wildcards - a baseline source must be deliberate.

    .PARAMETER ExportAllDCs
    (Set 'All') Capture from every domain controller in the forest.

    .PARAMETER OutFile
    Path of the DC baseline .reg file to write. The PDCe companion (when
    applicable) is written next to it as '<base>.pdce.reg'.

    .PARAMETER Force
    Overwrite existing output files (covers the companion too). Does NOT
    override a consensus failure.

    .PARAMETER Credential
    Alternate credential (IPC$ session per target; never on a command line).

    .PARAMETER ThrottleLimit
    Maximum concurrent scan workers (1-128, default 32).

    .PARAMETER RetryCount
    Retries per target for transport-class failures only (0-10, default 3).

    .PARAMETER TimeoutSeconds
    Best-effort per-attempt registry read budget (5-300, default 30).

    .EXAMPLE
    PS> Export-WinTimeConfigBaseline -DomainControllers dc1.corp.example.com, dc2.corp.example.com -OutFile .\dc-baseline.reg

    Captures a consensus baseline from two known-good reference DCs.

    .EXAMPLE
    PS> Export-WinTimeConfigBaseline -ExportAllDCs -OutFile .\forest-baseline.reg -WhatIf

    Resolves every DC in the forest and reports which files would be written
    - without scanning.

    .EXAMPLE
    PS> Import-Csv .\golden-dcs.csv | Export-WinTimeConfigBaseline -OutFile .\dc-baseline.reg -Force

    Pipes a curated reference list (Server column) into the export,
    overwriting a previous baseline file and its .pdce.reg companion.

    .OUTPUTS
    System.IO.FileInfo - one object per file written (baseline, then the
    PDCe companion when applicable).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Named')]
    [OutputType([System.IO.FileInfo])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Justification = 'Server lookup tables require an explicit OrdinalIgnoreCase comparer per DESIGN.md; literal @{} hashtables use culture-aware case-insensitive comparison instead.')]
    param(
        [Parameter(ParameterSetName = 'Named', Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('Server', 'ComputerName', 'DnsHostName')]
        [ValidateNotNullOrEmpty()]
        [string[]]$DomainControllers,

        [Parameter(ParameterSetName = 'All', Mandatory = $true)]
        [switch]$ExportAllDCs,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutFile,

        [Parameter()]
        [switch]$Force,

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
        [int]$TimeoutSeconds = 30
    )

    begin {
        Set-StrictMode -Version Latest
        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        $requestedNames = New-Object 'System.Collections.Generic.List[string]'

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

        function Get-TreeValueEntry {
            param([hashtable]$KeyValues, [string]$Name)
            if ($null -eq $KeyValues) { return $null }
            if ($KeyValues.ContainsKey($Name)) { return $KeyValues[$Name] }
            foreach ($key in $KeyValues.Keys) {
                if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $KeyValues[$key] }
            }
            return $null
        }

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

        # Canonical consensus signature for one @{Kind;Data} entry: kind plus a
        # normalized rendering (strings OrdinalIgnoreCase, numbers unsigned
        # decimal, multi-strings element-wise, binary hex). '(absent)' when null.
        function Get-ConsensusSignature {
            param($Entry)
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            if ($null -eq $Entry) { return '(absent)' }
            $kind = [string](Get-HashField -Table $Entry -Name 'Kind' -Default 'Unknown')
            $data = Get-HashField -Table $Entry -Name 'Data' -Default $null
            $rendered = ''
            if ($null -eq $data) {
                $rendered = ''
            } elseif ($data -is [string]) {
                $rendered = $data.ToUpperInvariant()
            } elseif ($data -is [byte[]]) {
                $hexParts = foreach ($byte in $data) { $byte.ToString('X2', $culture) }
                $rendered = ($hexParts -join ',')
            } elseif (($data -is [System.Collections.IEnumerable]) -and ($data -isnot [string])) {
                $parts = New-Object 'System.Collections.Generic.List[string]'
                foreach ($element in $data) {
                    if ($null -eq $element) { $parts.Add('') }
                    elseif ($element -is [string]) { $parts.Add($element.ToUpperInvariant()) }
                    else { $parts.Add([string]::Format($culture, '{0}', $element)) }
                }
                $rendered = ($parts -join [string][char]31)
            } else {
                $rendered = [string]::Format($culture, '{0}', $data)
            }
            return ($kind + '|' + $rendered)
        }

        # Human rendering of one @{Kind;Data} entry for the mini drift report.
        function Format-EntryData {
            param($Entry)
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            if ($null -eq $Entry) { return '(absent)' }
            $data = Get-HashField -Table $Entry -Name 'Data' -Default $null
            if ($null -eq $data) { return '(empty)' }
            if ($data -is [string]) { return $data }
            if ($data -is [byte[]]) {
                $hexParts = foreach ($byte in $data) { $byte.ToString('x2', $culture) }
                return ('hex:' + ($hexParts -join ','))
            }
            if (($data -is [System.Collections.IEnumerable]) -and ($data -isnot [string])) {
                $parts = New-Object 'System.Collections.Generic.List[string]'
                foreach ($element in $data) { $parts.Add([string]::Format($culture, '{0}', $element)) }
                return ($parts -join '|')
            }
            return [string]::Format($culture, '{0}', $data)
        }
    }

    process {
        if (($PSCmdlet.ParameterSetName -eq 'Named') -and ($null -ne $DomainControllers)) {
            foreach ($name in $DomainControllers) {
                if (-not [string]::IsNullOrWhiteSpace($name)) { $requestedNames.Add($name.Trim()) }
            }
        }
    }

    end {
        if (-not $script:IsWindowsPlatform) {
            throw 'Export-WinTimeConfigBaseline: scanning requires Windows (SMB remote registry). The module imports on this platform for tests and tooling only.'
        }

        $runStartUtc = [datetime]::UtcNow
        $timestamp = $runStartUtc.ToString('o', $invariant)
        $runId = [guid]::NewGuid().ToString()

        $moduleVersion = '0.1.0'
        $thisModule = $MyInvocation.MyCommand.Module
        if ($null -ne $thisModule -and $null -ne $thisModule.Version) { $moduleVersion = $thisModule.Version.ToString() }

        $database = Get-W32TimeDatabase
        $schemaVersionText = [string](Get-HashField -Table $database -Name 'SchemaVersion' -Default '')

        # ---- output paths -----------------------------------------------------
        $outResolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        if (-not $outResolved.EndsWith('.reg', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning ("Export-WinTimeConfigBaseline: output file '{0}' does not end in .reg." -f $outResolved)
        }
        $companionResolved = [System.IO.Path]::ChangeExtension($outResolved, 'pdce.reg')

        # ---- resolve targets (no scanning yet: -WhatIf stops after this) -------
        # Resolve-WinTimeTarget returns ONE hashtable @{ Targets; RootPdce;
        # Warnings } - not a target array.
        $resolveParams = @{}
        if ($PSBoundParameters.ContainsKey('Credential')) { $resolveParams['Credential'] = $Credential }
        $discovery = Resolve-WinTimeTarget @resolveParams
        $allTargets = @(Get-HashField -Table $discovery -Name 'Targets' -Default @())
        foreach ($discoveryWarning in @(Get-HashField -Table $discovery -Name 'Warnings' -Default @())) {
            Write-Warning ("Export-WinTimeConfigBaseline: {0}" -f $discoveryWarning)
        }

        $targets = @()
        if ($PSCmdlet.ParameterSetName -eq 'All') {
            $targets = $allTargets
        } else {
            $selected = New-Object 'System.Collections.Generic.List[object]'
            $missing = New-Object 'System.Collections.Generic.List[string]'
            $seen = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($name in $requestedNames) {
                if ($seen.ContainsKey($name)) { continue }
                $seen[$name] = $true
                $match = $null
                foreach ($candidate in $allTargets) {
                    if ([string]::Equals([string]$candidate.ComputerName, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $match = $candidate; break }
                }
                if ($null -ne $match) { $selected.Add($match) } else { $missing.Add($name) }
            }
            if ($missing.Count -gt 0) {
                $exception = New-Object System.ArgumentException ([string]::Format($invariant, 'These -DomainControllers were not found in the forest (exact FQDNs required): {0}', ($missing.ToArray() -join ', ')))
                $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'TargetNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $missing.ToArray())
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            $targets = $selected.ToArray()
        }
        if ($targets.Count -eq 0) {
            $exception = New-Object System.InvalidOperationException 'No reference domain controllers resolved; nothing to export.'
            $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'NoTargets', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $pdceTarget = $null
        foreach ($target in $targets) {
            if ($target.IsRootPdce) { $pdceTarget = $target; break }
        }
        # RootPdce is resolved against the whole forest regardless of which
        # DCs were requested, so it is authoritative here directly.
        $currentPdceFqdn = [string](Get-HashField -Table $discovery -Name 'RootPdce' -Default '')

        # ---- ShouldProcess gate: -WhatIf reports intent without scanning --------
        $intent = [string]::Format($invariant, "DC baseline '{0}' from {1} reference DC(s)", $outResolved, $targets.Count)
        if ($null -ne $pdceTarget) {
            $intent = $intent + [string]::Format($invariant, " and PDCe companion '{0}' (from {1})", $companionResolved, [string]$pdceTarget.ComputerName)
        }
        if (-not $PSCmdlet.ShouldProcess($intent, 'Export W32Time configuration baseline')) {
            return
        }

        # ---- overwrite pre-check (covers the companion; fail before scanning) ----
        $plannedPaths = New-Object 'System.Collections.Generic.List[string]'
        $plannedPaths.Add($outResolved)
        if ($null -ne $pdceTarget) { $plannedPaths.Add($companionResolved) }
        foreach ($plannedPath in $plannedPaths) {
            if ((Test-Path -LiteralPath $plannedPath) -and (-not $Force)) {
                $exception = New-Object System.IO.IOException ([string]::Format($invariant, "File '{0}' already exists. Use -Force to overwrite.", $plannedPath))
                $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'FileExists', [System.Management.Automation.ErrorCategory]::ResourceExists, $plannedPath)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }

        # ---- scan -----------------------------------------------------------------
        $readSpec = @(
            @{ Path = 'SYSTEM\CurrentControlSet\Services\W32Time'; Recursive = $true },
            @{ Path = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Recursive = $false }
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

        $targetByName = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($target in $targets) { $targetByName[[string]$target.ComputerName] = $target }

        $successes = New-Object 'System.Collections.Generic.List[object]'
        foreach ($result in $scanResults) {
            $server = [string](Get-HashField -Table $result -Name 'ComputerName' -Default '')
            $target = $null
            if ($targetByName.ContainsKey($server)) { $target = $targetByName[$server] }
            $success = [bool](Get-HashField -Table $result -Name 'Success' -Default $false)
            $tree = Get-HashField -Table $result -Name 'Tree' -Default $null
            if ($success -and ($null -ne $tree) -and ($null -ne $target)) {
                $successes.Add(@{ Target = $target; Tree = $tree; OsBuild = (Get-OsBuildFromTree -Tree $tree); Server = $server })
            } else {
                $status = [pscustomobject]@{
                    PSTypeName = 'WinTime.ScanStatus'
                    Server     = $server
                    Domain     = ''
                    Success    = $false
                    Attempts   = [int](Get-HashField -Table $result -Name 'Attempts' -Default 0)
                    LastError  = [string](Get-HashField -Table $result -Name 'Error' -Default '')
                    ErrorClass = [string](Get-HashField -Table $result -Name 'ErrorClass' -Default 'Unknown')
                    DurationMs = [int](Get-HashField -Table $result -Name 'DurationMs' -Default 0)
                    OsBuild    = 0
                    RunId      = $runId
                    Timestamp  = $timestamp
                }
                if ($null -ne $target) { $status.Domain = [string]$target.Domain }
                Write-Error -Message ([string]::Format($invariant, 'baseline scan failed for {0} [{1}]: {2}', $server, $status.ErrorClass, $status.LastError)) `
                    -ErrorId 'ScanFailure' -Category ConnectionError -TargetObject $status
            }
        }
        if ($successes.Count -eq 0) {
            $exception = New-Object System.InvalidOperationException 'Every reference DC scan failed; no baseline can be captured.'
            $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'NoScanResults', [System.Management.Automation.ErrorCategory]::ConnectionError, $null)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $pdceSuccess = $null
        $consensusSources = New-Object 'System.Collections.Generic.List[object]'
        foreach ($success in $successes) {
            if ([bool]$success['Target'].IsRootPdce) { $pdceSuccess = $success } else { $consensusSources.Add($success) }
        }
        if ($consensusSources.Count -eq 0) {
            # Degenerate but legal: only the PDCe was exportable. Its non-exempt
            # values become the DC baseline (single source).
            Write-Warning 'Export-WinTimeConfigBaseline: no non-PDCe reference DC succeeded; the DC baseline is captured from the PDCe alone - review by hand.'
            foreach ($success in $successes) { $consensusSources.Add($success) }
        }

        # ---- consensus + content policy (DESIGN section 4) ------------------------
        $baselineTree = @{}
        $companionTree = @{}
        $excludedOverrideNames = New-Object 'System.Collections.Generic.List[string]'
        $disagreements = New-Object 'System.Collections.Generic.List[object]'
        $disagreementLines = New-Object 'System.Collections.Generic.List[string]'

        foreach ($entry in @(Get-HashField -Table $database -Name 'Keys' -Default @())) {
            $entryClass = [string](Get-HashField -Table $entry -Name 'class' -Default '')
            $entryCompare = [string](Get-HashField -Table $entry -Name 'compare' -Default '')
            $entryPath = [string](Get-HashField -Table $entry -Name 'path' -Default '')
            $entryValue = [string](Get-HashField -Table $entry -Name 'value' -Default '')
            $entryLabel = $entryPath + '\' + $entryValue

            # Content policy: config values plus internal tamper values with
            # compare exact. Never ignore values, never diagnostic, never subtrees.
            if ([string]::Equals($entryCompare, 'ignore', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $isConfig = [string]::Equals($entryClass, 'config', [System.StringComparison]::OrdinalIgnoreCase)
            $isInternalExact = ([string]::Equals($entryClass, 'internal', [System.StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals($entryCompare, 'exact', [System.StringComparison]::OrdinalIgnoreCase))
            if (-not ($isConfig -or $isInternalExact)) { continue }

            # OS-divergent defaults never enter a shared baseline.
            $overrides = Get-HashField -Table $entry -Name 'defaults_overrides' -Default $null
            if (($null -ne $overrides) -and (@($overrides).Count -gt 0)) {
                $excludedOverrideNames.Add($entryLabel)
                continue
            }

            $isPdceExempt = [string]::Equals($entryCompare, 'pdce-exempt', [System.StringComparison]::OrdinalIgnoreCase)

            # PDCe copy of a pdce-exempt value goes to the companion file.
            if ($isPdceExempt -and ($null -ne $pdceSuccess)) {
                $pdceKey = Get-TreeKey -Tree $pdceSuccess['Tree'] -Path $entryPath
                $pdceEntry = Get-TreeValueEntry -KeyValues $pdceKey -Name $entryValue
                if ($null -ne $pdceEntry) {
                    if (-not $companionTree.ContainsKey($entryPath)) { $companionTree[$entryPath] = @{} }
                    $companionTree[$entryPath][$entryValue] = @{ Kind = $pdceEntry['Kind']; Data = $pdceEntry['Data'] }
                }
            }

            # Consensus across the (per-OS-cohort grouped) non-PDCe sources.
            $signatureMap = New-Object 'System.Collections.Specialized.OrderedDictionary'
            foreach ($source in $consensusSources) {
                if ($isPdceExempt -and [bool]$source['Target'].IsRootPdce) { continue }
                $sourceKey = Get-TreeKey -Tree $source['Tree'] -Path $entryPath
                $sourceEntry = Get-TreeValueEntry -KeyValues $sourceKey -Name $entryValue
                $signature = Get-ConsensusSignature -Entry $sourceEntry
                if (-not $signatureMap.Contains($signature)) {
                    $signatureMap[$signature] = @{ Entry = $sourceEntry; Sources = (New-Object 'System.Collections.Generic.List[object]') }
                }
                $signatureMap[$signature]['Sources'].Add($source)
            }
            if ($signatureMap.Count -eq 0) { continue }

            if ($signatureMap.Count -gt 1) {
                # Disagreement: collect the mini drift report line and the
                # ConfigRecord set for the terminating error's TargetObject.
                $variantTexts = New-Object 'System.Collections.Generic.List[string]'
                foreach ($signature in $signatureMap.Keys) {
                    $variant = $signatureMap[$signature]
                    $serverTexts = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($source in $variant['Sources']) {
                        $serverTexts.Add([string]::Format($invariant, '{0} (build {1})', $source['Server'], $source['OsBuild']))
                        $disagreements.Add([pscustomobject]@{
                                PSTypeName     = 'WinTime.ConfigRecord'
                                Server         = [string]$source['Server']
                                Domain         = [string]$source['Target'].Domain
                                Role           = 'Dc'
                                OsBuild        = [int]$source['OsBuild']
                                KeyPath        = $entryPath
                                ValueName      = $entryValue
                                Type           = [string](Get-HashField -Table $entry -Name 'type' -Default '')
                                Data           = (Format-EntryData -Entry (Get-TreeValueEntry -KeyValues (Get-TreeKey -Tree $source['Tree'] -Path $entryPath) -Name $entryValue))
                                Expected       = $null
                                ExpectedSource = 'Baseline'
                                Status         = 'Drift'
                                IsDrift        = $true
                                Class          = $entryClass
                                GpoBacked      = ($null -ne (Get-HashField -Table $entry -Name 'gpo' -Default $null))
                                PolicyApplied  = $false
                                Note           = 'baseline consensus disagreement across reference DCs'
                                RunId          = $runId
                                Timestamp      = $timestamp
                            })
                    }
                    $variantTexts.Add([string]::Format($invariant, '{0} on {1}', (Format-EntryData -Entry $variant['Entry']), ($serverTexts.ToArray() -join ', ')))
                }
                $disagreementLines.Add([string]::Format($invariant, '  {0}: {1}', $entryLabel, ($variantTexts.ToArray() -join '; ')))
                continue
            }

            # Single agreed variant: absent everywhere -> omit; present -> capture.
            $agreedSignature = @($signatureMap.Keys)[0]
            $agreed = $signatureMap[$agreedSignature]['Entry']
            if ($null -eq $agreed) { continue }
            if (-not $baselineTree.ContainsKey($entryPath)) { $baselineTree[$entryPath] = @{} }
            $baselineTree[$entryPath][$entryValue] = @{ Kind = $agreed['Kind']; Data = $agreed['Data'] }
        }

        if ($excludedOverrideNames.Count -gt 0) {
            Write-Warning ([string]::Format($invariant,
                    'Export-WinTimeConfigBaseline: {0} value(s) with OS-divergent defaults were EXCLUDED from the baseline and will be audited against per-OS Microsoft defaults instead: {1}',
                    $excludedOverrideNames.Count, ($excludedOverrideNames.ToArray() -join ', ')))
        }

        if ($disagreementLines.Count -gt 0) {
            $reportText = "Baseline consensus failure - compare:exact values disagree across the reference DCs (fix the drift or pick a homogeneous reference set; -Force does not override consensus):" `
                + [System.Environment]::NewLine + ($disagreementLines.ToArray() -join [System.Environment]::NewLine)
            $exception = New-Object System.InvalidOperationException $reportText
            $errorRecord = New-Object System.Management.Automation.ErrorRecord ($exception, 'BaselineConsensusFailure', [System.Management.Automation.ErrorCategory]::InvalidData, $disagreements.ToArray())
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        # ---- provenance + write (DESIGN sections 4 and 9) ---------------------------
        $sourceNames = @($consensusSources | ForEach-Object { [string]$_['Server'] } | Sort-Object -Unique)
        $buildNames = @($successes | ForEach-Object { ([int]$_['OsBuild']).ToString($invariant) } | Sort-Object -Unique)
        $pdceText = $currentPdceFqdn
        if ($pdceText.Length -eq 0) { $pdceText = '(not detected)' }

        # ConvertTo-RegFile owns the banner line and '; key: value' comment
        # rendering itself (Provenance hashtable in, known keys first); it has
        # no -Force switch by contract - the overwrite pre-check above already
        # covers both the baseline and its companion before any scanning ran.
        $baselineProvenance = @{
            SourceDCs     = $sourceNames
            Timestamp     = $timestamp
            OsBuilds      = $buildNames
            ModuleVersion = $moduleVersion
            SchemaVersion = $schemaVersionText
            Pdce          = $pdceText
        }
        $null = ConvertTo-RegFile -Tree $baselineTree -Path $outResolved -Provenance $baselineProvenance
        Write-Verbose ("Export-WinTimeConfigBaseline: wrote DC baseline '{0}' ({1} key(s))." -f $outResolved, $baselineTree.Count)
        Get-Item -LiteralPath $outResolved

        if ($null -ne $pdceTarget) {
            if ($null -eq $pdceSuccess) {
                Write-Warning ("Export-WinTimeConfigBaseline: the PDCe {0} was targeted but its scan failed; no .pdce.reg companion was written." -f [string]$pdceTarget.ComputerName)
            } else {
                Write-Warning 'Export-WinTimeConfigBaseline: the .pdce.reg companion is captured from a single source (the PDCe) - review it by hand before treating it as authoritative.'
                $companionProvenance = @{
                    SourceDCs     = [string]$pdceSuccess['Server']
                    Timestamp     = $timestamp
                    OsBuilds      = ([int]$pdceSuccess['OsBuild']).ToString($invariant)
                    ModuleVersion = $moduleVersion
                    SchemaVersion = $schemaVersionText
                    Pdce          = $pdceText
                    Note          = 'single-source PDCe values (pdce-exempt) - review by hand'
                }
                $null = ConvertTo-RegFile -Tree $companionTree -Path $companionResolved -Provenance $companionProvenance
                Write-Verbose ("Export-WinTimeConfigBaseline: wrote PDCe companion '{0}' ({1} key(s))." -f $companionResolved, $companionTree.Count)
                Get-Item -LiteralPath $companionResolved
            }
        }
    }
}
