# Invoke-WinTimeHealthEvaluation.ps1 - pure (no-network) health check engine
# implementing the DESIGN section 8 check catalog, plus the fleet-level
# RefidLoop analysis (Get-WinTimeRefidLoopFinding) and the shared
# WinTime.HealthRecord factory. The fleet-level function lives in this file per
# the component contract.

function New-WinTimeHealthRecord {
<#
.SYNOPSIS
Creates a WinTime.HealthRecord object (DESIGN section 3).

.DESCRIPTION
Single factory for typed health records so property names/order and the
PSTypeName stay identical between the per-server evaluation and the
fleet-level RefidLoop analysis.

.PARAMETER Server
Canonical FQDN of the evaluated server.

.PARAMETER Domain
DNS domain of the server.

.PARAMETER Role
Dc or RootPdce.

.PARAMETER Check
Check catalog name (Service, NtpQuery, Offset, ...).

.PARAMETER Status
Pass | Warn | Fail | Error | Blocked | NotApplicable.

.PARAMETER Detail
Self-sufficient human-readable finding text.

.PARAMETER Data
Supporting values (hashtable; the CSV projection flattens it to JSON).

.PARAMETER RunId
Run GUID shared by every record of one invocation.

.PARAMETER Timestamp
ISO-8601 invariant timestamp shared by every record of one invocation.

.OUTPUTS
System.Management.Automation.PSCustomObject (PSTypeName WinTime.HealthRecord)

.EXAMPLE
New-WinTimeHealthRecord -Server dc1.corp.example -Domain corp.example -Role Dc -Check Service -Status Pass -Detail 'running' -Data @{} -RunId $id -Timestamp $ts

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory record factory; changes no system state.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Domain,
        [Parameter(Mandatory = $true)][ValidateSet('Dc', 'RootPdce')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Warn', 'Fail', 'Error', 'Blocked', 'NotApplicable')][string]$Status,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Detail,
        [Parameter()][hashtable]$Data = @{},
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )

    if ($null -eq $Data) { $Data = @{} }
    return [pscustomobject]@{
        PSTypeName = 'WinTime.HealthRecord'
        Server     = $Server
        Domain     = $Domain
        Role       = $Role
        Check      = $Check
        Status     = $Status
        Detail     = $Detail
        Data       = $Data
        RunId      = $RunId
        Timestamp  = $Timestamp
    }
}

function Invoke-WinTimeHealthEvaluation {
<#
.SYNOPSIS
Evaluates the per-server W32Time health check catalog (DESIGN section 8) from
already-collected inputs. Pure function - performs no network I/O.

.DESCRIPTION
Implements the ten-check catalog minus the fleet-level RefidLoop (see
Get-WinTimeRefidLoopFinding). Semantics:

  - Transports are independent: when -Tree is $null (registry scan failed) the
    registry-backed checks report Error 'registry scan failed', while the
    UDP-backed checks (NtpQuery/Offset/Stratum/LastSync) still evaluate.
  - A reachable registry with no W32Time service key (Samba / non-Windows DC)
    turns the registry-backed checks into NotApplicable.
  - A failed NtpQuery Blocks Offset, Stratum and LastSync (one root cause, no
    Fail cascades); the Source check loses only its NTP layer.
  - Effective registry values resolve policy-twin first (GPO wins), then the
    operational value, then the role/OS default from the database.
  - LastSync auto-thresholds: warn above 2 x 2^MaxPollInterval (per-server
    effective value), fail above ClockHoldoverPeriod (7800 fallback when the
    value is absent, i.e. pre-1709).

.PARAMETER Target
Resolved target object: @{ ComputerName; Domain; Site; IsRootPdce; IsRodc;
DomainDepth }.

.PARAMETER Tree
Registry tree from the scan worker (hashtable path -> valueName ->
@{Kind;Data}), or $null when the registry scan failed.

.PARAMETER ScmStatus
Service Control Manager status string for w32time ('Running', 'Stopped', ...)
or $null/empty when the SCM query failed.

.PARAMETER Ntp
Invoke-NtpQuery result hashtable for this server, or $null when no probe ran.

.PARAMETER PdceNtp
Invoke-NtpQuery result for the forest-root PDCe hidden reference, or $null.

.PARAMETER Checks
Check names to evaluate (subset of the catalog); empty/absent = all. The
fleet-level 'RefidLoop' name is ignored here.

.PARAMETER Thresholds
Optional keys: OffsetWarnMilliseconds (500), OffsetFailMilliseconds (5000),
StratumDepthSlack (1), LastSyncWarnSeconds (0 = auto), LastSyncFailSeconds
(0 = auto), KnownReliableTimeServers (string[]).

.PARAMETER Database
Get-W32TimeDatabase result (policy twin paths and role/OS defaults).

.PARAMETER RunId
Run GUID stamped on every record.

.PARAMETER Timestamp
ISO-8601 invariant timestamp stamped on every record.

.OUTPUTS
WinTime.HealthRecord (one per selected check, catalog order)

.EXAMPLE
Invoke-WinTimeHealthEvaluation -Target $t -Tree $tree -ScmStatus Running -Ntp $ntp -PdceNtp $ref -Checks @() -Thresholds @{} -Database $db -RunId $id -Timestamp $ts

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ScmStatus', Justification = 'Read only inside the nested Test-ServiceCheck closure; PSScriptAnalyzer does not trace nested-function closures.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'PdceNtp', Justification = 'Read only inside nested closures (Test-OffsetCheck, Test-StratumCheck, ...).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Database', Justification = 'Read only inside the nested Get-DbEntry closure.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'RunId', Justification = 'Read only inside the nested New-Record closure (stamped on every record).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Timestamp', Justification = 'Read only inside the nested New-Record closure (stamped on every record).')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Target,

        [Parameter()]
        [AllowNull()]
        [hashtable]$Tree = $null,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ScmStatus = $null,

        [Parameter()]
        [AllowNull()]
        [hashtable]$Ntp = $null,

        [Parameter()]
        [AllowNull()]
        [hashtable]$PdceNtp = $null,

        [Parameter()]
        [AllowNull()]
        [string[]]$Checks = @(),

        [Parameter()]
        [hashtable]$Thresholds = @{},

        [Parameter(Mandatory = $true)]
        [hashtable]$Database,

        [Parameter(Mandatory = $true)]
        [string]$RunId,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp
    )

    # ---- constants ---------------------------------------------------------
    $svcRoot = 'SYSTEM\CurrentControlSet\Services\W32Time'
    $configKey = "$svcRoot\Config"
    $paramsKey = "$svcRoot\Parameters"
    $ntpClientKey = "$svcRoot\TimeProviders\NtpClient"
    $ntpServerKey = "$svcRoot\TimeProviders\NtpServer"
    $vmicKey = "$svcRoot\TimeProviders\VMICTimeProvider"
    $secureLimitsKey = "$svcRoot\SecureTimeLimits"
    $currentVersionKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $systemInfoKey = 'SYSTEM\CurrentControlSet\Control\SystemInformation'
    $localServiceIdentity = 'NT AUTHORITY\LocalService'

    $role = 'Dc'
    if ([bool]$Target.IsRootPdce) { $role = 'RootPdce' }
    $server = [string]$Target.ComputerName
    $domain = [string]$Target.Domain

    # ---- nested helpers (read-only closures over the parameters) -----------

    function Format-InvariantNumber {
        # All numeric text in Detail strings goes through InvariantCulture.
        param([Parameter(Mandatory = $true)][double]$Value, [string]$FormatSpec = '0.###')
        return $Value.ToString($FormatSpec, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    function Get-TreeKey {
        # Registry path lookup with OrdinalIgnoreCase semantics; returns the
        # valueName->@{Kind;Data} hashtable or $null.
        param([Parameter(Mandatory = $true)][string]$Path)
        if ($null -eq $Tree) { return $null }
        if ($Tree.ContainsKey($Path)) { return $Tree[$Path] }
        foreach ($k in $Tree.Keys) {
            if ([string]::Equals([string]$k, $Path, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Tree[$k]
            }
        }
        return $null
    }

    function Get-TreeValue {
        # Returns @{ Present = [bool]; Data = <object or $null> }.
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$Name
        )
        $key = Get-TreeKey -Path $Path
        if ($null -eq $key -or $key -isnot [hashtable]) { return @{ Present = $false; Data = $null } }
        $entry = $null
        if ($key.ContainsKey($Name)) {
            $entry = $key[$Name]
        }
        else {
            foreach ($n in $key.Keys) {
                if ([string]::Equals([string]$n, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $entry = $key[$n]
                    break
                }
            }
        }
        if ($null -eq $entry) { return @{ Present = $false; Data = $null } }
        $data = $null
        if ($entry -is [hashtable] -and $entry.ContainsKey('Data')) { $data = $entry['Data'] }
        return @{ Present = $true; Data = $data }
    }

    function Get-DbEntry {
        # Database key entry for path\value (OrdinalIgnoreCase), or $null.
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$Name
        )
        if (-not $Database.ContainsKey('Keys') -or $null -eq $Database['Keys']) { return $null }
        foreach ($entry in @($Database['Keys'])) {
            if ($entry -isnot [hashtable]) { continue }
            if (-not $entry.ContainsKey('path') -or -not $entry.ContainsKey('value')) { continue }
            if ([string]::Equals([string]$entry['path'], $Path, [System.StringComparison]::OrdinalIgnoreCase) -and
                [string]::Equals([string]$entry['value'], $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $entry
            }
        }
        return $null
    }

    function Get-EffectiveValue {
        # Policy twin (path from the database entry's gpo block) wins over the
        # operational value. Returns @{ Present; Data; PolicyApplied }.
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$Name
        )
        $entry = Get-DbEntry -Path $Path -Name $Name
        $policyPath = $null
        if ($null -ne $entry -and $entry.ContainsKey('gpo') -and $entry['gpo'] -is [hashtable] -and $entry['gpo'].ContainsKey('policy_path')) {
            $policyPath = [string]$entry['gpo']['policy_path']
        }
        if (-not [string]::IsNullOrEmpty($policyPath)) {
            $p = Get-TreeValue -Path $policyPath -Name $Name
            if ($p['Present']) {
                return @{ Present = $true; Data = $p['Data']; PolicyApplied = $true }
            }
        }
        $o = Get-TreeValue -Path $Path -Name $Name
        return @{ Present = [bool]$o['Present']; Data = $o['Data']; PolicyApplied = $false }
    }

    function Get-DcDefaultValue {
        # DC-role default from the database (defaults.dc with member fallback,
        # then build-conditional defaults_overrides), else the hardcoded
        # fallback from the check catalog.
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$Name,
            [Parameter()][AllowNull()]$Fallback = $null
        )
        $entry = Get-DbEntry -Path $Path -Name $Name
        if ($null -eq $entry) { return $Fallback }
        $value = $Fallback
        if ($entry.ContainsKey('defaults') -and $entry['defaults'] -is [hashtable]) {
            $defaults = $entry['defaults']
            if ($defaults.ContainsKey('dc') -and $null -ne $defaults['dc']) { $value = $defaults['dc'] }
            elseif ($defaults.ContainsKey('member') -and $null -ne $defaults['member']) { $value = $defaults['member'] }
        }
        if ($osBuild -gt 0 -and $entry.ContainsKey('defaults_overrides') -and $null -ne $entry['defaults_overrides']) {
            foreach ($override in @($entry['defaults_overrides'])) {
                if ($override -isnot [hashtable] -or -not $override.ContainsKey('value')) { continue }
                $matches2 = $true
                if ($override.ContainsKey('min_build') -and $null -ne $override['min_build'] -and $osBuild -lt [long]$override['min_build']) { $matches2 = $false }
                if ($matches2 -and $override.ContainsKey('max_build') -and $null -ne $override['max_build'] -and $osBuild -gt [long]$override['max_build']) { $matches2 = $false }
                if ($matches2 -and $override.ContainsKey('role') -and $null -ne $override['role']) {
                    # 'dc' covers Dc and RootPdce; member/standalone never match here.
                    if (-not [string]::Equals([string]$override['role'], 'dc', [System.StringComparison]::OrdinalIgnoreCase)) { $matches2 = $false }
                }
                if ($matches2) {
                    $value = $override['value']
                    break
                }
            }
        }
        return $value
    }

    function Get-EffectiveOrDefault {
        # Effective (policy/operational) value, else the DC default.
        # Returns @{ Value; Present(=found in registry); PolicyApplied }.
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$Name,
            [Parameter()][AllowNull()]$Fallback = $null
        )
        $e = Get-EffectiveValue -Path $Path -Name $Name
        if ($e['Present']) {
            return @{ Value = $e['Data']; Present = $true; PolicyApplied = [bool]$e['PolicyApplied'] }
        }
        return @{ Value = (Get-DcDefaultValue -Path $Path -Name $Name -Fallback $Fallback); Present = $false; PolicyApplied = $false }
    }

    function Test-KnownReliable {
        param([Parameter(Mandatory = $true)][string]$Name)
        foreach ($known in $knownReliable) {
            if ([string]::Equals([string]$known, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }

    function New-Record {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory record factory; changes no system state.')]
        param(
            [Parameter(Mandatory = $true)][string]$Check,
            [Parameter(Mandatory = $true)][string]$Status,
            [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Detail,
            [Parameter()][hashtable]$Data = @{}
        )
        return New-WinTimeHealthRecord -Server $server -Domain $domain -Role $role -Check $Check -Status $Status -Detail $Detail -Data $Data -RunId $RunId -Timestamp $Timestamp
    }

    # ---- shared derived state ----------------------------------------------

    $treeAvailable = ($null -ne $Tree)

    # W32Time key presence: any path at/under the service root that actually
    # carries values. Absent on a reachable registry => Samba / non-Windows DC.
    $w32TimePresent = $false
    if ($treeAvailable) {
        $svcRootPrefix = $svcRoot + '\'
        foreach ($k in $Tree.Keys) {
            $ks = [string]$k
            if ([string]::Equals($ks, $svcRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
                $ks.StartsWith($svcRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $vals = $Tree[$k]
                if ($vals -is [hashtable] -and $vals.Count -gt 0) {
                    $w32TimePresent = $true
                    break
                }
            }
        }
    }

    $ntpOk = ($null -ne $Ntp) -and [bool]$Ntp['Success']
    $ntpBlockDetail = 'blocked by NtpQuery: no NTP query result available'
    if ($null -ne $Ntp -and -not $ntpOk) {
        $ntpBlockDetail = "blocked by NtpQuery failure: $($Ntp['Error'])"
    }

    # OS build from the scanned CurrentVersion key (0 = unknown).
    $osBuild = 0
    $buildValue = Get-TreeValue -Path $currentVersionKey -Name 'CurrentBuildNumber'
    if ($buildValue['Present']) {
        $parsedBuild = 0
        if ([int]::TryParse([string]$buildValue['Data'], [ref]$parsedBuild)) { $osBuild = $parsedBuild }
    }

    # Thresholds with catalog defaults; hashtable reads guarded for StrictMode.
    $offsetWarnMs = 500.0
    if ($Thresholds.ContainsKey('OffsetWarnMilliseconds') -and $null -ne $Thresholds['OffsetWarnMilliseconds']) { $offsetWarnMs = [double]$Thresholds['OffsetWarnMilliseconds'] }
    $offsetFailMs = 5000.0
    if ($Thresholds.ContainsKey('OffsetFailMilliseconds') -and $null -ne $Thresholds['OffsetFailMilliseconds']) { $offsetFailMs = [double]$Thresholds['OffsetFailMilliseconds'] }
    $stratumSlack = 1
    if ($Thresholds.ContainsKey('StratumDepthSlack') -and $null -ne $Thresholds['StratumDepthSlack']) { $stratumSlack = [int]$Thresholds['StratumDepthSlack'] }
    $lastSyncWarnSeconds = 0
    if ($Thresholds.ContainsKey('LastSyncWarnSeconds') -and $null -ne $Thresholds['LastSyncWarnSeconds']) { $lastSyncWarnSeconds = [double]$Thresholds['LastSyncWarnSeconds'] }
    $lastSyncFailSeconds = 0
    if ($Thresholds.ContainsKey('LastSyncFailSeconds') -and $null -ne $Thresholds['LastSyncFailSeconds']) { $lastSyncFailSeconds = [double]$Thresholds['LastSyncFailSeconds'] }
    $knownReliable = @()
    if ($Thresholds.ContainsKey('KnownReliableTimeServers') -and $null -ne $Thresholds['KnownReliableTimeServers']) { $knownReliable = @($Thresholds['KnownReliableTimeServers']) }

    # ---- check implementations ---------------------------------------------

    function Test-ServiceCheck {
        if (-not $treeAvailable) {
            return New-Record -Check 'Service' -Status 'Error' -Detail 'registry scan failed - service configuration unavailable' -Data @{}
        }
        if (-not $w32TimePresent) {
            return New-Record -Check 'Service' -Status 'NotApplicable' -Detail 'no W32Time service key present (Samba or non-Windows DC)' -Data @{}
        }
        $start = Get-TreeValue -Path $svcRoot -Name 'Start'
        $identity = Get-TreeValue -Path $svcRoot -Name 'ObjectName'
        $delayed = Get-TreeValue -Path $svcRoot -Name 'DelayedAutostart'
        $data = @{
            ScmStatus        = $ScmStatus
            Start            = $start['Data']
            ObjectName       = $identity['Data']
            DelayedAutostart = $delayed['Data']
        }
        if ($start['Present'] -and [uint32]$start['Data'] -eq 4) {
            return New-Record -Check 'Service' -Status 'Fail' -Detail 'w32time service is disabled (Start=4)' -Data $data
        }
        if ([string]::IsNullOrEmpty($ScmStatus)) {
            return New-Record -Check 'Service' -Status 'Error' -Detail 'service state unavailable (SCM query failed) - registry values captured only' -Data $data
        }
        if (-not [string]::Equals($ScmStatus, 'Running', [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-Record -Check 'Service' -Status 'Fail' -Detail "w32time is not running (SCM state: $ScmStatus)" -Data $data
        }
        $warnings = @()
        if (-not $start['Present']) {
            $warnings += 'Start value missing from the registry'
        }
        elseif ([uint32]$start['Data'] -ne 2 -and [uint32]$start['Data'] -ne 3) {
            # 3 (Manual, started via the domain-join trigger) is the real out-of-box default
            # on every role including DCs (MS KB2385818); 2 (Automatic) is a legitimate
            # MS-recommended hardening for high-accuracy scenarios. Neither is drift on its own.
            $warnings += "nonstandard Start=$($start['Data'])"
        }
        if ($delayed['Present'] -and [uint32]$delayed['Data'] -eq 1) {
            $warnings += 'DelayedAutostart is set'
        }
        if (-not $identity['Present']) {
            $warnings += 'ObjectName missing - cannot verify service identity'
        }
        elseif (-not [string]::Equals([string]$identity['Data'], $localServiceIdentity, [System.StringComparison]::OrdinalIgnoreCase)) {
            $warnings += "nonstandard service identity '$($identity['Data'])' (tamper hint)"
        }
        if ($warnings.Count -gt 0) {
            return New-Record -Check 'Service' -Status 'Warn' -Detail ('running, but: ' + ($warnings -join '; ')) -Data $data
        }
        $startDescription = if ($start['Present'] -and [uint32]$start['Data'] -eq 2) { 'Start=2 (Automatic)' } else { 'Start=3 (Manual, domain-join trigger-start)' }
        return New-Record -Check 'Service' -Status 'Pass' -Detail "w32time running, $startDescription, identity NT AUTHORITY\LocalService" -Data $data
    }

    function Test-NtpQueryCheck {
        if ($null -eq $Ntp) {
            return New-Record -Check 'NtpQuery' -Status 'Error' -Detail 'no NTP query result available (UDP/123 probe was not attempted)' -Data @{}
        }
        $data = @{
            SamplesSent    = $Ntp['SamplesSent']
            RepliesValid   = $Ntp['RepliesValid']
            SamplesLostPct = $Ntp['SamplesLostPct']
            DelaySeconds   = $Ntp['DelaySeconds']
            Error          = $Ntp['Error']
        }
        if ($ntpOk) {
            $loss = 0
            if ($null -ne $Ntp['SamplesLostPct']) { $loss = [int]$Ntp['SamplesLostPct'] }
            $delayText = ''
            if ($null -ne $Ntp['DelaySeconds']) {
                $delayText = ', best delay ' + (Format-InvariantNumber -Value ([double]$Ntp['DelaySeconds'] * 1000.0) -FormatSpec '0.0') + ' ms'
            }
            if ($loss -gt 50) {
                return New-Record -Check 'NtpQuery' -Status 'Warn' -Detail "replies received but $loss% probe loss ($($Ntp['RepliesValid'])/$($Ntp['SamplesSent']) valid)$delayText" -Data $data
            }
            return New-Record -Check 'NtpQuery' -Status 'Pass' -Detail "$($Ntp['RepliesValid'])/$($Ntp['SamplesSent']) valid replies$delayText" -Data $data
        }
        $detail = [string]$Ntp['Error']
        if ([string]::IsNullOrEmpty($detail)) { $detail = 'no valid NTP reply' }
        if ($treeAvailable -and $w32TimePresent) {
            # When the config shows RequireSecureTimeSyncRequests=1, that is the
            # primary hint for a silent UDP/123 (semantics pending lab verification).
            $rsts = Get-EffectiveValue -Path $ntpServerKey -Name 'RequireSecureTimeSyncRequests'
            if ($rsts['Present'] -and [uint32]$rsts['Data'] -eq 1) {
                $detail = "RequireSecureTimeSyncRequests=1 is configured - the DC may be refusing unauthenticated SNTP probes (semantics unverified). $detail"
            }
        }
        return New-Record -Check 'NtpQuery' -Status 'Error' -Detail $detail -Data $data
    }

    function Test-OffsetCheck {
        if ([bool]$Target.IsRootPdce) {
            return New-Record -Check 'Offset' -Status 'NotApplicable' -Detail 'forest-root PDCe is the offset reference point' -Data @{}
        }
        if (-not $ntpOk) {
            return New-Record -Check 'Offset' -Status 'Blocked' -Detail $ntpBlockDetail -Data @{}
        }
        if ($null -eq $PdceNtp -or -not [bool]$PdceNtp['Success']) {
            return New-Record -Check 'Offset' -Status 'Error' -Detail 'PDCe NTP reference unavailable (reference dead or unreachable over UDP/123) - offset vs PDCe cannot be computed' -Data @{ OffsetSeconds = $Ntp['OffsetSeconds'] }
        }
        # Differential offset: the admin host's own clock error cancels.
        $offsetVsPdce = [double]$Ntp['OffsetSeconds'] - [double]$PdceNtp['OffsetSeconds']
        $absMs = [math]::Abs($offsetVsPdce) * 1000.0
        $data = @{
            OffsetVsPdceSeconds = $offsetVsPdce
            OffsetSeconds       = $Ntp['OffsetSeconds']
            PdceOffsetSeconds   = $PdceNtp['OffsetSeconds']
            WarnMilliseconds    = $offsetWarnMs
            FailMilliseconds    = $offsetFailMs
        }
        $detail = 'offset vs PDCe = ' + (Format-InvariantNumber -Value ($offsetVsPdce * 1000.0) -FormatSpec '0.0') + ' ms (warn >= ' + (Format-InvariantNumber -Value $offsetWarnMs -FormatSpec '0') + ' ms, fail >= ' + (Format-InvariantNumber -Value $offsetFailMs -FormatSpec '0') + ' ms)'
        if ($absMs -ge $offsetFailMs) {
            return New-Record -Check 'Offset' -Status 'Fail' -Detail $detail -Data $data
        }
        if ($absMs -ge $offsetWarnMs) {
            return New-Record -Check 'Offset' -Status 'Warn' -Detail $detail -Data $data
        }
        return New-Record -Check 'Offset' -Status 'Pass' -Detail $detail -Data $data
    }

    function Test-StratumCheck {
        if (-not $ntpOk) {
            return New-Record -Check 'Stratum' -Status 'Blocked' -Detail $ntpBlockDetail -Data @{}
        }
        $stratum = [int]$Ntp['Stratum']
        $li = [int]$Ntp['LI']
        $data = @{ Stratum = $stratum; LI = $li; PdceStratum = $null; ExpectedBand = $null }
        if ($li -eq 3) {
            return New-Record -Check 'Stratum' -Status 'Fail' -Detail "leap indicator 3 (clock unsynchronized), stratum $stratum" -Data $data
        }
        if ($stratum -eq 0 -or $stratum -gt 15) {
            return New-Record -Check 'Stratum' -Status 'Fail' -Detail "invalid stratum $stratum (unsynchronized)" -Data $data
        }
        if (Test-KnownReliable -Name $server) {
            return New-Record -Check 'Stratum' -Status 'Pass' -Detail "stratum $stratum; declared known-reliable time server - hierarchy band not enforced" -Data $data
        }
        $pdceStratum = $null
        if ($null -ne $PdceNtp -and [bool]$PdceNtp['Success'] -and $null -ne $PdceNtp['Stratum']) {
            $pdceStratum = [int]$PdceNtp['Stratum']
        }
        if ($null -eq $pdceStratum) {
            # Reference degraded: absolute rules only (DESIGN section 8).
            return New-Record -Check 'Stratum' -Status 'Pass' -Detail "stratum $stratum (PDCe reference unavailable - absolute rules only, hierarchy band not evaluated)" -Data $data
        }
        $data['PdceStratum'] = $pdceStratum
        $expected = $pdceStratum + [int]$Target.DomainDepth
        $rodcNote = ''
        if ([bool]$Target.IsRodc) {
            $expected = $expected + 1
            $rodcNote = ' +1 RODC'
        }
        $lower = $expected - $stratumSlack
        $upper = $expected + $stratumSlack
        $data['ExpectedBand'] = "$lower..$upper"
        if (-not [bool]$Target.IsRootPdce -and $stratum -le $pdceStratum) {
            return New-Record -Check 'Stratum' -Status 'Warn' -Detail "stratum $stratum <= PDCe stratum $pdceStratum - DC appears to sync outside the domain hierarchy" -Data $data
        }
        if ($stratum -lt $lower -or $stratum -gt $upper) {
            return New-Record -Check 'Stratum' -Status 'Warn' -Detail "stratum $stratum outside expected band $lower..$upper (PDCe $pdceStratum + depth $($Target.DomainDepth)$rodcNote +/- $stratumSlack)" -Data $data
        }
        return New-Record -Check 'Stratum' -Status 'Pass' -Detail "stratum $stratum within expected band $lower..$upper" -Data $data
    }

    function Test-SourceCheck {
        if ($treeAvailable -and -not $w32TimePresent) {
            return New-Record -Check 'Source' -Status 'NotApplicable' -Detail 'no W32Time service key present (Samba or non-Windows DC)' -Data @{}
        }
        $severity = @{ Pass = 1; Warn = 2; Error = 3; Fail = 4 }
        $layers = @()
        $data = @{}

        # Registry layer -----------------------------------------------------
        if (-not $treeAvailable) {
            $layers += @{ Status = 'Error'; Detail = 'registry scan failed - configured sync source unknown' }
        }
        else {
            $type = Get-EffectiveOrDefault -Path $paramsKey -Name 'Type' -Fallback 'NT5DS'
            $clientEnabled = Get-EffectiveOrDefault -Path $ntpClientKey -Name 'Enabled' -Fallback 1
            $typeText = [string]$type['Value']
            $data['Type'] = $typeText
            $data['TypePolicyApplied'] = $type['PolicyApplied']
            $data['NtpClientEnabled'] = $clientEnabled['Value']
            if ([uint32]$clientEnabled['Value'] -eq 0) {
                $layers += @{ Status = 'Fail'; Detail = 'NtpClient provider disabled (Enabled=0) - machine cannot sync' }
            }
            elseif ([string]::Equals($typeText, 'NoSync', [System.StringComparison]::OrdinalIgnoreCase)) {
                $layers += @{ Status = 'Fail'; Detail = 'Type=NoSync - machine never synchronizes' }
            }
            elseif ([bool]$Target.IsRootPdce) {
                if ([string]::Equals($typeText, 'NTP', [System.StringComparison]::OrdinalIgnoreCase) -or
                    [string]::Equals($typeText, 'AllSync', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $peers = Get-EffectiveValue -Path $paramsKey -Name 'NtpServer'
                    $data['NtpServer'] = $peers['Data']
                    if ($peers['Present'] -and -not [string]::IsNullOrEmpty(([string]$peers['Data']).Trim())) {
                        $layers += @{ Status = 'Pass'; Detail = "root PDCe Type=$typeText with external peers: $($peers['Data'])" }
                    }
                    else {
                        $layers += @{ Status = 'Warn'; Detail = "root PDCe Type=$typeText but no NtpServer peer list is configured" }
                    }
                }
                elseif ([string]::Equals($typeText, 'NT5DS', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $layers += @{ Status = 'Warn'; Detail = 'forest-root PDCe uses Type=NT5DS (domain hierarchy) - it should sync from external NTP peers' }
                }
                else {
                    $layers += @{ Status = 'Warn'; Detail = "unrecognized Type '$typeText'" }
                }
            }
            else {
                if ([string]::Equals($typeText, 'NT5DS', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $layers += @{ Status = 'Pass'; Detail = 'Type=NT5DS (domain hierarchy)' }
                }
                elseif ([string]::Equals($typeText, 'NTP', [System.StringComparison]::OrdinalIgnoreCase) -or
                        [string]::Equals($typeText, 'AllSync', [System.StringComparison]::OrdinalIgnoreCase)) {
                    if (Test-KnownReliable -Name $server) {
                        $layers += @{ Status = 'Pass'; Detail = "Type=$typeText - declared known-reliable time server" }
                    }
                    else {
                        $layers += @{ Status = 'Warn'; Detail = "Type=$typeText on a non-PDCe DC - classic sign of a mis-scoped PDCe GPO" }
                    }
                }
                else {
                    $layers += @{ Status = 'Warn'; Detail = "unrecognized Type '$typeText'" }
                }
            }
        }

        # NTP layer (refid regimes) -------------------------------------------
        $blockedNote = $null
        if ($ntpOk) {
            $stratum = [int]$Ntp['Stratum']
            $refRaw = $Ntp['RefId']
            $refText = [string]$Ntp['RefIdText']
            $data['Stratum'] = $stratum
            $data['RefId'] = $refRaw
            $data['RefIdText'] = $refText
            if ($stratum -ge 2) {
                if ($null -ne $refRaw -and [uint64]$refRaw -eq 0) {
                    $layers += @{ Status = 'Warn'; Detail = 'refid 0 - upstream unsynchronized or VMIC host-sync steering' }
                }
                else {
                    # IPv4 upstream address, or an MD5-hash refid for an IPv6
                    # upstream (indistinguishable on the wire). Unknown-upstream
                    # warnings are emitted once by RefidLoop, suppressed here.
                    $layers += @{ Status = 'Pass'; Detail = "upstream refid $refText" }
                }
            }
            elseif ($stratum -eq 1) {
                if ([string]::Equals($refText, 'LOCL', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $layers += @{ Status = 'Warn'; Detail = 'stratum-1 refid LOCL - free-running local clock' }
                }
                else {
                    $layers += @{ Status = 'Pass'; Detail = "stratum-1 reference source tag '$refText'" }
                }
            }
            else {
                $layers += @{ Status = 'Pass'; Detail = 'stratum 0 reply (evaluated by the Stratum check)' }
            }
        }
        else {
            $blockedNote = 'NTP-layer source verification blocked by NtpQuery failure'
        }

        $final = $layers[0]
        foreach ($l in $layers) {
            if ([int]$severity[$l['Status']] -gt [int]$severity[$final['Status']]) { $final = $l }
        }
        $detailParts = @()
        foreach ($l in $layers) { $detailParts += [string]$l['Detail'] }
        if ($null -ne $blockedNote) { $detailParts += "($blockedNote)" }
        return New-Record -Check 'Source' -Status $final['Status'] -Detail ($detailParts -join '; ') -Data $data
    }

    function Test-LastSyncCheck {
        if (-not $ntpOk) {
            return New-Record -Check 'LastSync' -Status 'Blocked' -Detail $ntpBlockDetail -Data @{}
        }
        $t3 = $Ntp['TransmitTimestamp']
        $ref = $Ntp['ReferenceTimestamp']
        if ($null -eq $t3 -or $null -eq $ref) {
            return New-Record -Check 'LastSync' -Status 'Error' -Detail 'reply lacked usable timestamps - sync age cannot be computed' -Data @{}
        }
        # Per-server effective thresholds (policy twin wins); registry absent
        # (scan failed or value missing) falls back to DB dc defaults, then to
        # the catalog fallbacks (MaxPollInterval 10, ClockHoldoverPeriod 7800).
        $maxPoll = Get-EffectiveOrDefault -Path $configKey -Name 'MaxPollInterval' -Fallback 10
        $holdover = Get-EffectiveOrDefault -Path $configKey -Name 'ClockHoldoverPeriod' -Fallback 7800
        $warnAuto = 2.0 * [math]::Pow(2.0, [double][uint32]$maxPoll['Value'])
        $warnS = $warnAuto
        $warnSource = "auto: 2 x 2^MaxPollInterval($($maxPoll['Value']))"
        if ($lastSyncWarnSeconds -gt 0) {
            $warnS = [double]$lastSyncWarnSeconds
            $warnSource = 'explicit'
        }
        $failS = [double][uint32]$holdover['Value']
        $failSource = "ClockHoldoverPeriod $($holdover['Value'])"
        if ($lastSyncFailSeconds -gt 0) {
            $failS = [double]$lastSyncFailSeconds
            $failSource = 'explicit'
        }
        $data = @{
            AgeSeconds          = $null
            MaxPollInterval     = $maxPoll['Value']
            ClockHoldoverPeriod = $holdover['Value']
            WarnSeconds         = $warnS
            FailSeconds         = $failS
            PolicyApplied       = $maxPoll['PolicyApplied']
        }
        if (([datetime]$ref).Year -lt 1990) {
            # Reference timestamp unset (NTP zero marker) = never synchronized.
            return New-Record -Check 'LastSync' -Status 'Fail' -Detail 'never synchronized (reference timestamp unset)' -Data $data
        }
        $age = ([datetime]$t3 - [datetime]$ref).TotalSeconds
        if ($age -lt 0) { $age = 0.0 }
        $data['AgeSeconds'] = $age
        $ageText = Format-InvariantNumber -Value $age -FormatSpec '0'
        $warnText = Format-InvariantNumber -Value $warnS -FormatSpec '0'
        $failText = Format-InvariantNumber -Value $failS -FormatSpec '0'
        if ($age -gt $failS) {
            return New-Record -Check 'LastSync' -Status 'Fail' -Detail "last sync $ageText s ago exceeds fail threshold $failText s ($failSource)" -Data $data
        }
        if ($age -gt $warnS) {
            return New-Record -Check 'LastSync' -Status 'Warn' -Detail "last sync $ageText s ago exceeds warn threshold $warnText s ($warnSource)" -Data $data
        }
        return New-Record -Check 'LastSync' -Status 'Pass' -Detail "last sync $ageText s ago (warn > $warnText s [$warnSource], fail > $failText s)" -Data $data
    }

    function Test-AnnounceCheck {
        if (-not $treeAvailable) {
            return New-Record -Check 'Announce' -Status 'Error' -Detail 'registry scan failed - AnnounceFlags unknown' -Data @{}
        }
        if (-not $w32TimePresent) {
            return New-Record -Check 'Announce' -Status 'NotApplicable' -Detail 'no W32Time service key present (Samba or non-Windows DC)' -Data @{}
        }
        $af = Get-EffectiveOrDefault -Path $configKey -Name 'AnnounceFlags' -Fallback 10
        $flags = [uint32]$af['Value']
        $data = @{
            AnnounceFlags = $flags
            PolicyApplied = $af['PolicyApplied']
            FromDefault   = (-not [bool]$af['Present'])
        }
        # Bitmask: 0x1 always timeserv, 0x2 auto timeserv, 0x4 always reliable,
        # 0x8 auto reliable.
        $timeservBits = $flags -band 0x3
        if ([bool]$Target.IsRootPdce) {
            if ($flags -eq 5) {
                return New-Record -Check 'Announce' -Status 'Pass' -Detail 'AnnounceFlags=5 (always time server + always reliable) - MS convention for the forest-root PDCe' -Data $data
            }
            if ($timeservBits -eq 0) {
                return New-Record -Check 'Announce' -Status 'Fail' -Detail "AnnounceFlags=$flags has no timeserv bits - the PDCe will not advertise as a time source" -Data $data
            }
            if ($flags -eq 10) {
                return New-Record -Check 'Announce' -Status 'Warn' -Detail 'AnnounceFlags=10 (auto flags) on the forest-root PDCe - set 5 per MS convention' -Data $data
            }
            return New-Record -Check 'Announce' -Status 'Warn' -Detail "nonstandard AnnounceFlags=$flags on the forest-root PDCe - set 5 per MS convention" -Data $data
        }
        if ($flags -eq 10) {
            return New-Record -Check 'Announce' -Status 'Pass' -Detail 'AnnounceFlags=10 (auto timeserv + auto reliable) - default' -Data $data
        }
        if (($flags -band 0x4) -ne 0) {
            if (Test-KnownReliable -Name $server) {
                return New-Record -Check 'Announce' -Status 'Pass' -Detail "AnnounceFlags=$flags with AlwaysReliable (0x4) - declared known-reliable time server" -Data $data
            }
            return New-Record -Check 'Announce' -Status 'Warn' -Detail "AnnounceFlags=$flags sets AlwaysReliable (0x4) on a regular DC - time hijack risk" -Data $data
        }
        if ($timeservBits -eq 0) {
            return New-Record -Check 'Announce' -Status 'Warn' -Detail "AnnounceFlags=$flags has no timeserv bits - DC will not advertise as a time source" -Data $data
        }
        return New-Record -Check 'Announce' -Status 'Warn' -Detail "nonstandard AnnounceFlags=$flags" -Data $data
    }

    function Test-VmicCheck {
        if (-not $treeAvailable) {
            return New-Record -Check 'Vmic' -Status 'Error' -Detail 'registry scan failed - hypervisor state unknown' -Data @{}
        }
        if (-not $w32TimePresent) {
            return New-Record -Check 'Vmic' -Status 'NotApplicable' -Detail 'no W32Time service key present (Samba or non-Windows DC)' -Data @{}
        }
        $manufacturer = Get-TreeValue -Path $systemInfoKey -Name 'SystemManufacturer'
        $product = Get-TreeValue -Path $systemInfoKey -Name 'SystemProductName'
        if (-not $manufacturer['Present'] -and -not $product['Present']) {
            return New-Record -Check 'Vmic' -Status 'Error' -Detail 'SystemInformation key unavailable - cannot determine hypervisor' -Data @{}
        }
        $manuText = [string]$manufacturer['Data']
        $prodText = [string]$product['Data']
        $data = @{
            SystemManufacturer = $manuText
            SystemProductName  = $prodText
            OsBuild            = $osBuild
        }
        # Detection keys on manufacturer/product strings (plus refid below),
        # never on stratum.
        $isHyperV = ($manuText -like '*Microsoft*') -and ($prodText -like '*Virtual*')
        $isVirtual = $isHyperV -or
            ($manuText -match '(?i)vmware|xen|qemu|kvm|innotek|virtualbox|parallels|nutanix|amazon|google') -or
            ($prodText -match '(?i)virtual|vmware|kvm|hvm|openstack')
        if (-not $isVirtual) {
            return New-Record -Check 'Vmic' -Status 'NotApplicable' -Detail "physical machine ($manuText $prodText)" -Data $data
        }
        if (-not $isHyperV) {
            return New-Record -Check 'Vmic' -Status 'NotApplicable' -Detail "non-Hyper-V guest ($manuText) - the VMIC provider is inactive" -Data $data
        }
        $enabled = Get-EffectiveOrDefault -Path $vmicKey -Name 'Enabled' -Fallback 1
        $data['VmicEnabled'] = $enabled['Value']
        if ([uint32]$enabled['Value'] -eq 0) {
            return New-Record -Check 'Vmic' -Status 'Pass' -Detail 'Hyper-V guest with VMICTimeProvider disabled' -Data $data
        }
        if ($osBuild -gt 0 -and $osBuild -lt 14393) {
            return New-Record -Check 'Vmic' -Status 'Fail' -Detail "VMICTimeProvider Enabled=1 on pre-2016 build $osBuild - the Hyper-V host continuously steers the guest clock (conflicts with the domain hierarchy)" -Data $data
        }
        if ($ntpOk -and $null -ne $Ntp['RefId'] -and [uint64]$Ntp['RefId'] -eq 0) {
            return New-Record -Check 'Vmic' -Status 'Warn' -Detail 'refid 0 with VMICTimeProvider enabled - Hyper-V TimeSync appears to be steering the clock' -Data $data
        }
        if ($osBuild -le 0) {
            return New-Record -Check 'Vmic' -Status 'Warn' -Detail 'VMICTimeProvider Enabled=1 and OS build unknown - cannot rule out pre-2016 host-sync behavior' -Data $data
        }
        return New-Record -Check 'Vmic' -Status 'Pass' -Detail "Hyper-V guest on build $osBuild - VMIC syncs at boot/resume only (post-2016 behavior)" -Data $data
    }

    function Test-SecureTimeSeedingCheck {
        if (-not $treeAvailable) {
            return New-Record -Check 'SecureTimeSeeding' -Status 'Error' -Detail 'registry scan failed - UtilizeSslTimeData unknown' -Data @{}
        }
        if (-not $w32TimePresent) {
            return New-Record -Check 'SecureTimeSeeding' -Status 'NotApplicable' -Detail 'no W32Time service key present (Samba or non-Windows DC)' -Data @{}
        }
        # Effective value; the DB default is build-conditional (26100+ ships 0).
        $sts = Get-EffectiveOrDefault -Path $configKey -Name 'UtilizeSslTimeData' -Fallback 1
        $effective = [uint32]$sts['Value']
        $data = @{
            UtilizeSslTimeData = $effective
            Present            = $sts['Present']
            PolicyApplied      = $sts['PolicyApplied']
            OsBuild            = $osBuild
        }
        if ($effective -eq 0) {
            $detail = 'Secure Time Seeding disabled (UtilizeSslTimeData=0)'
            if (-not [bool]$sts['Present'] -and $osBuild -ge 26100) {
                $detail = "Secure Time Seeding disabled by default on build $osBuild (26100+ ships UtilizeSslTimeData=0, the 2025 default change)"
            }
            return New-Record -Check 'SecureTimeSeeding' -Status 'Pass' -Detail $detail -Data $data
        }
        $status = 'Pass'
        $detail = 'Info: UtilizeSslTimeData=1 - Secure Time Seeding can step the clock from SSL timestamps; Microsoft changed the default to 0 in 2025 (build 26100+). Consider disabling on DCs.'
        # Steering heuristic: an STS estimate that diverges far from actual time
        # while STS is enabled means STS may step this DC's clock.
        $estimated = Get-TreeValue -Path $secureLimitsKey -Name 'SecureTimeEstimated'
        $confidence = Get-TreeValue -Path $secureLimitsKey -Name 'SecureTimeConfidence'
        if ($confidence['Present']) { $data['SecureTimeConfidence'] = $confidence['Data'] }
        if ($estimated['Present']) {
            try {
                $raw = [uint64]$estimated['Data']
                if ($raw -gt 0 -and $raw -le [uint64][long]::MaxValue) {
                    $estimate = [datetime]::FromFileTimeUtc([long]$raw)
                    $referenceNow = $null
                    if ($ntpOk -and $null -ne $Ntp['TransmitTimestamp']) {
                        $referenceNow = [datetime]$Ntp['TransmitTimestamp']
                    }
                    else {
                        $referenceNow = [datetime]::Parse($Timestamp, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    }
                    $divergence = [math]::Abs(($estimate - $referenceNow).TotalSeconds)
                    $data['SecureTimeEstimated'] = $estimate.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                    $data['DivergenceSeconds'] = $divergence
                    if (($divergence * 1000.0) -gt $offsetFailMs) {
                        $status = 'Warn'
                        $detail = 'Secure Time Seeding is enabled (UtilizeSslTimeData=1) and its estimate diverges ' + (Format-InvariantNumber -Value $divergence -FormatSpec '0') + ' s from actual time - STS may actively step this DC (heuristic: divergence > OffsetFailMilliseconds)'
                    }
                }
            }
            catch {
                $data['SecureTimeEstimatedParseError'] = $_.Exception.Message
            }
        }
        return New-Record -Check 'SecureTimeSeeding' -Status $status -Detail $detail -Data $data
    }

    # ---- dispatch (catalog order, filtered by -Checks) ----------------------

    $catalog = @('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'Vmic', 'SecureTimeSeeding')
    $selected = @()
    if ($null -eq $Checks -or @($Checks).Count -eq 0) {
        $selected = $catalog
    }
    else {
        foreach ($name in $catalog) {
            foreach ($wanted in $Checks) {
                if ([string]::Equals($name, [string]$wanted, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $selected += $name
                    break
                }
            }
        }
    }

    foreach ($check in $selected) {
        switch ($check) {
            'Service' { Test-ServiceCheck }
            'NtpQuery' { Test-NtpQueryCheck }
            'Offset' { Test-OffsetCheck }
            'Stratum' { Test-StratumCheck }
            'Source' { Test-SourceCheck }
            'LastSync' { Test-LastSyncCheck }
            'Announce' { Test-AnnounceCheck }
            'Vmic' { Test-VmicCheck }
            'SecureTimeSeeding' { Test-SecureTimeSeedingCheck }
        }
    }
}

function Get-WinTimeRefidLoopFinding {
<#
.SYNOPSIS
Fleet-level RefidLoop analysis: detects DC-to-DC refid cycles (time islands)
and unknown upstreams across all scanned servers.

.DESCRIPTION
Builds the directed graph DC -> upstream-DC by mapping each server's NTP refid
(IPv4 of its sync source at stratum >= 2) onto the known DC IP addresses, then
runs cycle detection (each node has at most one refid, so the graph is
functional and an iterative colored walk finds every cycle). Findings:

  - Fail for every member of a cycle with no external upstream (a time
    island); suppressed to Warn when a cycle member is declared in
    -KnownReliableTimeServers (it claims an external source, e.g. GPS).
  - Warn for a non-PDCe DC whose refid matches no forest DC IP (unknown
    upstream: external server, IPv6-upstream hash refid, or a decommissioned
    DC). Emitted once here and suppressed in the Source check. The root PDCe
    is expected to have an external upstream and is never flagged.

Nodes without a successful NTP result, at stratum < 2, or with refid 0 take no
part in the graph. Clean nodes produce no records (findings only).

.PARAMETER AllResults
Hashtable fqdn -> @{ Ntp = <Invoke-NtpQuery result>; Target = <target
object>; Ips = <string[] of the DC's IPv4 addresses> }.

.PARAMETER RunId
Run GUID stamped on every record.

.PARAMETER Timestamp
ISO-8601 invariant timestamp stamped on every record.

.PARAMETER KnownReliableTimeServers
Declared GTIMESERV hosts; suppresses hierarchy warnings for them.

.OUTPUTS
WinTime.HealthRecord[] (Check = RefidLoop; findings only, may be empty)

.EXAMPLE
Get-WinTimeRefidLoopFinding -AllResults $fleet -RunId $id -Timestamp $ts

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'RunId', Justification = 'Read only inside the nested New-LoopRecord closure (stamped on every record).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Timestamp', Justification = 'Read only inside the nested New-LoopRecord closure (stamped on every record).')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AllResults,

        [Parameter(Mandatory = $true)]
        [string]$RunId,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp,

        [Parameter()]
        [AllowNull()]
        [string[]]$KnownReliableTimeServers = @()
    )

    if ($null -eq $KnownReliableTimeServers) { $KnownReliableTimeServers = @() }

    function Test-LoopKnownReliable {
        param([Parameter(Mandatory = $true)][string]$Name)
        foreach ($known in $KnownReliableTimeServers) {
            if ([string]::Equals([string]$known, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }

    function New-LoopRecord {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory record factory; changes no system state.')]
        param(
            [Parameter(Mandatory = $true)][string]$Fqdn,
            [Parameter(Mandatory = $true)][string]$Status,
            [Parameter(Mandatory = $true)][string]$Detail,
            [Parameter()][hashtable]$Data = @{}
        )
        $node = $AllResults[$Fqdn]
        $nodeDomain = ''
        $nodeRole = 'Dc'
        if ($node -is [hashtable] -and $node.ContainsKey('Target') -and $null -ne $node['Target']) {
            $nodeDomain = [string]$node['Target'].Domain
            if ([bool]$node['Target'].IsRootPdce) { $nodeRole = 'RootPdce' }
        }
        return New-WinTimeHealthRecord -Server $Fqdn -Domain $nodeDomain -Role $nodeRole -Check 'RefidLoop' -Status $Status -Detail $Detail -Data $Data -RunId $RunId -Timestamp $Timestamp
    }

    # IP -> owning DC map.
    $ipToFqdn = @{}
    foreach ($fqdn in @($AllResults.Keys)) {
        $node = $AllResults[$fqdn]
        if ($node -isnot [hashtable] -or -not $node.ContainsKey('Ips') -or $null -eq $node['Ips']) { continue }
        foreach ($ip in @($node['Ips'])) {
            if (-not [string]::IsNullOrEmpty([string]$ip)) {
                $ipToFqdn[[string]$ip] = [string]$fqdn
            }
        }
    }

    # Edges DC -> upstream DC (functional graph: one refid per node), plus the
    # unknown-upstream findings collected on the way. Note: an MD5-hash refid
    # for an IPv6 upstream could coincidentally match a DC IP - accepted
    # limitation of the refid regime (DESIGN section 8).
    $edges = @{}
    $records = @()
    foreach ($fqdn in @($AllResults.Keys | Sort-Object)) {
        $node = $AllResults[$fqdn]
        if ($node -isnot [hashtable] -or -not $node.ContainsKey('Ntp') -or $null -eq $node['Ntp']) { continue }
        $ntp = $node['Ntp']
        if (-not [bool]$ntp['Success']) { continue }
        if ($null -eq $ntp['Stratum'] -or [int]$ntp['Stratum'] -lt 2) { continue }  # ASCII-refid regime
        if ($null -eq $ntp['RefId'] -or [uint64]$ntp['RefId'] -eq 0) { continue }   # unsync/VMIC, handled by Source
        $raw = [uint32]$ntp['RefId']
        $dotted = '{0}.{1}.{2}.{3}' -f (($raw -shr 24) -band 0xFF), (($raw -shr 16) -band 0xFF), (($raw -shr 8) -band 0xFF), ($raw -band 0xFF)
        if ($ipToFqdn.ContainsKey($dotted)) {
            $edges[[string]$fqdn] = [string]$ipToFqdn[$dotted]
        }
        else {
            $isPdce = $false
            if ($node.ContainsKey('Target') -and $null -ne $node['Target']) { $isPdce = [bool]$node['Target'].IsRootPdce }
            if (-not $isPdce -and -not (Test-LoopKnownReliable -Name $fqdn)) {
                $records += New-LoopRecord -Fqdn $fqdn -Status 'Warn' -Detail "syncs from unknown upstream $dotted - matches no forest DC IP (external server, IPv6-upstream hash refid, or a decommissioned DC)" -Data @{ RefId = $raw; RefIdDotted = $dotted }
            }
        }
    }

    # Cycle detection over the functional graph: iterative walk with colors
    # (0 = unvisited, 1 = on the current path, 2 = finished).
    $state = @{}
    $cycles = @()
    foreach ($start in @($edges.Keys | Sort-Object)) {
        if ($state.ContainsKey($start)) { continue }
        $path = New-Object System.Collections.ArrayList
        $node = [string]$start
        while ($true) {
            if (-not $edges.ContainsKey($node)) { break }  # terminal: no upstream edge
            if ($state.ContainsKey($node)) {
                if ([int]$state[$node] -eq 1) {
                    # New cycle: everything from the first occurrence of $node.
                    $idx = $path.IndexOf($node)
                    $cycles += , @($path.GetRange($idx, $path.Count - $idx).ToArray())
                }
                break
            }
            $state[$node] = 1
            $null = $path.Add($node)
            $node = [string]$edges[$node]
        }
        foreach ($visited in $path) { $state[[string]$visited] = 2 }
    }

    foreach ($cycle in $cycles) {
        $cycleText = (@($cycle) + $cycle[0]) -join ' -> '
        $hasReliableMember = $false
        foreach ($member in $cycle) {
            if (Test-LoopKnownReliable -Name $member) { $hasReliableMember = $true; break }
        }
        foreach ($member in $cycle) {
            if ($hasReliableMember) {
                $records += New-LoopRecord -Fqdn $member -Status 'Warn' -Detail "refid loop $cycleText contains a declared known-reliable time server - verify its external source is actually healthy" -Data @{ Cycle = @($cycle) }
            }
            else {
                $records += New-LoopRecord -Fqdn $member -Status 'Fail' -Detail "time island: refid loop $cycleText with no external upstream - these DCs only sync from each other" -Data @{ Cycle = @($cycle) }
            }
        }
    }

    return @($records)
}
