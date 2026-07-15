function Compare-W32TimeConfig {
<#
.SYNOPSIS
Compares a scanned W32Time registry tree against the key database, baselines
and applied policy, emitting WinTime.ConfigRecord objects.

.DESCRIPTION
Implements the DESIGN.md section 3/4 comparison semantics for one target:

Expectation cascade per database entry:
  1. Policy twin value present in the tree  -> Expected = policy value,
     ExpectedSource = 'Policy', PolicyApplied = $true.
  2. Otherwise baseline: PdceBaseline for pdce-exempt entries on the detected
     forest-root PDCe; DcBaseline for everything else, when the baseline
     contains the value -> ExpectedSource = 'Baseline'.
  3. Otherwise Resolve-W32TimeExpectation (role/OS-resolved MS default) ->
     ExpectedSource = 'MSDefault'.

Status semantics:
  - compare 'ignore' entries emit an Ignored record when the value is present
    on the target and are skipped entirely when absent.
  - pdce-exempt entries on the detected forest-root PDCe with no applied
    policy and no PdceBaseline value -> PdceExempt (Note carries the actual
    value and the conventional PDCe expectation).
  - When RootPdceDetected is $false, pdce-exempt entries are compared as
    exact with Note 'PDCe detection failed; exemption disabled'.
  - Absent value + policy- or baseline-defined expectation -> Missing (drift);
    absent + only an MS default (or nothing) -> NotSet (not drift).
  - Registry value kind differing from the documented type -> Drift with a
    type-mismatch Note (data comparison skipped).
  - DWORD/QWORD compared numerically as unsigned; strings OrdinalIgnoreCase;
    REG_MULTI_SZ element-wise (order-sensitive); REG_BINARY byte-wise. The
    Parameters\NtpServer peer list is compared ordinal (case- and
    whitespace-exact) with a Note when it differs only in whitespace/case.
  - A drift value equal to the documented gpo_default (policy NOT applied)
    gets the "matches GPO preset" Note hint.
  - A present value with no defined expectation at all (admin-defined, null
    default) is recorded as Match with an explanatory Note.

Tree values not matched by any database entry, inside the W32Time service or
policy subtrees, and not under an internal_subtrees path, are emitted as
Undocumented (Class 'unknown') with Promoted = $true for the security subset:
unknown TimeProviders subkey, value name matching *Dll*, or any unknown value
under the W32Time policy key. Each internal_subtrees path that exists on the
target yields a single Ignored record with ValueName '(subtree)'.

IsDrift is $true exactly when Status is Drift or Missing. Every record
carries all WinTime.ConfigRecord properties plus the Promoted flag.

.PARAMETER Tree
Registry tree hashtable from the scan worker: key = registry path relative to
HKLM, value = hashtable of valueName -> @{ Kind = <RegistryValueKind name>;
Data = <object> }. Paths and value names are matched OrdinalIgnoreCase.

.PARAMETER Target
Resolved target object ([pscustomobject] with ComputerName, Domain, Site,
IsRootPdce, IsRodc, DomainDepth).

.PARAMETER Database
Database object from Get-W32TimeDatabase (SchemaVersion, Verified, Keys,
InternalSubtrees).

.PARAMETER DcBaseline
Optional baseline registry tree (same shape as Tree) captured from reference
DCs; $null when no baseline was supplied.

.PARAMETER PdceBaseline
Optional PDCe companion baseline tree used for pdce-exempt entries on the
forest-root PDCe; $null when not supplied.

.PARAMETER RootPdceDetected
$true when forest-root PDCe detection succeeded. When $false, pdce-exempt
handling is disabled and affected records carry an explanatory Note.

.PARAMETER OsBuild
Target OS build number (CurrentBuildNumber); 0 when unknown. Forwarded to
Resolve-W32TimeExpectation for defaults_overrides resolution.

.PARAMETER RunId
Run identifier (one GUID string per invocation) stamped on every record.

.PARAMETER Timestamp
ISO-8601 invariant timestamp string stamped on every record.

.OUTPUTS
System.Management.Automation.PSCustomObject (PSTypeName 'WinTime.ConfigRecord')

.EXAMPLE
Compare-W32TimeConfig -Tree $result.Tree -Target $target -Database $db `
    -DcBaseline $null -PdceBaseline $null -RootPdceDetected $true `
    -OsBuild 20348 -RunId $runId -Timestamp $stamp
Compares a scanned tree against role/OS-resolved MS defaults only.
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'RunId',
        Justification = 'used inside the nested New-ConfigRecord factory; analyzer does not track nested-function scope')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Timestamp',
        Justification = 'used inside the nested New-ConfigRecord factory; analyzer does not track nested-function scope')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]
        $Tree,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscustomobject]
        $Target,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Database,

        [Parameter()]
        [AllowNull()]
        [hashtable]
        $DcBaseline,

        [Parameter()]
        [AllowNull()]
        [hashtable]
        $PdceBaseline,

        [Parameter(Mandatory = $true)]
        [bool]
        $RootPdceDetected,

        [Parameter()]
        [int]
        $OsBuild = 0,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RunId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Timestamp
    )

    Set-StrictMode -Version Latest

    # ---- nested helpers (scoped to this function only) --------------------

    # Field access that is safe for Hashtable, OrderedDictionary and
    # PSCustomObject under StrictMode (never property-dot into a dictionary).
    function Get-Field {
        param($Object, [string]$Name)
        if ($null -eq $Object) { return $null }
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) { return $Object[$Name] }
            return $null
        }
        $prop = $Object.PSObject.Properties[$Name]
        if ($null -ne $prop) { return $prop.Value }
        return $null
    }

    # True when $Path equals $Root or is beneath it (OrdinalIgnoreCase).
    function Test-PathUnder {
        param([string]$Path, [string]$Root)
        if ([string]::Equals($Path, $Root, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        return $Path.StartsWith(($Root + '\'), [System.StringComparison]::OrdinalIgnoreCase)
    }

    # Provider subkey name directly under ...\TimeProviders\, or $null.
    function Get-ProviderSegment {
        param([string]$Path)
        if ([string]::IsNullOrEmpty($Path)) { return $null }
        $marker = '\TimeProviders\'
        $idx = $Path.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
        if ($idx -lt 0) { return $null }
        $rest = $Path.Substring($idx + $marker.Length)
        $end = $rest.IndexOf('\')
        if ($end -ge 0) { $rest = $rest.Substring(0, $end) }
        if ([string]::IsNullOrEmpty($rest)) { return $null }
        return $rest
    }

    # Unsigned numeric normalization for DWORD/QWORD comparison; $null when
    # the input is not usable as an unsigned number.
    function ConvertTo-UnsignedNumber {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [uint64]) { return $Value }
        if ($Value -is [uint32] -or $Value -is [uint16] -or $Value -is [byte]) { return [uint64]$Value }
        if ($Value -is [int] -or $Value -is [int16] -or $Value -is [sbyte]) {
            # NB: the hex literal 0xFFFFFFFF parses as Int32 -1 in PowerShell,
            # so '-band 0xFFFFFFFF' is a no-op against a negative Int32 and
            # would leave the value negative (the surrounding [uint64] cast
            # would then throw). Reinterpret via BitConverter instead.
            if ($Value -lt 0) { return [uint64][System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$Value), 0) }  # two's-complement DWORD
            return [uint64]$Value
        }
        if ($Value -is [long]) {
            if ($Value -lt 0) { return [System.BitConverter]::ToUInt64([System.BitConverter]::GetBytes($Value), 0) }  # two's-complement QWORD
            return [uint64]$Value
        }
        if ($Value -is [double]) {
            if ($Value -lt 0 -or ($Value -ne [math]::Floor($Value))) { return $null }
            return [uint64]$Value
        }
        if ($Value -is [string]) {
            $s = $Value.Trim()
            $parsed = [uint64]0
            if ($s.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
                if ([uint64]::TryParse($s.Substring(2), [System.Globalization.NumberStyles]::HexNumber,
                        [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) { return $parsed }
                return $null
            }
            if ([uint64]::TryParse($s, [System.Globalization.NumberStyles]::None,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) { return $parsed }
            return $null
        }
        return $null
    }

    function ConvertTo-StringArray {
        param($Value)
        $list = New-Object 'System.Collections.Generic.List[string]'
        if ($null -ne $Value) {
            foreach ($item in @($Value)) { $list.Add([string]$item) }
        }
        return , $list.ToArray()
    }

    # Human-readable rendering of a data value for Note text (invariant).
    function Format-NoteValue {
        param($Value)
        if ($null -eq $Value) { return '(absent)' }
        if ($Value -is [byte[]]) {
            return ('0x' + ([System.BitConverter]::ToString($Value) -replace '-', ''))
        }
        if ($Value -is [System.Array]) { return (@($Value) -join ' | ') }
        $num = ConvertTo-UnsignedNumber $Value
        if ($null -ne $num -and -not ($Value -is [string])) {
            return $num.ToString([System.Globalization.CultureInfo]::InvariantCulture)
        }
        return [string]$Value
    }

    # Data equality per documented registry type. $NoteList receives
    # explanatory notes (peer-list whitespace/case near-miss).
    function Test-DataEqual {
        param([string]$RegType, $Actual, $Expected, $NoteList, [bool]$IsPeerList)
        if ($IsPeerList) {
            # NtpServer peer list: flags/hosts compared ordinal, case- and
            # whitespace-exact (order-sensitive by design; a reordered peer
            # list changes fallback semantics and is reported as drift).
            $a = [string]$Actual
            $e = [string]$Expected
            if ([string]::Equals($a, $e, [System.StringComparison]::Ordinal)) { return $true }
            $aNorm = ($a -replace '\s+', ' ').Trim()
            $eNorm = ($e -replace '\s+', ' ').Trim()
            if ([string]::Equals($aNorm, $eNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($null -ne $NoteList) {
                    $NoteList.Add('peer list differs from expected only in whitespace/case (ordinal compare)')
                }
            }
            return $false
        }
        switch ($RegType) {
            'REG_DWORD' {
                $a = ConvertTo-UnsignedNumber $Actual
                $e = ConvertTo-UnsignedNumber $Expected
                if ($null -ne $a -and $null -ne $e) { return ($a -eq $e) }
                return [string]::Equals([string]$Actual, [string]$Expected, [System.StringComparison]::OrdinalIgnoreCase)
            }
            'REG_QWORD' {
                $a = ConvertTo-UnsignedNumber $Actual
                $e = ConvertTo-UnsignedNumber $Expected
                if ($null -ne $a -and $null -ne $e) { return ($a -eq $e) }
                return [string]::Equals([string]$Actual, [string]$Expected, [System.StringComparison]::OrdinalIgnoreCase)
            }
            'REG_MULTI_SZ' {
                $aArr = ConvertTo-StringArray $Actual
                $eArr = ConvertTo-StringArray $Expected
                if ($aArr.Count -ne $eArr.Count) { return $false }
                for ($i = 0; $i -lt $aArr.Count; $i++) {
                    if (-not [string]::Equals($aArr[$i], $eArr[$i], [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
                }
                return $true
            }
            'REG_BINARY' {
                $aBytes = @(); if ($null -ne $Actual) { $aBytes = @($Actual) }
                $eBytes = @(); if ($null -ne $Expected) { $eBytes = @($Expected) }
                if ($aBytes.Count -ne $eBytes.Count) { return $false }
                for ($i = 0; $i -lt $aBytes.Count; $i++) {
                    if ([int]$aBytes[$i] -ne [int]$eBytes[$i]) { return $false }
                }
                return $true
            }
            default {
                return [string]::Equals([string]$Actual, [string]$Expected, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
    }

    # Normalize an expectation for serialization on the record (unsigned
    # DWORD/QWORD, string[] for REG_MULTI_SZ) without altering semantics.
    function ConvertTo-ExpectedOut {
        param([string]$RegType, $Expected)
        if ($null -eq $Expected) { return $null }
        if ($RegType -eq 'REG_DWORD') {
            $n = ConvertTo-UnsignedNumber $Expected
            if ($null -ne $n -and $n -le [uint32]::MaxValue) { return [uint32]$n }
            return $Expected
        }
        if ($RegType -eq 'REG_QWORD') {
            $n = ConvertTo-UnsignedNumber $Expected
            if ($null -ne $n) { return $n }
            return $Expected
        }
        if ($RegType -eq 'REG_MULTI_SZ') { return , (ConvertTo-StringArray $Expected) }
        return $Expected
    }

    function Find-BaselineValue {
        param([hashtable]$Baseline, [string]$Path, [string]$Name)
        if ($null -eq $Baseline) { return $null }
        foreach ($pathEntry in $Baseline.GetEnumerator()) {
            if (-not [string]::Equals([string]$pathEntry.Key, $Path, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $inner = $pathEntry.Value
            if ($inner -is [System.Collections.IDictionary]) {
                foreach ($valueEntry in $inner.GetEnumerator()) {
                    if ([string]::Equals([string]$valueEntry.Key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $valueEntry.Value
                    }
                }
            }
        }
        return $null
    }

    # Look up (and optionally mark as matched) a value in the scanned tree
    # index built below. Returns the mutable bookkeeping hashtable or $null.
    function Find-IndexValue {
        param([string]$Path, [string]$Name, [bool]$Mark)
        if ([string]::IsNullOrEmpty($Path)) { return $null }
        if (-not $pathIndex.ContainsKey($Path)) { return $null }
        $values = ($pathIndex[$Path])['Values']
        if (-not $values.ContainsKey($Name)) { return $null }
        $found = $values[$Name]
        if ($Mark) { $found['Matched'] = $true }
        return $found
    }

    function New-ConfigRecord {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'pure in-memory record factory; changes no system state')]
        param(
            [string]$KeyPath, [string]$ValueName, $TypeName, $Data, $Expected, $ExpectedSource,
            [string]$Status, [string]$Class, [bool]$GpoBacked, [bool]$PolicyApplied, $Note, [bool]$Promoted
        )
        [pscustomobject]@{
            PSTypeName     = 'WinTime.ConfigRecord'
            Server         = [string]$Target.ComputerName
            Domain         = [string]$Target.Domain
            Role           = $roleName
            OsBuild        = $OsBuild
            KeyPath        = $KeyPath
            ValueName      = $ValueName
            Type           = $TypeName
            Data           = $Data
            Expected       = $Expected
            ExpectedSource = $ExpectedSource
            Status         = $Status
            IsDrift        = ($Status -eq 'Drift' -or $Status -eq 'Missing')
            Class          = $Class
            GpoBacked      = $GpoBacked
            PolicyApplied  = $PolicyApplied
            Note           = $Note
            Promoted       = $Promoted
            RunId          = $RunId
            Timestamp      = $Timestamp
        }
    }

    # ---- setup -------------------------------------------------------------

    $kindByRegType = @{
        'REG_SZ'        = 'String'
        'REG_EXPAND_SZ' = 'ExpandString'
        'REG_DWORD'     = 'DWord'
        'REG_QWORD'     = 'QWord'
        'REG_MULTI_SZ'  = 'MultiString'
        'REG_BINARY'    = 'Binary'
        'REG_NONE'      = 'None'
    }

    $effectivePdce = ([bool](Get-Field $Target 'IsRootPdce')) -and $RootPdceDetected
    if ($effectivePdce) { $roleName = 'RootPdce' } else { $roleName = 'Dc' }

    $dbKeys = @(Get-Field $Database 'Keys')
    $internalSubtrees = @(Get-Field $Database 'InternalSubtrees')

    # OrdinalIgnoreCase index over the scanned tree with per-value Matched
    # bookkeeping for the undocumented sweep.
    $pathIndex = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($treeEntry in $Tree.GetEnumerator()) {
        $treePath = [string]$treeEntry.Key
        if (-not $pathIndex.ContainsKey($treePath)) {
            $pathIndex[$treePath] = @{
                Path   = $treePath
                Values = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase))
            }
        }
        $bucketValues = ($pathIndex[$treePath])['Values']
        $inner = $treeEntry.Value
        if ($inner -is [System.Collections.IDictionary]) {
            foreach ($valueEntry in $inner.GetEnumerator()) {
                $valueName = [string]$valueEntry.Key
                $meta = $valueEntry.Value
                $bucketValues[$valueName] = @{
                    Name    = $valueName
                    Kind    = [string](Get-Field $meta 'Kind')
                    Data    = (Get-Field $meta 'Data')
                    Matched = $false
                }
            }
        }
    }

    Write-Verbose ("Compare-W32TimeConfig: {0} ({1}), {2} tree key(s), {3} database entr(ies), role {4}" -f `
        [string]$Target.ComputerName, [string]$Target.Domain, $pathIndex.Count, $dbKeys.Count, $roleName)

    # ---- pass 1: database entries ------------------------------------------

    foreach ($entry in $dbKeys) {
        if ($null -eq $entry) { continue }
        $entryPath = [string](Get-Field $entry 'path')
        $entryValue = [string](Get-Field $entry 'value')
        $entryType = [string](Get-Field $entry 'type')
        $entryClass = [string](Get-Field $entry 'class')
        $entryCompare = [string](Get-Field $entry 'compare')
        $entryGpo = Get-Field $entry 'gpo'
        $gpoBacked = ($null -ne $entryGpo)

        $expectedKind = $null
        if ($kindByRegType.ContainsKey($entryType)) { $expectedKind = $kindByRegType[$entryType] }

        $op = Find-IndexValue -Path $entryPath -Name $entryValue -Mark $true

        $pol = $null
        if ($gpoBacked) {
            $policyPath = [string](Get-Field $entryGpo 'policy_path')
            $pol = Find-IndexValue -Path $policyPath -Name $entryValue -Mark $true
        }
        $policyApplied = ($null -ne $pol)

        $data = $null
        $typeName = $expectedKind
        if ($null -ne $op) {
            $data = $op['Data']
            $typeName = $op['Kind']
        }

        # compare: ignore -> Ignored record when present, nothing when absent.
        if ($entryCompare -eq 'ignore') {
            if ($null -ne $op) {
                New-ConfigRecord -KeyPath $entryPath -ValueName $entryValue -TypeName $typeName -Data $data `
                    -Expected $null -ExpectedSource $null -Status 'Ignored' -Class $entryClass `
                    -GpoBacked $gpoBacked -PolicyApplied $policyApplied -Note $null -Promoted $false
            }
            continue
        }

        $notes = New-Object 'System.Collections.Generic.List[string]'
        $isPdceExemptEntry = ($entryCompare -eq 'pdce-exempt')
        if ($isPdceExemptEntry -and -not $RootPdceDetected) {
            $notes.Add('PDCe detection failed; exemption disabled')
        }

        # Expectation cascade: Policy -> Baseline -> MSDefault (resolver).
        $expected = $null
        $expectedSource = $null
        $pdceExempt = $false
        if ($policyApplied) {
            $expected = $pol['Data']
            $expectedSource = 'Policy'
        }
        elseif ($isPdceExemptEntry -and $effectivePdce) {
            $baselineValue = Find-BaselineValue -Baseline $PdceBaseline -Path $entryPath -Name $entryValue
            if ($null -ne $baselineValue) {
                $expected = Get-Field $baselineValue 'Data'
                $expectedSource = 'Baseline'
            }
            else { $pdceExempt = $true }
        }
        else {
            $baselineValue = Find-BaselineValue -Baseline $DcBaseline -Path $entryPath -Name $entryValue
            if ($null -ne $baselineValue) {
                $expected = Get-Field $baselineValue 'Data'
                $expectedSource = 'Baseline'
            }
        }
        if ($null -eq $expectedSource -and -not $pdceExempt) {
            $resolved = Resolve-W32TimeExpectation -Entry $entry -Role $roleName -OsBuild $OsBuild
            $expected = Get-Field $resolved 'Expected'
            $expectedSource = [string](Get-Field $resolved 'Source')
            if ([string]::IsNullOrEmpty($expectedSource)) { $expectedSource = 'MSDefault' }
            $resolvedNote = [string](Get-Field $resolved 'Note')
            if (-not [string]::IsNullOrEmpty($resolvedNote)) { $notes.Add($resolvedNote) }
            # DESIGN.md section 5: "unknown build => base defaults + Note".
            # Resolve-W32TimeExpectation only applies defaults_overrides when
            # OsBuild > 0; when the entry carries overrides but the build is
            # unknown, the base (non-OS-conditional) default was used and may
            # not reflect this target's actual per-OS Microsoft default.
            $osConditional = [bool](Get-Field $resolved 'OsConditional')
            if ($osConditional -and $OsBuild -le 0) {
                $notes.Add('OS build unknown; base default used despite an OS-conditional Microsoft default for this value')
            }
        }

        if ($pdceExempt) {
            # PdceExempt: no policy, no PDCe baseline. Report the actual value
            # alongside the conventional PDCe expectation; never drift.
            $conventional = Resolve-W32TimeExpectation -Entry $entry -Role 'RootPdce' -OsBuild $OsBuild
            $convExpected = Get-Field $conventional 'Expected'
            $convSource = [string](Get-Field $conventional 'Source')
            if ([string]::IsNullOrEmpty($convSource)) { $convSource = 'MSDefault' }
            $convText = Format-NoteValue $convExpected
            if ($null -eq $convExpected) { $convText = '(admin-defined; no documented convention)' }
            $notes.Add(('PDCe-exempt: actual value {0}; conventional PDCe expectation {1} — review by hand' -f `
                (Format-NoteValue $data), $convText))
            $noteText = ($notes -join '; ')
            New-ConfigRecord -KeyPath $entryPath -ValueName $entryValue -TypeName $typeName -Data $data `
                -Expected (ConvertTo-ExpectedOut -RegType $entryType -Expected $convExpected) `
                -ExpectedSource $convSource -Status 'PdceExempt' -Class $entryClass `
                -GpoBacked $gpoBacked -PolicyApplied $false -Note $noteText -Promoted $false
            continue
        }

        $status = $null
        if ($null -eq $op) {
            # Absent operational value.
            if ($policyApplied) {
                $status = 'Missing'
                $notes.Add('policy twin defines this value but the operational value is absent — operational value diverges from applied GPO')
            }
            elseif ($expectedSource -eq 'Baseline') {
                $status = 'Missing'
                $notes.Add('baseline defines this value but it is absent on the target')
            }
            else {
                $status = 'NotSet'  # service uses its built-in default; not drift
            }
        }
        else {
            $kindMatches = $true
            if (-not [string]::IsNullOrEmpty($expectedKind)) {
                $foundKind = [string]$op['Kind']
                if (-not [string]::Equals($foundKind, $expectedKind, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $kindMatches = $false
                }
            }
            if (-not $kindMatches) {
                $status = 'Drift'
                $notes.Add(('type mismatch: documented {0} ({1}), found {2}' -f $entryType, $expectedKind, [string]$op['Kind']))
            }
            elseif ($null -eq $expected -and $expectedSource -ne 'Policy') {
                # Documented value with no defined expectation (admin-defined).
                $status = 'Match'
                $notes.Add('no documented default (admin-defined value); recorded without comparison')
            }
            else {
                $isPeerList = ([string]::Equals($entryValue, 'NtpServer', [System.StringComparison]::OrdinalIgnoreCase) -and `
                        $entryPath.EndsWith('\W32Time\Parameters', [System.StringComparison]::OrdinalIgnoreCase))
                if (Test-DataEqual -RegType $entryType -Actual $data -Expected $expected -NoteList $notes -IsPeerList $isPeerList) {
                    $status = 'Match'
                }
                else {
                    $status = 'Drift'
                    if ($policyApplied) {
                        $notes.Add('operational value diverges from applied GPO')
                    }
                    elseif ($gpoBacked) {
                        # Drift value equal to the documented GPO preset hints
                        # at a policy applying that we did not see in the tree.
                        $gpoDefault = Get-Field $entryGpo 'gpo_default'
                        if ($null -ne $gpoDefault) {
                            $scratch = New-Object 'System.Collections.Generic.List[string]'
                            if (Test-DataEqual -RegType $entryType -Actual $data -Expected $gpoDefault -NoteList $scratch -IsPeerList $false) {
                                $policyName = [string](Get-Field $entryGpo 'policy')
                                $notes.Add(("matches GPO preset for '{0}' — likely a GPO applying" -f $policyName))
                            }
                        }
                    }
                }
            }
        }

        $noteText = $null
        if ($notes.Count -gt 0) { $noteText = ($notes -join '; ') }
        New-ConfigRecord -KeyPath $entryPath -ValueName $entryValue -TypeName $typeName -Data $data `
            -Expected (ConvertTo-ExpectedOut -RegType $entryType -Expected $expected) `
            -ExpectedSource $expectedSource -Status $status -Class $entryClass `
            -GpoBacked $gpoBacked -PolicyApplied $policyApplied -Note $noteText -Promoted $false
    }

    # ---- pass 2: internal runtime-state subtrees (presence only) -----------

    foreach ($subtree in $internalSubtrees) {
        if ($null -eq $subtree) { continue }
        $subtreePath = [string](Get-Field $subtree 'path')
        if ([string]::IsNullOrEmpty($subtreePath)) { continue }
        $keyCount = 0
        $valueCount = 0
        foreach ($kv in $pathIndex.GetEnumerator()) {
            if (Test-PathUnder -Path $kv.Key -Root $subtreePath) {
                $keyCount++
                $valueCount += ($kv.Value)['Values'].Count
            }
        }
        if ($keyCount -gt 0) {
            $noteText = ('internal runtime-state subtree present ({0} key(s), {1} value(s)); contents not compared' -f $keyCount, $valueCount)
            New-ConfigRecord -KeyPath $subtreePath -ValueName '(subtree)' -TypeName $null -Data $null `
                -Expected $null -ExpectedSource $null -Status 'Ignored' -Class 'internal' `
                -GpoBacked $false -PolicyApplied $false -Note $noteText -Promoted $false
        }
    }

    # ---- pass 3: undocumented sweep -----------------------------------------

    $serviceRoot = 'SYSTEM\CurrentControlSet\Services\W32Time'
    $policyRoot = 'SOFTWARE\Policies\Microsoft\W32Time'

    # Providers the database knows about (operational and policy sides).
    $knownProviders = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $dbKeys) {
        if ($null -eq $entry) { continue }
        $segment = Get-ProviderSegment -Path ([string](Get-Field $entry 'path'))
        if ($null -ne $segment) { [void]$knownProviders.Add($segment) }
        $gpoBlock = Get-Field $entry 'gpo'
        if ($null -ne $gpoBlock) {
            $segment = Get-ProviderSegment -Path ([string](Get-Field $gpoBlock 'policy_path'))
            if ($null -ne $segment) { [void]$knownProviders.Add($segment) }
        }
    }

    $sortedPaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $pathIndex.Keys) { $sortedPaths.Add($p) }
    $sortedPaths.Sort([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($sweepPath in $sortedPaths) {
        # Only the W32Time service and policy subtrees are swept; the
        # build/hypervisor metadata keys the scanner also reads are not
        # W32Time configuration and never surface as Undocumented.
        $inScope = (Test-PathUnder -Path $sweepPath -Root $serviceRoot) -or (Test-PathUnder -Path $sweepPath -Root $policyRoot)
        if (-not $inScope) { continue }
        $underInternal = $false
        foreach ($subtree in $internalSubtrees) {
            if ($null -eq $subtree) { continue }
            $subtreePath = [string](Get-Field $subtree 'path')
            if (-not [string]::IsNullOrEmpty($subtreePath) -and (Test-PathUnder -Path $sweepPath -Root $subtreePath)) {
                $underInternal = $true
                break
            }
        }
        if ($underInternal) { continue }

        $bucket = $pathIndex[$sweepPath]
        $sortedNames = New-Object 'System.Collections.Generic.List[string]'
        foreach ($n in $bucket['Values'].Keys) { $sortedNames.Add($n) }
        $sortedNames.Sort([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($sweepName in $sortedNames) {
            $sweepValue = ($bucket['Values'])[$sweepName]
            if ($sweepValue['Matched']) { continue }

            # DESIGN section 4 security promotion subset.
            $reasons = New-Object 'System.Collections.Generic.List[string]'
            if (Test-PathUnder -Path $sweepPath -Root $policyRoot) {
                $reasons.Add('policy-twin value not known to the database')
            }
            $segment = Get-ProviderSegment -Path $sweepPath
            if ($null -ne $segment -and -not $knownProviders.Contains($segment)) {
                $reasons.Add(("subkey 'TimeProviders\{0}' is not a documented time provider" -f $segment))
            }
            if ($sweepName -like '*Dll*') {
                $reasons.Add("value name matches '*Dll*'")
            }
            $promoted = ($reasons.Count -gt 0)
            $noteText = 'value not present in the W32Time key database'
            if ($promoted) {
                $noteText = ('security-promoted undocumented value: {0}' -f ($reasons -join '; '))
            }
            New-ConfigRecord -KeyPath $bucket['Path'] -ValueName $sweepValue['Name'] -TypeName $sweepValue['Kind'] `
                -Data $sweepValue['Data'] -Expected $null -ExpectedSource $null -Status 'Undocumented' `
                -Class 'unknown' -GpoBacked $false -PolicyApplied $false -Note $noteText -Promoted $promoted
        }
    }
}
