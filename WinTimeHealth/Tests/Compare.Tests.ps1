#
# Pester 5 tests for Private/Compare-W32TimeConfig.ps1 (comparison engine).
#
# Dot-sources the specific Private functions it needs; does NOT import the
# module. When the parallel-built database components
# (ConvertFrom-SimpleYaml / Get-W32TimeDatabase / Resolve-W32TimeExpectation)
# are not present yet, a minimal contract-shaped stub database and stub
# resolver are used instead; the real-database context is gated on Test-Path.
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester 5 scoping: variables assigned in BeforeAll/BeforeDiscovery are consumed in It blocks')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'test-fixture factories (New-RegValue/New-TestTarget/New-StubDatabase) are pure in-memory builders')]
param()

Set-StrictMode -Version Latest

BeforeDiscovery {
    $privateDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Private'
    $dataFile = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'Data') 'W32TimeKeys.yaml'
    $script:HasRealDb = (Test-Path (Join-Path $privateDir 'Get-W32TimeDatabase.ps1')) -and
        (Test-Path (Join-Path $privateDir 'ConvertFrom-SimpleYaml.ps1')) -and
        (Test-Path $dataFile)
}

BeforeAll {
    Set-StrictMode -Version Latest

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $privateDir = Join-Path $moduleRoot 'Private'
    $script:DataFile = Join-Path (Join-Path $moduleRoot 'Data') 'W32TimeKeys.yaml'

    . (Join-Path $privateDir 'Compare-W32TimeConfig.ps1')

    # Resolver: real one when the parallel component landed, else a minimal
    # stub implementing the fixed contract:
    #   Resolve-W32TimeExpectation -Entry <db entry> -Role <Dc|RootPdce> -OsBuild <int?>
    #   -> @{ Expected; Source }
    $resolverFile = Join-Path $privateDir 'Resolve-W32TimeExpectation.ps1'
    if (Test-Path $resolverFile) {
        . $resolverFile
    }
    else {
        function Resolve-W32TimeExpectation {
            param($Entry, [string]$Role, $OsBuild)
            $value = $null
            $defaults = $null
            if ($Entry -is [System.Collections.IDictionary] -and $Entry.Contains('defaults')) { $defaults = $Entry['defaults'] }
            if ($null -ne $defaults) {
                if ($Role -eq 'RootPdce' -and $defaults.Contains('pdce')) { $value = $defaults['pdce'] }
                elseif ($defaults.Contains('dc')) { $value = $defaults['dc'] }
            }
            $overrides = $null
            if ($Entry -is [System.Collections.IDictionary] -and $Entry.Contains('defaults_overrides')) { $overrides = $Entry['defaults_overrides'] }
            if ($null -ne $overrides -and $null -ne $OsBuild -and [int]$OsBuild -gt 0) {
                foreach ($override in @($overrides)) {
                    if ($null -eq $override) { continue }
                    $min = 0
                    $max = [int]::MaxValue
                    if ($override.Contains('min_build')) { $min = [int]$override['min_build'] }
                    if ($override.Contains('max_build')) { $max = [int]$override['max_build'] }
                    $roleOk = $true
                    if ($override.Contains('role')) {
                        $overrideRole = [string]$override['role']
                        if ($overrideRole -ne 'dc') { $roleOk = $false }  # targets here are always DCs
                    }
                    if ($roleOk -and [int]$OsBuild -ge $min -and [int]$OsBuild -le $max) {
                        $value = $override['value']
                    }
                }
            }
            return @{ Expected = $value; Source = 'MSDefault' }
        }
    }

    # ---- shared fixtures -----------------------------------------------

    $script:CfgPath = 'SYSTEM\CurrentControlSet\Services\W32Time\Config'
    $script:ParamsPath = 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $script:NtpClientPath = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
    $script:PolConfigPath = 'SOFTWARE\Policies\Microsoft\W32Time\Config'
    $script:PolParamsPath = 'SOFTWARE\Policies\Microsoft\W32Time\Parameters'
    $script:PolNtpClientPath = 'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
    $script:StlPath = 'SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits'

    function New-RegValue {
        param([string]$Kind, $Data)
        return @{ Kind = $Kind; Data = $Data }
    }

    function New-TestTarget {
        param([bool]$IsRootPdce = $false, [string]$ComputerName = 'dc01.corp.example.com')
        return [pscustomobject]@{
            ComputerName = $ComputerName
            Domain       = 'corp.example.com'
            Site         = 'HQ'
            IsRootPdce   = $IsRootPdce
            IsRodc       = $false
            DomainDepth  = 0
        }
    }

    # Minimal contract-shaped database stub (entry hashtables mirror the
    # YAML fields; defaults deliberately small so expectations are obvious).
    function New-StubDatabase {
        $keys = @(
            @{
                path = $CfgPath; value = 'AnnounceFlags'; type = 'REG_DWORD'; class = 'config'
                gpo = @{ policy = 'Global Configuration Settings'; policy_path = $PolConfigPath; gpo_default = 10 }
                defaults = @{ dc = 10; member = 10; standalone = 10; pdce = 5 }
                defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = 'stub'
            },
            @{
                path = $CfgPath; value = 'EventLogFlags'; type = 'REG_DWORD'; class = 'config'
                gpo = @{ policy = 'Global Configuration Settings'; policy_path = $PolConfigPath; gpo_default = 2 }
                defaults = @{ dc = 2; member = 2; standalone = 2 }
                defaults_overrides = $null; compare = 'exact'; units = $null; notes = 'stub'
            },
            @{
                path = $CfgPath; value = 'MaxNegPhaseCorrection'; type = 'REG_DWORD'; class = 'config'
                gpo = @{ policy = 'Global Configuration Settings'; policy_path = $PolConfigPath; gpo_default = 172800 }
                defaults = @{ dc = [uint32]4294967295; member = [uint32]4294967295; standalone = 54000 }
                defaults_overrides = $null; compare = 'exact'; units = 'seconds'; notes = 'stub 0xFFFFFFFF'
            },
            @{
                path = $NtpClientPath; value = 'SpecialPollInterval'; type = 'REG_DWORD'; class = 'config'
                gpo = @{ policy = 'Time Providers\Configure Windows NTP Client'; policy_path = $PolNtpClientPath; gpo_default = 1024 }
                defaults = @{ dc = 3600; member = 3600; standalone = 604800 }
                defaults_overrides = $null; compare = 'exact'; units = 'seconds'; notes = 'stub'
            },
            @{
                path = $ParamsPath; value = 'Type'; type = 'REG_SZ'; class = 'config'
                gpo = @{ policy = 'Time Providers\Configure Windows NTP Client'; policy_path = $PolParamsPath; gpo_default = 'NT5DS' }
                defaults = @{ dc = 'NT5DS'; member = 'NT5DS'; standalone = 'NTP'; pdce = 'NTP' }
                defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = 'stub'
            },
            @{
                path = $ParamsPath; value = 'NtpServer'; type = 'REG_SZ'; class = 'config'
                gpo = @{ policy = 'Time Providers\Configure Windows NTP Client'; policy_path = $PolParamsPath; gpo_default = 'time.windows.com,0x9' }
                defaults = @{ dc = $null; member = $null; standalone = 'time.windows.com,0x1'; pdce = $null }
                defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = 'stub'
            },
            @{
                path = $ParamsPath; value = 'ServiceDll'; type = 'REG_EXPAND_SZ'; class = 'internal'
                gpo = $null
                defaults = @{ dc = '%windir%\System32\W32Time.dll'; member = '%windir%\System32\W32Time.dll'; standalone = '%windir%\System32\W32Time.dll' }
                defaults_overrides = $null; compare = 'exact'; units = $null; notes = 'stub tamper check'
            },
            @{
                path = $CfgPath; value = 'TestMulti'; type = 'REG_MULTI_SZ'; class = 'config'
                gpo = $null
                defaults = @{ dc = @('alpha', 'beta'); member = @('alpha', 'beta'); standalone = @('alpha', 'beta') }
                defaults_overrides = $null; compare = 'exact'; units = $null; notes = 'stub multistring'
            },
            @{
                path = $CfgPath; value = 'FileLogName'; type = 'REG_SZ'; class = 'diagnostic'
                gpo = $null
                defaults = @{ dc = $null; member = $null; standalone = $null }
                defaults_overrides = $null; compare = 'exact'; units = $null; notes = 'stub diagnostic'
            },
            @{
                path = 'SYSTEM\CurrentControlSet\Services\W32Time'; value = 'DependOnService'; type = 'REG_MULTI_SZ'; class = 'internal'
                gpo = $null
                defaults = @{ dc = $null; member = $null; standalone = $null }
                defaults_overrides = $null; compare = 'ignore'; units = $null; notes = 'stub ignore'
            }
        )
        return @{
            SchemaVersion    = 2
            Verified         = '2026-07-11'
            Keys             = $keys
            InternalSubtrees = @(
                @{ path = $StlPath; notes = 'stub STS runtime state' },
                @{ path = 'SYSTEM\CurrentControlSet\Services\W32Time\Security'; notes = 'stub security descriptor cache' }
            )
        }
    }

    function Invoke-CompareTest {
        param(
            [hashtable]$Tree,
            $Target,
            $Database,
            [hashtable]$DcBaseline = $null,
            [hashtable]$PdceBaseline = $null,
            [bool]$RootPdceDetected = $true,
            [int]$OsBuild = 20348
        )
        if ($null -eq $Target) { $Target = New-TestTarget }
        if ($null -eq $Database) { $Database = $script:StubDb }
        return @(Compare-W32TimeConfig -Tree $Tree -Target $Target -Database $Database `
                -DcBaseline $DcBaseline -PdceBaseline $PdceBaseline `
                -RootPdceDetected $RootPdceDetected -OsBuild $OsBuild `
                -RunId 'run-0001' -Timestamp '2026-07-11T00:00:00.0000000Z')
    }

    function Find-Record {
        param($Records, [string]$ValueName, [string]$KeyPath = '')
        # comma operator keeps an empty result an array (StrictMode-safe .Count)
        if ($KeyPath -ne '') {
            return , @($Records | Where-Object { $_.ValueName -eq $ValueName -and $_.KeyPath -eq $KeyPath })
        }
        return , @($Records | Where-Object { $_.ValueName -eq $ValueName })
    }

    $script:StubDb = New-StubDatabase
}

Describe 'Compare-W32TimeConfig (stub database)' {

    Context 'record shape' {
        BeforeAll {
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]10)) } }
            $script:ShapeRecords = Invoke-CompareTest -Tree $tree -Target (New-TestTarget)
            $script:ShapeRecord = (Find-Record $ShapeRecords 'AnnounceFlags')[0]
        }

        It 'stamps the WinTime.ConfigRecord type name' {
            $ShapeRecord.PSObject.TypeNames | Should -Contain 'WinTime.ConfigRecord'
        }

        It 'carries every DESIGN section 3 property plus Promoted, in order' {
            (@($ShapeRecord.PSObject.Properties.Name) -join ',') |
                Should -Be 'Server,Domain,Role,OsBuild,KeyPath,ValueName,Type,Data,Expected,ExpectedSource,Status,IsDrift,Class,GpoBacked,PolicyApplied,Note,Promoted,RunId,Timestamp'
        }

        It 'passes through Server, Domain, OsBuild, RunId and Timestamp' {
            $ShapeRecord.Server | Should -Be 'dc01.corp.example.com'
            $ShapeRecord.Domain | Should -Be 'corp.example.com'
            $ShapeRecord.OsBuild | Should -Be 20348
            $ShapeRecord.RunId | Should -Be 'run-0001'
            $ShapeRecord.Timestamp | Should -Be '2026-07-11T00:00:00.0000000Z'
        }

        It 'emits one record per non-ignore database entry and nothing undocumented for a known-only tree' {
            # 10 stub entries: 9 compared + 1 ignore entry that is absent.
            $ShapeRecords.Count | Should -Be 9
            @($ShapeRecords | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
        }
    }

    Context 'expectation cascade and status' {
        It 'matches an MS-default value (Match, ExpectedSource MSDefault)' {
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]10)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'MSDefault'
            $rec.Expected | Should -Be ([uint32]10)
            $rec.IsDrift | Should -BeFalse
            $rec.GpoBacked | Should -BeTrue
            $rec.PolicyApplied | Should -BeFalse
            $rec.Role | Should -Be 'Dc'
            $rec.Class | Should -Be 'config'
        }

        It 'reports numeric drift against the MS default' {
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]7)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'Drift'
            $rec.IsDrift | Should -BeTrue
            $rec.Data | Should -Be ([uint32]7)
            $rec.Expected | Should -Be ([uint32]10)
        }

        It 'appends the GPO-preset hint when a drift value equals gpo_default and no policy is applied' {
            $tree = @{ $NtpClientPath = @{ SpecialPollInterval = (New-RegValue 'DWord' ([uint32]1024)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'SpecialPollInterval')[0]
            $rec.Status | Should -Be 'Drift'
            $rec.PolicyApplied | Should -BeFalse
            $rec.Note | Should -Match 'matches GPO preset'
            $rec.Note | Should -Match 'likely a GPO applying'
        }

        It 'does not append the GPO-preset hint when the drift value differs from gpo_default' {
            $tree = @{ $NtpClientPath = @{ SpecialPollInterval = (New-RegValue 'DWord' ([uint32]777)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'SpecialPollInterval')[0]
            $rec.Status | Should -Be 'Drift'
            if ($null -ne $rec.Note) { $rec.Note | Should -Not -Match 'matches GPO preset' }
        }

        It 'uses the policy twin as the effective expectation (Match)' {
            $tree = @{
                $CfgPath      = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]3)) }
                $PolConfigPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]3)) }
            }
            $recs = Invoke-CompareTest -Tree $tree
            $rec = (Find-Record $recs 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'Policy'
            $rec.PolicyApplied | Should -BeTrue
            $rec.Expected | Should -Be ([uint32]3)
            # the consumed policy twin must not surface as Undocumented
            @($recs | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
        }

        It 'flags divergence from an applied GPO as Drift with the diverges Note' {
            $tree = @{
                $CfgPath      = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]2)) }
                $PolConfigPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]3)) }
            }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Drift'
            $rec.ExpectedSource | Should -Be 'Policy'
            $rec.Note | Should -Match 'diverges from applied GPO'
        }

        It 'reports Missing when the policy twin defines the value but the operational value is absent' {
            $tree = @{ $PolConfigPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]3)) } }
            $recs = Invoke-CompareTest -Tree $tree
            $rec = (Find-Record $recs 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Missing'
            $rec.IsDrift | Should -BeTrue
            $rec.PolicyApplied | Should -BeTrue
            $rec.Note | Should -Match 'diverges from applied GPO'
            @($recs | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
        }

        It 'reports NotSet (not drift) for an absent value with no baseline' {
            $rec = (Find-Record (Invoke-CompareTest -Tree @{}) 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'NotSet'
            $rec.IsDrift | Should -BeFalse
            $rec.Data | Should -BeNullOrEmpty
            $rec.Expected | Should -Be ([uint32]2)     # informational MS default
            $rec.ExpectedSource | Should -Be 'MSDefault'
        }

        It 'reports Missing (drift) for an absent value the baseline defines' {
            $baseline = @{ $CfgPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]2)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree @{} -DcBaseline $baseline) 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Missing'
            $rec.IsDrift | Should -BeTrue
            $rec.ExpectedSource | Should -Be 'Baseline'
        }

        It 'prefers the DC baseline over the MS default' {
            $baseline = @{ $CfgPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $tree = @{ $CfgPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $baseline) 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'Baseline'
            $rec.Expected | Should -Be ([uint32]5)

            $tree2 = @{ $CfgPath = @{ EventLogFlags = (New-RegValue 'DWord' ([uint32]2)) } }
            $rec2 = (Find-Record (Invoke-CompareTest -Tree $tree2 -DcBaseline $baseline) 'EventLogFlags' $CfgPath)[0]
            $rec2.Status | Should -Be 'Drift'
            $rec2.ExpectedSource | Should -Be 'Baseline'
        }
    }

    Context 'pdce exemption' {
        It 'reports PdceExempt on the root PDCe with no PdceBaseline, Note carrying actual + conventional values' {
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Target (New-TestTarget -IsRootPdce $true)) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'PdceExempt'
            $rec.IsDrift | Should -BeFalse
            $rec.Role | Should -Be 'RootPdce'
            $rec.Expected | Should -Be ([uint32]5)     # conventional PDCe value
            $rec.Note | Should -Match 'PDCe-exempt'
            $rec.Note | Should -Match 'actual value 5'
            $rec.Note | Should -Match 'conventional PDCe expectation 5'
        }

        It 'reports PdceExempt with (absent) in the Note when the value is missing on the PDCe' {
            $rec = (Find-Record (Invoke-CompareTest -Tree @{} -Target (New-TestTarget -IsRootPdce $true)) 'NtpServer' $ParamsPath)[0]
            $rec.Status | Should -Be 'PdceExempt'
            $rec.Note | Should -Match '\(absent\)'
        }

        It 'compares against the PdceBaseline when provided (Match and Drift)' {
            $pdceBaseline = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Target (New-TestTarget -IsRootPdce $true) -PdceBaseline $pdceBaseline) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'Baseline'

            $tree2 = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]10)) } }
            $rec2 = (Find-Record (Invoke-CompareTest -Tree $tree2 -Target (New-TestTarget -IsRootPdce $true) -PdceBaseline $pdceBaseline) 'AnnounceFlags')[0]
            $rec2.Status | Should -Be 'Drift'
        }

        It 'lets an applied policy trump the exemption on the PDCe' {
            $tree = @{
                $CfgPath      = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]5)) }
                $PolConfigPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]10)) }
            }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Target (New-TestTarget -IsRootPdce $true)) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'Drift'
            $rec.ExpectedSource | Should -Be 'Policy'
            $rec.PolicyApplied | Should -BeTrue
            $rec.Note | Should -Match 'diverges from applied GPO'
        }

        It 'treats pdce-exempt as exact with a Note when PDCe detection failed' {
            $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]5)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Target (New-TestTarget -IsRootPdce $true) -RootPdceDetected $false) 'AnnounceFlags')[0]
            $rec.Status | Should -Be 'Drift'                 # 5 vs Dc default 10
            $rec.Role | Should -Be 'Dc'                      # exemption disabled
            $rec.Note | Should -Match 'PDCe detection failed; exemption disabled'
        }

        It 'treats pdce-exempt entries on ordinary DCs as exact' {
            $tree = @{ $ParamsPath = @{ Type = (New-RegValue 'String' 'NTP') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'Type' $ParamsPath)[0]
            $rec.Status | Should -Be 'Drift'                 # NTP vs NT5DS on a plain DC
            $rec.Expected | Should -Be 'NT5DS'
        }

        It 'reports NotSet for an absent admin-defined pdce-exempt value on an ordinary DC' {
            $rec = (Find-Record (Invoke-CompareTest -Tree @{}) 'NtpServer' $ParamsPath)[0]
            $rec.Status | Should -Be 'NotSet'
            $rec.IsDrift | Should -BeFalse
        }
    }

    Context 'value comparison semantics' {
        It 'compares 0xFFFFFFFF as unsigned (Match against the MS default)' {
            $tree = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'MaxNegPhaseCorrection')[0]
            $rec.Status | Should -Be 'Match'
            $rec.Data | Should -Be ([uint32]::MaxValue)
            $rec.Expected | Should -Be ([uint32]::MaxValue)
            $rec.Expected | Should -BeOfType [uint32]
        }

        It 'compares 0xFFFFFFFF as unsigned via a baseline expectation' {
            $baseline = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
            $tree = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $baseline) 'MaxNegPhaseCorrection')[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'Baseline'
        }

        It 'accepts a hex-string expectation for a DWORD (0xFFFFFFFF)' {
            $baseline = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' '0xFFFFFFFF') } }
            $tree = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $baseline) 'MaxNegPhaseCorrection')[0]
            $rec.Status | Should -Be 'Match'
        }

        It 'compares strings OrdinalIgnoreCase' {
            $tree = @{ $ParamsPath = @{ Type = (New-RegValue 'String' 'nt5ds') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'Type' $ParamsPath)[0]
            $rec.Status | Should -Be 'Match'
        }

        It 'compares REG_EXPAND_SZ tamper values case-insensitively and flags changes' {
            $tree = @{ $ParamsPath = @{ ServiceDll = (New-RegValue 'ExpandString' '%WINDIR%\system32\w32time.DLL') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'ServiceDll')[0]
            $rec.Status | Should -Be 'Match'

            $tree2 = @{ $ParamsPath = @{ ServiceDll = (New-RegValue 'ExpandString' 'C:\evil\w32time.dll') } }
            $rec2 = (Find-Record (Invoke-CompareTest -Tree $tree2) 'ServiceDll')[0]
            $rec2.Status | Should -Be 'Drift'
        }

        It 'compares REG_MULTI_SZ element-wise' {
            $match = @{ $CfgPath = @{ TestMulti = (New-RegValue 'MultiString' @('alpha', 'beta')) } }
            (Find-Record (Invoke-CompareTest -Tree $match) 'TestMulti')[0].Status | Should -Be 'Match'

            $caseOnly = @{ $CfgPath = @{ TestMulti = (New-RegValue 'MultiString' @('ALPHA', 'beta')) } }
            (Find-Record (Invoke-CompareTest -Tree $caseOnly) 'TestMulti')[0].Status | Should -Be 'Match'

            $reordered = @{ $CfgPath = @{ TestMulti = (New-RegValue 'MultiString' @('beta', 'alpha')) } }
            (Find-Record (Invoke-CompareTest -Tree $reordered) 'TestMulti')[0].Status | Should -Be 'Drift'

            $shorter = @{ $CfgPath = @{ TestMulti = (New-RegValue 'MultiString' @('alpha')) } }
            (Find-Record (Invoke-CompareTest -Tree $shorter) 'TestMulti')[0].Status | Should -Be 'Drift'
        }

        It 'keeps REG_MULTI_SZ Data and Expected as string arrays' {
            $tree = @{ $CfgPath = @{ TestMulti = (New-RegValue 'MultiString' @('alpha', 'beta')) } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'TestMulti')[0]
            , $rec.Data | Should -BeOfType [System.Array]
            , $rec.Expected | Should -BeOfType [System.Array]
            @($rec.Expected).Count | Should -Be 2
        }

        It 'flags a registry type mismatch as Drift with a Note and skips the data compare' {
            $tree = @{ $CfgPath = @{ EventLogFlags = (New-RegValue 'String' '2') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'EventLogFlags' $CfgPath)[0]
            $rec.Status | Should -Be 'Drift'
            $rec.Type | Should -Be 'String'
            $rec.Note | Should -Match 'type mismatch'
            $rec.Note | Should -Match 'REG_DWORD'
        }

        It 'records a present admin-defined value (no expectation) as Match with a Note' {
            $tree = @{ $CfgPath = @{ FileLogName = (New-RegValue 'String' 'C:\w32tm.log') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree) 'FileLogName')[0]
            $rec.Status | Should -Be 'Match'
            $rec.Expected | Should -BeNullOrEmpty
            $rec.Note | Should -Match 'recorded without comparison'
            $rec.Class | Should -Be 'diagnostic'
        }
    }

    Context 'NtpServer peer list' {
        BeforeAll {
            $script:PeerBaseline = @{ $ParamsPath = @{ NtpServer = (New-RegValue 'String' 'a.pool.org,0x8 b.pool.org,0x8') } }
        }

        It 'matches an ordinally identical peer list' {
            $tree = @{ $ParamsPath = @{ NtpServer = (New-RegValue 'String' 'a.pool.org,0x8 b.pool.org,0x8') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $PeerBaseline) 'NtpServer')[0]
            $rec.Status | Should -Be 'Match'
            $rec.ExpectedSource | Should -Be 'Baseline'
        }

        It 'reports Drift with a whitespace/case Note when the list differs only in whitespace/case' {
            $tree = @{ $ParamsPath = @{ NtpServer = (New-RegValue 'String' 'A.pool.org,0x8  b.pool.org,0x8') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $PeerBaseline) 'NtpServer')[0]
            $rec.Status | Should -Be 'Drift'
            $rec.Note | Should -Match 'whitespace/case'
        }

        It 'reports plain Drift without the whitespace Note for a genuinely different peer list' {
            $tree = @{ $ParamsPath = @{ NtpServer = (New-RegValue 'String' 'c.pool.org,0x8') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $PeerBaseline) 'NtpServer')[0]
            $rec.Status | Should -Be 'Drift'
            if ($null -ne $rec.Note) { $rec.Note | Should -Not -Match 'whitespace/case' }
        }

        It 'hints when a drifted peer list equals the documented GPO preset' {
            $tree = @{ $ParamsPath = @{ NtpServer = (New-RegValue 'String' 'time.windows.com,0x9') } }
            $rec = (Find-Record (Invoke-CompareTest -Tree $tree -DcBaseline $PeerBaseline) 'NtpServer')[0]
            $rec.Status | Should -Be 'Drift'
            $rec.Note | Should -Match 'matches GPO preset'
        }
    }

    Context 'ignored entries and internal subtrees' {
        It 'emits an Ignored record for a present compare:ignore value' {
            $tree = @{ 'SYSTEM\CurrentControlSet\Services\W32Time' = @{ DependOnService = (New-RegValue 'MultiString' @('tdx')) } }
            $recs = Invoke-CompareTest -Tree $tree
            $rec = (Find-Record $recs 'DependOnService')[0]
            $rec.Status | Should -Be 'Ignored'
            $rec.Class | Should -Be 'internal'
            $rec.IsDrift | Should -BeFalse
            $rec.Expected | Should -BeNullOrEmpty
        }

        It 'emits nothing for an absent compare:ignore value' {
            (Find-Record (Invoke-CompareTest -Tree @{}) 'DependOnService').Count | Should -Be 0
        }

        It 'reports an existing internal subtree once as Ignored (subtree) and never diffs its contents' {
            $tree = @{
                $StlPath              = @{
                    SecureTimeEstimated = (New-RegValue 'QWord' ([uint64]133600000000000000))
                    SecureTimeConfidence = (New-RegValue 'DWord' ([uint32]6))
                }
                ($StlPath + '\RunTime') = @{ SecureTimeTickCount = (New-RegValue 'QWord' ([uint64]12345)) }
            }
            $recs = Invoke-CompareTest -Tree $tree
            $subtreeRecs = @($recs | Where-Object { $_.ValueName -eq '(subtree)' })
            $subtreeRecs.Count | Should -Be 1
            $subtreeRecs[0].KeyPath | Should -Be $StlPath
            $subtreeRecs[0].Status | Should -Be 'Ignored'
            $subtreeRecs[0].Class | Should -Be 'internal'
            $subtreeRecs[0].Note | Should -Match '2 key\(s\), 3 value\(s\)'
            # none of the subtree values leak into the undocumented sweep
            @($recs | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
        }

        It 'emits no subtree record when the internal subtree is absent' {
            $recs = Invoke-CompareTest -Tree @{}
            @($recs | Where-Object { $_.ValueName -eq '(subtree)' }).Count | Should -Be 0
        }
    }

    Context 'undocumented sweep and promotion' {
        BeforeAll {
            $tree = @{
                $CfgPath = @{
                    AnnounceFlags = (New-RegValue 'DWord' ([uint32]10))
                    RandomLegacy  = (New-RegValue 'String' 'x')
                    HelperDll     = (New-RegValue 'String' 'evil.dll')
                }
                'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Evil' = @{
                    Anything = (New-RegValue 'DWord' ([uint32]1))
                }
                $NtpClientPath = @{ WeirdButHarmless = (New-RegValue 'DWord' ([uint32]9)) }
                $PolConfigPath = @{ UnknownPolicyValue = (New-RegValue 'DWord' ([uint32]1)) }
                'SOFTWARE\Microsoft\Windows NT\CurrentVersion' = @{ CurrentBuildNumber = (New-RegValue 'String' '20348') }
                'SYSTEM\CurrentControlSet\Control\SystemInformation' = @{ SystemManufacturer = (New-RegValue 'String' 'Contoso') }
            }
            $script:SweepRecords = Invoke-CompareTest -Tree $tree
            $script:Undocumented = @($SweepRecords | Where-Object { $_.Status -eq 'Undocumented' })
        }

        It 'reports an unknown value in a documented key as Undocumented, not promoted' {
            $rec = (Find-Record $Undocumented 'RandomLegacy')[0]
            $rec.Class | Should -Be 'unknown'
            $rec.IsDrift | Should -BeFalse
            $rec.Promoted | Should -BeFalse
        }

        It 'promotes a value under an unknown TimeProviders subkey' {
            $rec = (Find-Record $Undocumented 'Anything')[0]
            $rec.Promoted | Should -BeTrue
            $rec.Note | Should -Match 'not a documented time provider'
        }

        It 'promotes any value name matching *Dll*' {
            $rec = (Find-Record $Undocumented 'HelperDll')[0]
            $rec.Promoted | Should -BeTrue
            $rec.Note | Should -Match 'Dll'
        }

        It 'promotes an unknown policy-twin value' {
            $rec = (Find-Record $Undocumented 'UnknownPolicyValue')[0]
            $rec.Promoted | Should -BeTrue
            $rec.Note | Should -Match 'policy-twin value not known'
        }

        It 'does not promote an unknown value under a documented provider' {
            $rec = (Find-Record $Undocumented 'WeirdButHarmless')[0]
            $rec.Promoted | Should -BeFalse
        }

        It 'never sweeps the build/hypervisor metadata keys' {
            (Find-Record $SweepRecords 'CurrentBuildNumber').Count | Should -Be 0
            (Find-Record $SweepRecords 'SystemManufacturer').Count | Should -Be 0
        }

        It 'matches database entries case-insensitively so they do not resurface in the sweep' {
            $tree = @{ ($CfgPath.ToUpperInvariant()) = @{ 'ANNOUNCEFLAGS' = (New-RegValue 'DWord' ([uint32]10)) } }
            $recs = Invoke-CompareTest -Tree $tree
            (Find-Record $recs 'AnnounceFlags' $CfgPath)[0].Status | Should -Be 'Match'
            @($recs | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
        }
    }
}

Describe 'Compare-W32TimeConfig (real database)' -Skip:(-not $HasRealDb) {
    BeforeAll {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $privateDir = Join-Path $moduleRoot 'Private'
        . (Join-Path $privateDir 'ConvertFrom-SimpleYaml.ps1')
        . (Join-Path $privateDir 'Get-W32TimeDatabase.ps1')

        $loader = Get-Command Get-W32TimeDatabase
        if ($loader.Parameters.ContainsKey('Path')) {
            $script:RealDb = Get-W32TimeDatabase -Path $DataFile
        }
        else {
            $script:RealDb = Get-W32TimeDatabase
        }
    }

    It 'matches AnnounceFlags=10 on an ordinary DC against the real database' {
        $tree = @{ $CfgPath = @{ AnnounceFlags = (New-RegValue 'DWord' ([uint32]10)) } }
        $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Database $RealDb) 'AnnounceFlags' $CfgPath)[0]
        $rec.Status | Should -Be 'Match'
        $rec.ExpectedSource | Should -Be 'MSDefault'
    }

    It 'hints at the GPO preset for SpecialPollInterval=1024 drift (real gpo_default)' {
        $tree = @{ $NtpClientPath = @{ SpecialPollInterval = (New-RegValue 'DWord' ([uint32]1024)) } }
        $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Database $RealDb) 'SpecialPollInterval' $NtpClientPath)[0]
        $rec.Status | Should -Be 'Drift'
        $rec.Note | Should -Match 'matches GPO preset'
    }

    It 'round-trips 0xFFFFFFFF unsigned through a baseline compare' {
        $baseline = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
        $tree = @{ $CfgPath = @{ MaxNegPhaseCorrection = (New-RegValue 'DWord' ([uint32]::MaxValue)) } }
        $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Database $RealDb -DcBaseline $baseline) 'MaxNegPhaseCorrection' $CfgPath)[0]
        $rec.Status | Should -Be 'Match'
        $rec.ExpectedSource | Should -Be 'Baseline'
    }

    It 'promotes a synthetic TimeProviders\Evil subkey against the real database' {
        $tree = @{
            'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Evil' = @{
                EvilDll = (New-RegValue 'ExpandString' 'C:\evil.dll')
            }
        }
        $rec = (Find-Record (Invoke-CompareTest -Tree $tree -Database $RealDb) 'EvilDll')[0]
        $rec.Status | Should -Be 'Undocumented'
        $rec.Class | Should -Be 'unknown'
        $rec.Promoted | Should -BeTrue
    }

    It 'reports the real SecureTimeLimits internal subtree as Ignored (subtree)' {
        $tree = @{ $StlPath = @{ SecureTimeConfidence = (New-RegValue 'DWord' ([uint32]6)) } }
        $recs = Invoke-CompareTest -Tree $tree -Database $RealDb
        $subtreeRecs = @($recs | Where-Object { $_.ValueName -eq '(subtree)' -and $_.KeyPath -eq $StlPath })
        $subtreeRecs.Count | Should -Be 1
        $subtreeRecs[0].Status | Should -Be 'Ignored'
        @($recs | Where-Object { $_.Status -eq 'Undocumented' }).Count | Should -Be 0
    }
}
