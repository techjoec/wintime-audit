#Requires -Version 5.1
# Pester 5 tests for the YAML database loader component:
#   Private/ConvertFrom-SimpleYaml.ps1
#   Private/Get-W32TimeDatabase.ps1
#   Private/Resolve-W32TimeExpectation.ps1

Set-StrictMode -Version Latest

BeforeAll {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    $privateDir = Join-Path -Path $moduleRoot -ChildPath 'Private'
    . (Join-Path -Path $privateDir -ChildPath 'ConvertFrom-SimpleYaml.ps1')
    . (Join-Path -Path $privateDir -ChildPath 'Get-W32TimeDatabase.ps1')
    . (Join-Path -Path $privateDir -ChildPath 'Resolve-W32TimeExpectation.ps1')

    $script:DataPath = Join-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'Data') -ChildPath 'W32TimeKeys.yaml'

    # Finds a key entry by value name and registry path suffix (OrdinalIgnoreCase).
    function Get-DbEntry {
        param([array]$Keys, [string]$PathSuffix, [string]$ValueName)
        foreach ($entry in $Keys) {
            $entryPath = [string]$entry['path']
            $entryValue = [string]$entry['value']
            if ([string]::Equals($entryValue, $ValueName, [System.StringComparison]::OrdinalIgnoreCase) -and
                $entryPath.EndsWith($PathSuffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $entry
            }
        }
        return $null
    }
}

Describe 'ConvertFrom-SimpleYaml' {

    Context 'scalars' {
        It 'parses decimal integers as [int]' {
            $r = ConvertFrom-SimpleYaml -Content 'a: 42'
            $r['a'] | Should -Be 42
            $r['a'] | Should -BeOfType [int]
        }

        It 'parses hex 0xFFFFFFFF as unsigned [uint32] 4294967295' {
            $r = ConvertFrom-SimpleYaml -Content 'a: 0xFFFFFFFF'
            $r['a'] | Should -Be ([uint32]4294967295)
            $r['a'] | Should -BeOfType [uint32]
        }

        It 'parses hex wider than 32 bits as [uint64]' {
            $r = ConvertFrom-SimpleYaml -Content 'a: 0x1FFFFFFFF'
            $r['a'] | Should -Be ([uint64]8589934591)
            $r['a'] | Should -BeOfType [uint64]
        }

        It 'parses null and ~ as $null (key still present)' {
            $r = ConvertFrom-SimpleYaml -Content "a: null`nb: ~"
            $r.ContainsKey('a') | Should -BeTrue
            $r['a'] | Should -Be $null
            $r['b'] | Should -Be $null
        }

        It 'parses booleans' {
            $r = ConvertFrom-SimpleYaml -Content "a: true`nb: false"
            $r['a'] | Should -BeTrue
            $r['b'] | Should -BeFalse
        }

        It 'parses double-quoted strings with backslash escapes' {
            $r = ConvertFrom-SimpleYaml -Content 'a: "%windir%\\System32\\W32Time.dll"'
            $r['a'] | Should -Be '%windir%\System32\W32Time.dll'
        }

        It 'parses single-quoted strings with doubled-quote escapes' {
            $r = ConvertFrom-SimpleYaml -Content "a: 'it''s'"
            $r['a'] | Should -Be "it's"
        }

        It 'keeps plain strings verbatim, including backslashes' {
            $r = ConvertFrom-SimpleYaml -Content 'a: SYSTEM\CurrentControlSet\Services\W32Time'
            $r['a'] | Should -Be 'SYSTEM\CurrentControlSet\Services\W32Time'
        }

        It 'treats a date-like plain scalar as a string' {
            $r = ConvertFrom-SimpleYaml -Content 'a: 2026-07-11'
            $r['a'] | Should -Be '2026-07-11'
            $r['a'] | Should -BeOfType [string]
        }

        It 'strips trailing comments outside quotes only' {
            $r = ConvertFrom-SimpleYaml -Content "a: 5 # comment`nb: `"x # not a comment`" # real comment"
            $r['a'] | Should -Be 5
            $r['b'] | Should -Be 'x # not a comment'
        }
    }

    Context 'structures' {
        It 'parses nested block maps' {
            $yaml = @'
gpo:
  policy: Global Configuration Settings
  policy_path: SOFTWARE\Policies\Microsoft\W32Time\Config
  gpo_default: 10
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $r['gpo']['policy'] | Should -Be 'Global Configuration Settings'
            $r['gpo']['gpo_default'] | Should -Be 10
        }

        It 'parses sequences of block maps with nested maps and flow maps' {
            $yaml = @'
keys:
  - path: SYSTEM\A
    value: One
    gpo:
      policy: P1
    defaults: { dc: 1, member: 0xFFFFFFFF, standalone: null }
  - path: SYSTEM\B
    value: Two
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $items = @($r['keys'])
            $items.Count | Should -Be 2
            $items[0]['gpo']['policy'] | Should -Be 'P1'
            $items[0]['defaults']['dc'] | Should -Be 1
            $items[0]['defaults']['member'] | Should -Be ([uint32]4294967295)
            $items[0]['defaults'].ContainsKey('standalone') | Should -BeTrue
            $items[0]['defaults']['standalone'] | Should -Be $null
            $items[1]['value'] | Should -Be 'Two'
        }

        It 'parses sequences of inline flow maps' {
            $yaml = @'
defaults_overrides:
  - { min_build: 26100, value: 0 }
  - { max_build: 200, role: dc, value: 5 }
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $ov = @($r['defaults_overrides'])
            $ov.Count | Should -Be 2
            $ov[0]['min_build'] | Should -Be 26100
            $ov[0]['value'] | Should -Be 0
            $ov[1]['role'] | Should -Be 'dc'
        }

        It 'parses inline flow maps with quoted keys and quoted values' {
            $r = ConvertFrom-SimpleYaml -Content 'os: { "Server 2025": "default is 0; see notes", plain: 3 }'
            $r['os']['Server 2025'] | Should -Be 'default is 0; see notes'
            $r['os']['plain'] | Should -Be 3
        }

        It 'folds >- block scalars to a single space-joined string' {
            $yaml = @'
notes: >-
  first line
  second line
after: 1
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $r['notes'] | Should -Be 'first line second line'
            $r['after'] | Should -Be 1
        }

        It 'does not treat # inside folded scalar content as a comment' {
            $yaml = @'
notes: >-
  value 0x1 # flag one
  and more
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $r['notes'] | Should -Be 'value 0x1 # flag one and more'
        }

        It 'skips full-line and indented comments' {
            $yaml = @'
# header
a: 1
  # section comment
b: 2
'@
            $r = ConvertFrom-SimpleYaml -Content $yaml
            $r['a'] | Should -Be 1
            $r['b'] | Should -Be 2
        }

        It 'returns an empty hashtable for empty content' {
            $r = ConvertFrom-SimpleYaml -Content ''
            $r | Should -BeOfType [hashtable]
            $r.Count | Should -Be 0
        }
    }

    Context 'unsupported syntax throws instead of misparsing' {
        It 'throws on flow sequences' {
            { ConvertFrom-SimpleYaml -Content 'a: [1, 2]' } | Should -Throw '*flow sequences*'
        }

        It 'throws on nested flow collections' {
            { ConvertFrom-SimpleYaml -Content 'a: { b: { c: 1 } }' } | Should -Throw '*nested flow*'
        }

        It 'throws on literal block scalars (|)' {
            { ConvertFrom-SimpleYaml -Content "a: |`n  x" } | Should -Throw '*not supported*'
        }

        It 'throws on non-stripping folded scalars (>+)' {
            { ConvertFrom-SimpleYaml -Content "a: >+`n  x" } | Should -Throw '*not supported*'
        }

        It 'throws on tab indentation' {
            { ConvertFrom-SimpleYaml -Content "a:`n`tb: 1" } | Should -Throw '*tab*'
        }

        It 'throws on unterminated quoted strings' {
            { ConvertFrom-SimpleYaml -Content 'a: "oops' } | Should -Throw '*unterminated*'
        }

        It 'throws on anchors and aliases' {
            { ConvertFrom-SimpleYaml -Content 'a: &anchor 1' } | Should -Throw '*anchor*'
        }

        It 'throws on duplicate mapping keys' {
            { ConvertFrom-SimpleYaml -Content "a: 1`na: 2" } | Should -Throw '*duplicate*'
        }

        It 'throws on lines that are not mapping entries' {
            { ConvertFrom-SimpleYaml -Content '???' } | Should -Throw '*unsupported syntax*'
        }

        It 'throws on document separators (multi-doc streams)' {
            { ConvertFrom-SimpleYaml -Content "---`na: 1" } | Should -Throw '*unsupported syntax*'
        }

        It 'throws on unsupported double-quote escape sequences' {
            { ConvertFrom-SimpleYaml -Content 'a: "bad \q escape"' } | Should -Throw '*escape*'
        }

        It 'throws on a missing file' {
            { ConvertFrom-SimpleYaml -Path (Join-Path $TestDrive 'no-such-file.yaml') } | Should -Throw '*not found*'
        }
    }
}

Describe 'W32TimeKeys.yaml deep facts (real database)' {

    BeforeAll {
        $script:Raw = ConvertFrom-SimpleYaml -Path $script:DataPath
    }

    It 'declares schema_version 2 and a verified stamp' {
        $script:Raw['schema_version'] | Should -Be 2
        $script:Raw['verified'] | Should -Be '2026-07-11'
    }

    It 'contains 69 registry path entries: 66 keys plus 3 internal subtrees' {
        $keys = @($script:Raw['keys'])
        $subtrees = @($script:Raw['internal_subtrees'])
        $keys.Count | Should -Be 66
        $subtrees.Count | Should -Be 3
        ($keys.Count + $subtrees.Count) | Should -Be 69
    }

    It 'AnnounceFlags: pdce expected-configured value is 5 (dc/member default 10)' {
        $e = Get-DbEntry -Keys @($script:Raw['keys']) -PathSuffix '\W32Time\Config' -ValueName 'AnnounceFlags'
        $e | Should -Not -BeNullOrEmpty
        $e['defaults']['pdce'] | Should -Be 5
        $e['defaults']['dc'] | Should -Be 10
        $e['compare'] | Should -Be 'pdce-exempt'
    }

    It 'MaxNegPhaseCorrection: member default is unsigned 4294967295 (0xFFFFFFFF)' {
        $e = Get-DbEntry -Keys @($script:Raw['keys']) -PathSuffix '\W32Time\Config' -ValueName 'MaxNegPhaseCorrection'
        $e | Should -Not -BeNullOrEmpty
        $e['defaults']['member'] | Should -Be ([uint32]4294967295)
        $e['defaults']['member'] | Should -BeOfType [uint32]
        $e['defaults']['dc'] | Should -Be 172800
    }

    It 'CompatibilityFlags: hex default 0x80000000 parses unsigned' {
        $e = Get-DbEntry -Keys @($script:Raw['keys']) -PathSuffix '\TimeProviders\NtpClient' -ValueName 'CompatibilityFlags'
        $e | Should -Not -BeNullOrEmpty
        $e['defaults']['dc'] | Should -Be ([uint32]2147483648)
        $e['defaults']['dc'] | Should -BeOfType [uint32]
    }

    It 'the six Global-Configuration policy twins under TimeProviders\NtpServer point at ...\W32Time\Config' {
        $ntpServerPath = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'
        $twins = @()
        foreach ($e in @($script:Raw['keys'])) {
            if ([string]::Equals([string]$e['path'], $ntpServerPath, [System.StringComparison]::OrdinalIgnoreCase) -and
                $null -ne $e['gpo'] -and
                [string]$e['gpo']['policy'] -eq 'Global Configuration Settings') {
                $twins += , $e
            }
        }
        $twins.Count | Should -Be 6
        $names = @($twins | ForEach-Object { [string]$_['value'] } | Sort-Object)
        $names | Should -Be @('ChainDisable', 'ChainEntryTimeout', 'ChainLoggingRate', 'ChainMaxEntries', 'ChainMaxHostEntries', 'RequireSecureTimeSyncRequests')
        foreach ($t in $twins) {
            $t['gpo']['policy_path'] | Should -Be 'SOFTWARE\Policies\Microsoft\W32Time\Config'
        }
    }

    It 'NtpServer and Type policy twins point at ...\W32Time\Parameters (ADMX key override)' {
        foreach ($name in @('NtpServer', 'Type')) {
            $e = Get-DbEntry -Keys @($script:Raw['keys']) -PathSuffix '\W32Time\Parameters' -ValueName $name
            $e | Should -Not -BeNullOrEmpty
            $e['gpo']['policy_path'] | Should -Be 'SOFTWARE\Policies\Microsoft\W32Time\Parameters'
        }
    }

    It 'UtilizeSslTimeData carries a defaults_overrides entry: min_build 26100 -> value 0' {
        $e = Get-DbEntry -Keys @($script:Raw['keys']) -PathSuffix '\W32Time\Config' -ValueName 'UtilizeSslTimeData'
        $e | Should -Not -BeNullOrEmpty
        $ov = @($e['defaults_overrides'])
        $ov.Count | Should -Be 1
        $ov[0]['min_build'] | Should -Be 26100
        $ov[0]['value'] | Should -Be 0
    }
}

Describe 'Get-W32TimeDatabase' {

    It 'returns the Database object shape with validated content' {
        $db = Get-W32TimeDatabase
        $db | Should -BeOfType [hashtable]
        $db['SchemaVersion'] | Should -Be 2
        $db['SchemaVersion'] | Should -BeOfType [int]
        $db['Verified'] | Should -Be '2026-07-11'
        $db['Verified'] | Should -BeOfType [string]
        @($db['Keys']).Count | Should -Be 66
        @($db['InternalSubtrees']).Count | Should -Be 3
    }

    It 'caches the database in script scope (same object on second call)' {
        $first = Get-W32TimeDatabase
        $second = Get-W32TimeDatabase
        [object]::ReferenceEquals($first, $second) | Should -BeTrue
    }

    It 'normalizes optional fields so every entry exposes gpo/defaults/defaults_overrides/units/notes' {
        $db = Get-W32TimeDatabase
        foreach ($entry in @($db['Keys'])) {
            foreach ($field in @('gpo', 'defaults', 'defaults_overrides', 'units', 'notes')) {
                $entry.ContainsKey($field) | Should -BeTrue -Because "entry $($entry['path'])\$($entry['value']) must expose '$field'"
            }
            $entry['defaults'] | Should -BeOfType [hashtable]
        }
        # TimeJumpAuditOffset has no GPO twin -> normalized to $null.
        $e = Get-DbEntry -Keys @($db['Keys']) -PathSuffix '\W32Time\Config' -ValueName 'TimeJumpAuditOffset'
        $e['gpo'] | Should -Be $null
        # AnnounceFlags has no overrides -> normalized to $null; UtilizeSslTimeData has an array.
        $af = Get-DbEntry -Keys @($db['Keys']) -PathSuffix '\W32Time\Config' -ValueName 'AnnounceFlags'
        $af['defaults_overrides'] | Should -Be $null
        $ssl = Get-DbEntry -Keys @($db['Keys']) -PathSuffix '\W32Time\Config' -ValueName 'UtilizeSslTimeData'
        , $ssl['defaults_overrides'] | Should -BeOfType [array]
    }

    It 'throws on schema_version other than 2' {
        $badPath = Join-Path $TestDrive 'schema1.yaml'
        $yaml = @'
schema_version: 1
verified: test
keys:
  - path: SYSTEM\Test
    value: V
    type: REG_DWORD
    class: config
    compare: exact
    defaults: { dc: 1, member: 1, standalone: 1 }
'@
        Set-Content -LiteralPath $badPath -Value $yaml -Encoding UTF8
        { Get-W32TimeDatabase -Path $badPath } | Should -Throw '*schema_version*'
    }

    It 'throws listing offenders when compare is not a known enum value' {
        $badPath = Join-Path $TestDrive 'badcompare.yaml'
        $yaml = @'
schema_version: 2
verified: test
keys:
  - path: SYSTEM\Test
    value: GoodValue
    type: REG_DWORD
    class: config
    compare: exact
    defaults: { dc: 1, member: 1, standalone: 1 }
  - path: SYSTEM\Test
    value: BadValue
    type: REG_DWORD
    class: config
    compare: sometimes
    defaults: { dc: 1, member: 1, standalone: 1 }
'@
        Set-Content -LiteralPath $badPath -Value $yaml -Encoding UTF8
        { Get-W32TimeDatabase -Path $badPath } | Should -Throw "*BadValue*unknown compare value 'sometimes'*"
    }

    It 'throws listing offenders when a required field is missing' {
        $badPath = Join-Path $TestDrive 'missingfield.yaml'
        $yaml = @'
schema_version: 2
verified: test
keys:
  - path: SYSTEM\Test
    value: NoType
    class: config
    compare: exact
    defaults: { dc: 1, member: 1, standalone: 1 }
'@
        Set-Content -LiteralPath $badPath -Value $yaml -Encoding UTF8
        { Get-W32TimeDatabase -Path $badPath } | Should -Throw "*NoType*missing required field 'type'*"
    }

    It 'propagates parser errors for syntactically broken YAML' {
        $badPath = Join-Path $TestDrive 'brokensyntax.yaml'
        Set-Content -LiteralPath $badPath -Value "schema_version: 2`nkeys: [broken" -Encoding UTF8
        { Get-W32TimeDatabase -Path $badPath } | Should -Throw '*flow sequences*'
    }
}

Describe 'Database integrity (DESIGN section 11)' {

    BeforeAll {
        $script:Db = Get-W32TimeDatabase
        $script:ValidTypes = @('REG_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_MULTI_SZ', 'REG_EXPAND_SZ', 'REG_BINARY')
        $script:ValidClasses = @('config', 'internal', 'diagnostic')
        $script:ValidCompare = @('exact', 'pdce-exempt', 'ignore')
    }

    It 'every entry uses known type/class/compare enum values and a W32Time service path' {
        $violations = @()
        foreach ($e in @($script:Db['Keys'])) {
            $label = "$($e['path'])\$($e['value'])"
            if ($script:ValidTypes -notcontains [string]$e['type']) { $violations += "$label : type '$($e['type'])'" }
            if ($script:ValidClasses -notcontains [string]$e['class']) { $violations += "$label : class '$($e['class'])'" }
            if ($script:ValidCompare -notcontains [string]$e['compare']) { $violations += "$label : compare '$($e['compare'])'" }
            if (-not ([string]$e['path']).StartsWith('SYSTEM\CurrentControlSet\Services\W32Time', [System.StringComparison]::OrdinalIgnoreCase)) {
                $violations += "$label : path outside the W32Time service key"
            }
        }
        $violations | Should -BeNullOrEmpty
    }

    It 'path\value pairs are unique (OrdinalIgnoreCase)' {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $dupes = @()
        foreach ($e in @($script:Db['Keys'])) {
            $id = "$($e['path'])\$($e['value'])"
            if (-not $seen.Add($id)) { $dupes += $id }
        }
        $dupes | Should -BeNullOrEmpty
    }

    It 'every gpo block carries policy, policy_path under SOFTWARE\Policies\Microsoft\W32Time, and gpo_default' {
        $violations = @()
        foreach ($e in @($script:Db['Keys'])) {
            if ($null -eq $e['gpo']) { continue }
            $label = "$($e['path'])\$($e['value'])"
            $gpo = $e['gpo']
            if (-not $gpo.ContainsKey('policy') -or [string]::IsNullOrEmpty([string]$gpo['policy'])) { $violations += "$label : gpo without policy" }
            if (-not $gpo.ContainsKey('policy_path') -or
                -not ([string]$gpo['policy_path']).StartsWith('SOFTWARE\Policies\Microsoft\W32Time', [System.StringComparison]::OrdinalIgnoreCase)) {
                $violations += "$label : gpo policy_path '$($gpo['policy_path'])'"
            }
            if (-not $gpo.ContainsKey('gpo_default')) { $violations += "$label : gpo without gpo_default" }
        }
        $violations | Should -BeNullOrEmpty
    }

    It 'every defaults block defines the dc, member and standalone roles' {
        $violations = @()
        foreach ($e in @($script:Db['Keys'])) {
            $label = "$($e['path'])\$($e['value'])"
            foreach ($role in @('dc', 'member', 'standalone')) {
                if (-not $e['defaults'].ContainsKey($role)) { $violations += "$label : defaults missing role '$role'" }
            }
        }
        $violations | Should -BeNullOrEmpty
    }

    It 'defaults_overrides entries are machine-readable: value plus min_build/max_build bounds, valid role filter' {
        $violations = @()
        foreach ($e in @($script:Db['Keys'])) {
            if ($null -eq $e['defaults_overrides']) { continue }
            $label = "$($e['path'])\$($e['value'])"
            foreach ($ov in @($e['defaults_overrides'])) {
                if ($ov -isnot [hashtable]) { $violations += "$label : override is not a mapping"; continue }
                if (-not $ov.ContainsKey('value')) { $violations += "$label : override without value" }
                if (-not ($ov.ContainsKey('min_build') -or $ov.ContainsKey('max_build'))) { $violations += "$label : override without build bounds" }
                if ($ov.ContainsKey('role') -and (@('dc', 'member', 'standalone') -notcontains [string]$ov['role'])) {
                    $violations += "$label : override with unknown role '$($ov['role'])'"
                }
            }
        }
        $violations | Should -BeNullOrEmpty
    }

    It 'numeric defaults are stored non-negative (hex parsed unsigned)' {
        $violations = @()
        foreach ($e in @($script:Db['Keys'])) {
            foreach ($role in @($e['defaults'].Keys)) {
                $v = $e['defaults'][$role]
                if ($null -eq $v) { continue }
                if (($v -is [int] -or $v -is [long]) -and $v -lt 0) {
                    $violations += "$($e['path'])\$($e['value']) : $role = $v"
                }
            }
        }
        $violations | Should -BeNullOrEmpty
    }

    It 'internal subtrees list the three known runtime-state keys with notes' {
        $paths = @()
        foreach ($s in @($script:Db['InternalSubtrees'])) {
            $s.ContainsKey('path') | Should -BeTrue
            $s.ContainsKey('notes') | Should -BeTrue
            $paths += [string]$s['path']
        }
        ($paths | Sort-Object) | Should -Be @(
            'SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits',
            'SYSTEM\CurrentControlSet\Services\W32Time\Security',
            'SYSTEM\CurrentControlSet\Services\W32Time\TriggerInfo'
        )
    }
}

Describe 'Resolve-W32TimeExpectation' {

    BeforeAll {
        $script:Db = Get-W32TimeDatabase
        $script:Ssl = Get-DbEntry -Keys @($script:Db['Keys']) -PathSuffix '\W32Time\Config' -ValueName 'UtilizeSslTimeData'
        $script:Announce = Get-DbEntry -Keys @($script:Db['Keys']) -PathSuffix '\W32Time\Config' -ValueName 'AnnounceFlags'
        $script:TypeEntry = Get-DbEntry -Keys @($script:Db['Keys']) -PathSuffix '\W32Time\Parameters' -ValueName 'Type'
        $script:NtpServerEntry = Get-DbEntry -Keys @($script:Db['Keys']) -PathSuffix '\W32Time\Parameters' -ValueName 'NtpServer'
    }

    Context 'OS-conditional defaults (UtilizeSslTimeData)' {
        It 'build 26100 (Server 2025) resolves to 0' {
            $r = Resolve-W32TimeExpectation -Entry $script:Ssl -Role Dc -OsBuild 26100
            $r['Expected'] | Should -Be 0
            $r['Source'] | Should -Be 'MSDefault'
            $r['OsConditional'] | Should -BeTrue
        }

        It 'builds above the min_build threshold still resolve to 0 (open-ended range)' {
            $r = Resolve-W32TimeExpectation -Entry $script:Ssl -Role Dc -OsBuild 27842
            $r['Expected'] | Should -Be 0
        }

        It 'build 20348 (Server 2022) resolves to the base default 1' {
            $r = Resolve-W32TimeExpectation -Entry $script:Ssl -Role Dc -OsBuild 20348
            $r['Expected'] | Should -Be 1
            $r['OsConditional'] | Should -BeTrue
        }

        It 'unknown build (0) resolves to the base default and flags OsConditional' {
            $r = Resolve-W32TimeExpectation -Entry $script:Ssl -Role Dc -OsBuild 0
            $r['Expected'] | Should -Be 1
            $r['OsConditional'] | Should -BeTrue
        }

        It 'applies overrides to RootPdce as well' {
            $r = Resolve-W32TimeExpectation -Entry $script:Ssl -Role RootPdce -OsBuild 26100
            $r['Expected'] | Should -Be 0
        }
    }

    Context 'role resolution' {
        It 'AnnounceFlags: RootPdce resolves to the pdce conventional value 5' {
            $r = Resolve-W32TimeExpectation -Entry $script:Announce -Role RootPdce -OsBuild 20348
            $r['Expected'] | Should -Be 5
            $r['OsConditional'] | Should -BeFalse
        }

        It 'AnnounceFlags: Dc resolves to 10' {
            $r = Resolve-W32TimeExpectation -Entry $script:Announce -Role Dc -OsBuild 20348
            $r['Expected'] | Should -Be 10
        }

        It 'Type: RootPdce -> NTP, Dc -> NT5DS' {
            (Resolve-W32TimeExpectation -Entry $script:TypeEntry -Role RootPdce -OsBuild 0)['Expected'] | Should -Be 'NTP'
            (Resolve-W32TimeExpectation -Entry $script:TypeEntry -Role Dc -OsBuild 0)['Expected'] | Should -Be 'NT5DS'
        }

        It 'NtpServer: RootPdce pdce default is explicitly null (admin-defined peer list)' {
            $r = Resolve-W32TimeExpectation -Entry $script:NtpServerEntry -Role RootPdce -OsBuild 0
            $r['Expected'] | Should -Be $null
        }

        It 'falls back to the member default when the entry has no dc key' {
            $entry = @{ path = 'X'; value = 'V'; defaults = @{ member = 5; standalone = 6 }; defaults_overrides = $null }
            $r = Resolve-W32TimeExpectation -Entry $entry -Role Dc -OsBuild 0
            $r['Expected'] | Should -Be 5
        }

        It 'RootPdce without a pdce key falls back to the dc default' {
            $entry = @{ path = 'X'; value = 'V'; defaults = @{ dc = 7; member = 5; standalone = 6 }; defaults_overrides = $null }
            $r = Resolve-W32TimeExpectation -Entry $entry -Role RootPdce -OsBuild 0
            $r['Expected'] | Should -Be 7
        }
    }

    Context 'override matching rules (synthetic entry)' {
        BeforeAll {
            $script:Synthetic = @{
                path               = 'SYSTEM\Test'
                value              = 'V'
                defaults           = @{ dc = 1; member = 2; standalone = 3 }
                defaults_overrides = @(
                    @{ min_build = 100; max_build = 200; role = 'member'; value = 9 },
                    @{ min_build = 100; max_build = 200; role = 'dc'; value = 7 },
                    @{ min_build = 100; value = 8 }
                )
            }
        }

        It 'skips overrides whose role filter does not cover DC roles' {
            $r = Resolve-W32TimeExpectation -Entry $script:Synthetic -Role Dc -OsBuild 150
            $r['Expected'] | Should -Be 7
        }

        It "role filter 'dc' also matches RootPdce" {
            $r = Resolve-W32TimeExpectation -Entry $script:Synthetic -Role RootPdce -OsBuild 150
            $r['Expected'] | Should -Be 7
        }

        It 'min_build and max_build are inclusive' {
            (Resolve-W32TimeExpectation -Entry $script:Synthetic -Role Dc -OsBuild 100)['Expected'] | Should -Be 7
            (Resolve-W32TimeExpectation -Entry $script:Synthetic -Role Dc -OsBuild 200)['Expected'] | Should -Be 7
        }

        It 'first matching override wins' {
            # Build 201: only the open-ended third override matches.
            (Resolve-W32TimeExpectation -Entry $script:Synthetic -Role Dc -OsBuild 201)['Expected'] | Should -Be 8
        }

        It 'below all ranges the base role default applies but OsConditional stays true' {
            $r = Resolve-W32TimeExpectation -Entry $script:Synthetic -Role Dc -OsBuild 99
            $r['Expected'] | Should -Be 1
            $r['OsConditional'] | Should -BeTrue
        }
    }
}
