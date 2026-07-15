# Pester 5 tests for the .reg v5 baseline parser/writer (DESIGN.md section 9).
# Dot-sources the Private functions directly; the module psm1 may not exist yet.

Set-StrictMode -Version Latest

BeforeAll {
    Set-StrictMode -Version Latest

    $privateDir = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Private'
    . (Join-Path -Path $privateDir -ChildPath 'ConvertFrom-RegFile.ps1')
    . (Join-Path -Path $privateDir -ChildPath 'ConvertTo-RegFile.ps1')

    # Deep-equality assertion for registry trees (paths, names, kinds, data incl. arrays).
    function Assert-RegTreeEqual {
        param([hashtable]$Expected, [hashtable]$Actual)

        @($Actual.Keys).Count | Should -Be @($Expected.Keys).Count -Because 'section count should match'
        foreach ($path in $Expected.Keys) {
            $Actual.ContainsKey($path) | Should -BeTrue -Because "section '$path' should be present"
            $expValues = $Expected[$path]
            $actValues = $Actual[$path]
            @($actValues.Keys).Count | Should -Be @($expValues.Keys).Count -Because "value count under '$path' should match"
            foreach ($name in $expValues.Keys) {
                $actValues.ContainsKey($name) | Should -BeTrue -Because "value '$path\$name' should be present"
                $exp = $expValues[$name]
                $act = $actValues[$name]
                $act['Kind'] | Should -Be $exp['Kind'] -Because "kind of '$path\$name' should match"
                $expData = $exp['Data']
                $actData = $act['Data']
                if ($expData -is [System.Array]) {
                    $expArr = @($expData)
                    $actArr = @($actData)
                    $actArr.Count | Should -Be $expArr.Count -Because "element count of '$path\$name' should match"
                    for ($i = 0; $i -lt $expArr.Count; $i++) {
                        $actArr[$i] | Should -Be $expArr[$i] -Because "element $i of '$path\$name' should match"
                    }
                }
                else {
                    $actData | Should -Be $expData -Because "data of '$path\$name' should match"
                }
            }
        }
    }

    # The string Zurich+u-umlaut+checkmark built from code points so this test file stays pure ASCII.
    $script:UnicodeSample = 'Z' + [char]0x00FC + 'rich' + [char]0x2713

    # One tree containing every supported kind, incl. the contract edge cases.
    function Get-SampleTree {
        $tree = @{
            'SYSTEM\CurrentControlSet\Services\W32Time\Config'                    = @{
                'MaxDword'      = @{ Kind = 'DWord'; Data = [uint32]4294967295 }          # 0xFFFFFFFF
                'AnnounceFlags' = @{ Kind = 'DWord'; Data = [uint32]10 }
                'MaxQword'      = @{ Kind = 'QWord'; Data = [uint64]::MaxValue }
                'City'          = @{ Kind = 'String'; Data = $script:UnicodeSample }
                'Escapes'       = @{ Kind = 'String'; Data = 'say "hi" C:\temp' }
                ''              = @{ Kind = 'String'; Data = 'default value data' }
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'                = @{
                'ServiceDll' = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\system32\w32time.dll' }
                'Blob'       = @{ Kind = 'Binary'; Data = [byte[]]@(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01) }
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'   = @{
                # Empty string in the MIDDLE is preserved by the hex(7) layout.
                'Peers'      = @{ Kind = 'MultiString'; Data = [string[]]@('time.contoso.com,0x8', '', 'time2.contoso.com,0x8') }
                'EmptyMulti' = @{ Kind = 'MultiString'; Data = [string[]]@() }
            }
        }
        return $tree
    }
}

Describe 'ConvertTo-RegFile output format' {
    BeforeEach {
        $script:OutPath = Join-Path -Path $TestDrive -ChildPath 'writer.reg'
        ConvertTo-RegFile -Tree (Get-SampleTree) -Path $script:OutPath -Provenance @{ Timestamp = '2026-07-11T00:00:00Z' }
        $script:OutBytes = [System.IO.File]::ReadAllBytes($script:OutPath)
        $script:OutText = [System.Text.Encoding]::Unicode.GetString($script:OutBytes, 2, $script:OutBytes.Length - 2)
        $script:OutLines = $script:OutText -split "`r`n"
    }

    It 'writes UTF-16LE with BOM' {
        $script:OutBytes[0] | Should -Be 0xFF
        $script:OutBytes[1] | Should -Be 0xFE
    }

    It 'uses CRLF line endings throughout' {
        # No bare LF or CR may remain once CRLF pairs are removed.
        ($script:OutText -replace "`r`n", '') | Should -Not -Match "[`r`n]"
    }

    It 'starts with the audit banner comment' {
        $script:OutLines[0] | Should -BeExactly '; WinTimeHealth AUDIT BASELINE - do not merge into a registry'
    }

    It 'emits provenance comments before the v5 header' {
        $script:OutLines[1] | Should -BeExactly '; Timestamp: 2026-07-11T00:00:00Z'
        $script:OutLines[2] | Should -BeExactly 'Windows Registry Editor Version 5.00'
    }

    It 'sorts sections OrdinalIgnoreCase by path' {
        $sectionLines = @($script:OutLines | Where-Object { $_ -match '^\[' })
        $sorted = @($sectionLines | Sort-Object)
        for ($i = 0; $i -lt $sectionLines.Count; $i++) {
            $sectionLines[$i] | Should -Be $sorted[$i]
        }
        $sectionLines[0] | Should -BeExactly '[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config]'
    }

    It 'sorts value names within a section and puts the default value (@=) first' {
        $configIndex = [array]::IndexOf($script:OutLines, '[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config]')
        $configIndex | Should -BeGreaterThan 0
        $script:OutLines[$configIndex + 1] | Should -BeExactly '@="default value data"'
        $script:OutLines[$configIndex + 2] | Should -BeExactly '"AnnounceFlags"=dword:0000000a'
    }

    It 'emits DWord as lowercase 8-digit hex' {
        $script:OutText | Should -Match '"MaxDword"=dword:ffffffff'
    }

    It 'escapes backslash and double quote in strings' {
        $script:OutText.Contains('"Escapes"="say \"hi\" C:\\temp"') | Should -BeTrue
    }

    It 'emits QWord as hex(b) with 8 little-endian bytes' {
        $script:OutText | Should -Match '"MaxQword"=hex\(b\):ff,ff,ff,ff,ff,ff,ff,ff'
    }

    It 'emits an empty MultiString as a lone NUL terminator' {
        $script:OutText | Should -Match '"EmptyMulti"=hex\(7\):00,00'
    }

    It 'rejects kinds that have no mergeable v5 layout' {
        $badTree = @{ 'SOFTWARE\Test' = @{ 'Raw' = @{ Kind = 'Unknown'; Data = [byte[]]@(1, 2) } } }
        { ConvertTo-RegFile -Tree $badTree -Path (Join-Path -Path $TestDrive -ChildPath 'bad.reg') } |
            Should -Throw "*kind 'Unknown'*"
    }

    It 'wraps hex byte lists with backslash continuations at ~76 columns, two-space indent' {
        $bytes = New-Object 'byte[]' 200
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [byte]($i % 256) }
        $tree = @{ 'SOFTWARE\Test' = @{ 'Big' = @{ Kind = 'Binary'; Data = $bytes } } }
        $path = Join-Path -Path $TestDrive -ChildPath 'wrap.reg'
        ConvertTo-RegFile -Tree $tree -Path $path

        $raw = [System.IO.File]::ReadAllBytes($path)
        $lines = ([System.Text.Encoding]::Unicode.GetString($raw, 2, $raw.Length - 2)) -split "`r`n"
        $hexLines = @($lines | Where-Object { $_ -match '^("Big"=hex:|  [0-9a-f])' })
        $hexLines.Count | Should -BeGreaterThan 2
        foreach ($line in $hexLines) {
            $line.Length | Should -BeLessOrEqual 78 -Because 'wrapped hex lines stay near 76 columns'
        }
        # Every hex line except the last continues with a trailing backslash.
        for ($i = 0; $i -lt $hexLines.Count - 1; $i++) {
            $hexLines[$i] | Should -Match ',\\$'
        }
        # Continuation lines are indented exactly two spaces.
        for ($i = 1; $i -lt $hexLines.Count; $i++) {
            $hexLines[$i] | Should -Match '^  [0-9a-f]{2},'
        }
        # And the wrapped payload still round-trips byte for byte.
        $reparsed = ConvertFrom-RegFile -Path $path
        $roundBytes = @($reparsed.Tree['SOFTWARE\Test']['Big'].Data)
        $roundBytes.Count | Should -Be 200
        for ($i = 0; $i -lt 200; $i++) { $roundBytes[$i] | Should -Be $bytes[$i] }
    }
}

Describe 'write -> parse roundtrip' {
    It 'round-trips a tree containing every supported kind, deep-equal' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'roundtrip.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $result = ConvertFrom-RegFile -Path $path
        Assert-RegTreeEqual -Expected $tree -Actual $result.Tree
    }

    It 'normalizes DWord to [uint32] and QWord to [uint64] after the roundtrip' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'types.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $config = (ConvertFrom-RegFile -Path $path).Tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']
        $config['MaxDword'].Data | Should -BeOfType [uint32]
        $config['MaxDword'].Data | Should -Be ([uint32]4294967295)
        $config['MaxQword'].Data | Should -BeOfType [uint64]
        $config['MaxQword'].Data | Should -Be ([uint64]::MaxValue)
    }

    It 'preserves the unicode string sample exactly' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'unicode.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $parsed.Tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['City'].Data |
            Should -BeExactly $script:UnicodeSample
    }

    It 'uses OrdinalIgnoreCase semantics for parsed tree paths and value names' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'case.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $parsed.Tree.ContainsKey('system\currentcontrolset\services\w32time\config') | Should -BeTrue
        $parsed.Tree['SYSTEM\CurrentControlSet\Services\W32Time\Config'].ContainsKey('announceflags') | Should -BeTrue
    }

    It 'preserves empty strings in the MIDDLE of a MultiString' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'multimid.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $peers = @($parsed.Tree['SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient']['Peers'].Data)
        $peers.Count | Should -Be 3
        $peers[1] | Should -BeExactly ''
    }

    It 'drops TRAILING empty MultiString elements (indistinguishable from the terminator - documented)' {
        $tree = @{ 'SOFTWARE\Test' = @{ 'M' = @{ Kind = 'MultiString'; Data = [string[]]@('a', '') } } }
        $path = Join-Path -Path $TestDrive -ChildPath 'multitrail.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $m = @($parsed.Tree['SOFTWARE\Test']['M'].Data)
        $m.Count | Should -Be 1
        $m[0] | Should -BeExactly 'a'
    }

    It 'round-trips an empty MultiString to an empty array' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'multiempty.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $m = $parsed.Tree['SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient']['EmptyMulti']
        $m.Kind | Should -Be 'MultiString'
        @($m.Data).Count | Should -Be 0
    }

    It 'round-trips an ExpandString with environment variables' {
        $tree = Get-SampleTree
        $path = Join-Path -Path $TestDrive -ChildPath 'expand.reg'
        ConvertTo-RegFile -Tree $tree -Path $path
        $parsed = ConvertFrom-RegFile -Path $path
        $svc = $parsed.Tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['ServiceDll']
        $svc.Kind | Should -Be 'ExpandString'
        $svc.Data | Should -BeExactly '%SystemRoot%\system32\w32time.dll'
    }
}

Describe 'provenance roundtrip' {
    It 'round-trips all known provenance keys (values as strings)' {
        $prov = @{
            SourceDCs     = @('dc1.contoso.com', 'dc2.contoso.com')
            Timestamp     = '2026-07-11T01:02:03Z'
            OsBuilds      = @(20348, 26100)
            ModuleVersion = '1.0.0'
            SchemaVersion = 2
            Pdce          = 'pdc.contoso.com'
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'prov.reg'
        ConvertTo-RegFile -Tree (Get-SampleTree) -Path $path -Provenance $prov
        $parsed = (ConvertFrom-RegFile -Path $path).Provenance
        $parsed['SourceDCs'] | Should -BeExactly 'dc1.contoso.com, dc2.contoso.com'
        $parsed['Timestamp'] | Should -BeExactly '2026-07-11T01:02:03Z'
        $parsed['OsBuilds'] | Should -BeExactly '20348, 26100'
        $parsed['ModuleVersion'] | Should -BeExactly '1.0.0'
        $parsed['SchemaVersion'] | Should -BeExactly '2'
        $parsed['Pdce'] | Should -BeExactly 'pdc.contoso.com'
    }

    It 'reports missing provenance keys as $null and echoes all comment lines in Raw' {
        $path = Join-Path -Path $TestDrive -ChildPath 'provpartial.reg'
        ConvertTo-RegFile -Tree (Get-SampleTree) -Path $path -Provenance @{ Timestamp = '2026-07-11T00:00:00Z' }
        $parsed = (ConvertFrom-RegFile -Path $path).Provenance
        $parsed['Timestamp'] | Should -BeExactly '2026-07-11T00:00:00Z'
        $parsed['SourceDCs'] | Should -BeNullOrEmpty
        $parsed['OsBuilds'] | Should -BeNullOrEmpty
        $parsed['ModuleVersion'] | Should -BeNullOrEmpty
        $parsed['SchemaVersion'] | Should -BeNullOrEmpty
        $parsed['Pdce'] | Should -BeNullOrEmpty
        @($parsed['Raw']).Count | Should -Be 2
        @($parsed['Raw'])[0] | Should -BeExactly '; WinTimeHealth AUDIT BASELINE - do not merge into a registry'
    }
}

Describe 'ConvertFrom-RegFile with a regedit-style fixture' {
    BeforeAll {
        # Hand-written fixture mimicking a real regedit export: header on the first line,
        # CRLF endings, backslash continuations breaking MID byte-pair (the '6f,' / '00,'
        # split), two-space continuation indent, trailing spaces on some lines, @= default.
        $fixtureLines = @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest\Sub]'
            '@="Default data"   '
            '"Quoted"="say \"hi\" C:\\temp"'
            '"Start"=dword:00000002  '
            '"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\'
            '  00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,00,\  '
            '  00'
            '"Sources"=hex(7):61,00,00,00,62,00,63,00,00,00,00,00'
            '"Qw"=hex(b):ff,ff,ff,ff,ff,ff,ff,ff'
            '"Blob"=hex:de,ad,be,ef'
            ''
            '[HKLM\SOFTWARE\WinTimeTest\Short]'
            '"ViaHklmPrefix"=dword:00000001'
            ''
        )
        $script:FixturePath = Join-Path -Path $TestDrive -ChildPath 'fixture.reg'
        $enc = New-Object System.Text.UnicodeEncoding($false, $true)
        [System.IO.File]::WriteAllText($script:FixturePath, ($fixtureLines -join "`r`n"), $enc)
        $script:Fixture = ConvertFrom-RegFile -Path $script:FixturePath
    }

    It 'parses both sections, normalizing HKEY_LOCAL_MACHINE\ and HKLM\ prefixes away' {
        @($script:Fixture.Tree.Keys).Count | Should -Be 2
        $script:Fixture.Tree.ContainsKey('SOFTWARE\WinTimeTest\Sub') | Should -BeTrue
        $script:Fixture.Tree.ContainsKey('SOFTWARE\WinTimeTest\Short') | Should -BeTrue
        $script:Fixture.Tree['SOFTWARE\WinTimeTest\Short']['ViaHklmPrefix'].Data | Should -Be ([uint32]1)
    }

    It 'stores the @= default value under the empty-string name' {
        $sub = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']
        $sub.ContainsKey('') | Should -BeTrue
        $sub[''].Kind | Should -Be 'String'
        $sub[''].Data | Should -BeExactly 'Default data'
    }

    It 'unescapes \" and \\ in quoted strings' {
        $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['Quoted'].Data | Should -BeExactly 'say "hi" C:\temp'
    }

    It 'parses dword despite trailing spaces on the line' {
        $start = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['Start']
        $start.Kind | Should -Be 'DWord'
        $start.Data | Should -Be ([uint32]2)
    }

    It 'reassembles hex(2) continuations broken mid byte-pair into the ExpandString' {
        $img = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['ImagePath']
        $img.Kind | Should -Be 'ExpandString'
        $img.Data | Should -BeExactly '%SystemRoot%\system32'
    }

    It 'parses hex(7) into a string array' {
        $src = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['Sources']
        $src.Kind | Should -Be 'MultiString'
        $arr = @($src.Data)
        $arr.Count | Should -Be 2
        $arr[0] | Should -BeExactly 'a'
        $arr[1] | Should -BeExactly 'bc'
    }

    It 'parses hex(b) into [uint64]' {
        $qw = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['Qw']
        $qw.Kind | Should -Be 'QWord'
        $qw.Data | Should -BeOfType [uint64]
        $qw.Data | Should -Be ([uint64]::MaxValue)
    }

    It 'parses hex: into bytes' {
        $blob = $script:Fixture.Tree['SOFTWARE\WinTimeTest\Sub']['Blob']
        $blob.Kind | Should -Be 'Binary'
        $arr = @($blob.Data)
        $arr.Count | Should -Be 4
        $arr[0] | Should -Be 0xDE
        $arr[3] | Should -Be 0xEF
    }

    It 'captures generic hex(X) as raw bytes with Kind Unknown' {
        $lines = @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
            '"Odd"=hex(4):01,02,03,04'
            ''
        )
        $p = Join-Path -Path $TestDrive -ChildPath 'generic.reg'
        $enc = New-Object System.Text.UnicodeEncoding($false, $true)
        [System.IO.File]::WriteAllText($p, ($lines -join "`r`n"), $enc)
        $odd = (ConvertFrom-RegFile -Path $p).Tree['SOFTWARE\WinTimeTest']['Odd']
        $odd.Kind | Should -Be 'Unknown'
        @($odd.Data).Count | Should -Be 4
    }
}

Describe 'ConvertFrom-RegFile rejections' {
    BeforeAll {
        # Writes CRLF-joined lines as UTF-16LE+BOM and returns the path.
        function Write-RegFixture {
            param([string]$Name, [string[]]$Lines)
            $p = Join-Path -Path $TestDrive -ChildPath $Name
            $enc = New-Object System.Text.UnicodeEncoding($false, $true)
            [System.IO.File]::WriteAllText($p, ($Lines -join "`r`n"), $enc)
            return $p
        }
    }

    It 'rejects REGEDIT4 exports with a re-export-as-v5 error' {
        $p = Write-RegFixture -Name 'v4.reg' -Lines @(
            'REGEDIT4'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
            '"A"=dword:00000001'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*Re-export*Version 5.00*'
    }

    It 'rejects key deletion syntax [-...]' {
        $p = Write-RegFixture -Name 'delkey.reg' -Lines @(
            'Windows Registry Editor Version 5.00'
            ''
            '[-HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*deletion*'
    }

    It 'rejects value deletion syntax "name"=-' {
        $p = Write-RegFixture -Name 'delval.reg' -Lines @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
            '"Gone"=-'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*deletion*'
    }

    It 'rejects sections outside HKEY_LOCAL_MACHINE' {
        $p = Write-RegFixture -Name 'hkcu.reg' -Lines @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_CURRENT_USER\SOFTWARE\WinTimeTest]'
            '"A"=dword:00000001'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*HKEY_LOCAL_MACHINE*'
    }

    It 'rejects files without the v5 header' {
        $p = Write-RegFixture -Name 'noheader.reg' -Lines @(
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
            '"A"=dword:00000001'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*Windows Registry Editor Version 5.00*'
    }

    It 'rejects value lines outside any section' {
        $p = Write-RegFixture -Name 'nosection.reg' -Lines @(
            'Windows Registry Editor Version 5.00'
            ''
            '"A"=dword:00000001'
        )
        { ConvertFrom-RegFile -Path $p } | Should -Throw '*outside*'
    }

    It 'rejects a missing file with a clear error' {
        { ConvertFrom-RegFile -Path (Join-Path -Path $TestDrive -ChildPath 'nope.reg') } |
            Should -Throw '*not found*'
    }
}

Describe 'ConvertFrom-RegFile BOM sniffing' {
    BeforeAll {
        $script:BomLines = @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\WinTimeTest]'
            '"City"="Z' + [char]0x00FC + 'rich"'
            '"Flag"=dword:0000000a'
            ''
        )
    }

    It 'reads UTF-8 with BOM' {
        $p = Join-Path -Path $TestDrive -ChildPath 'utf8bom.reg'
        $enc = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($p, ($script:BomLines -join "`r`n"), $enc)
        $tree = (ConvertFrom-RegFile -Path $p).Tree
        $tree['SOFTWARE\WinTimeTest']['City'].Data | Should -BeExactly ('Z' + [char]0x00FC + 'rich')
        $tree['SOFTWARE\WinTimeTest']['Flag'].Data | Should -Be ([uint32]10)
    }

    It 'reads UTF-16LE with BOM' {
        $p = Join-Path -Path $TestDrive -ChildPath 'utf16.reg'
        $enc = New-Object System.Text.UnicodeEncoding($false, $true)
        [System.IO.File]::WriteAllText($p, ($script:BomLines -join "`r`n"), $enc)
        $tree = (ConvertFrom-RegFile -Path $p).Tree
        $tree['SOFTWARE\WinTimeTest']['City'].Data | Should -BeExactly ('Z' + [char]0x00FC + 'rich')
    }

    It 'falls back to ANSI (Latin-1) when no BOM is present' {
        $p = Join-Path -Path $TestDrive -ChildPath 'ansi.reg'
        # Latin-1 bytes written directly; 0xFC is u-umlaut in Latin-1.
        $enc = [System.Text.Encoding]::GetEncoding(28591)
        [System.IO.File]::WriteAllBytes($p, $enc.GetBytes(($script:BomLines -join "`r`n")))
        $tree = (ConvertFrom-RegFile -Path $p).Tree
        $tree['SOFTWARE\WinTimeTest']['City'].Data | Should -BeExactly ('Z' + [char]0x00FC + 'rich')
        $tree['SOFTWARE\WinTimeTest']['Flag'].Data | Should -Be ([uint32]10)
    }
}
