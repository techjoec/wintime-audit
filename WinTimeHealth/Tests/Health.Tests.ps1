# Health.Tests.ps1 - Pester 5 tests for Invoke-NtpQuery (packet/timestamp/math
# helpers + loopback wire tests) and Invoke-WinTimeHealthEvaluation /
# Get-WinTimeRefidLoopFinding (check-catalog matrix, DESIGN section 8).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'test-fixture factories and the loopback fake-NTP-server helpers are pure in-memory/local-only builders, not system-state changes')]
param()

BeforeAll {
    Set-StrictMode -Version Latest

    $privateDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Private'
    . (Join-Path $privateDir 'Invoke-NtpQuery.ps1')
    . (Join-Path $privateDir 'Invoke-WinTimeHealthEvaluation.ps1')

    $script:NtpEpoch = [datetime]::new(1900, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

    # ---- fixture builders ---------------------------------------------------

    function New-HealthTarget {
        param(
            [string]$Fqdn = 'dc1.corp.contoso.com',
            [string]$Domain = 'corp.contoso.com',
            [bool]$IsRootPdce = $false,
            [bool]$IsRodc = $false,
            [int]$DomainDepth = 1
        )
        [pscustomobject]@{
            ComputerName = $Fqdn
            Domain       = $Domain
            Site         = 'HQ'
            IsRootPdce   = $IsRootPdce
            IsRodc       = $IsRodc
            DomainDepth  = $DomainDepth
        }
    }

    function New-RegVal {
        param([string]$Kind, $Data)
        @{ Kind = $Kind; Data = $Data }
    }

    function New-HealthyTree {
        # Healthy non-PDCe DC, physical Dell, build 20348 (Server 2022).
        @{
            'SYSTEM\CurrentControlSet\Services\W32Time'                             = @{
                # 3 (Manual, domain-join trigger-start) is the real out-of-box default on
                # every role including DCs - see the Start entry's notes in W32TimeKeys.yaml.
                Start      = New-RegVal 'DWord' ([uint32]3)
                ObjectName = New-RegVal 'String' 'NT AUTHORITY\LocalService'
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\Config'                      = @{
                MaxPollInterval     = New-RegVal 'DWord' ([uint32]10)
                ClockHoldoverPeriod = New-RegVal 'DWord' ([uint32]7800)
                AnnounceFlags       = New-RegVal 'DWord' ([uint32]10)
                UtilizeSslTimeData  = New-RegVal 'DWord' ([uint32]0)
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'                  = @{
                Type = New-RegVal 'String' 'NT5DS'
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'     = @{
                Enabled = New-RegVal 'DWord' ([uint32]1)
            }
            'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'     = @{
                Enabled = New-RegVal 'DWord' ([uint32]1)
            }
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion'                          = @{
                CurrentBuildNumber = New-RegVal 'String' '20348'
            }
            'SYSTEM\CurrentControlSet\Control\SystemInformation'                    = @{
                SystemManufacturer = New-RegVal 'String' 'Dell Inc.'
                SystemProductName  = New-RegVal 'String' 'PowerEdge R750'
            }
        }
    }

    function New-NtpResult {
        # Healthy stratum-3 reply; last sync 600 s ago; override via -With.
        param([hashtable]$With = @{})
        $now = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $r = @{
            Success            = $true
            Error              = $null
            Stratum            = 3
            LI                 = 0
            RefId              = [uint32]0x0A000001
            RefIdText          = '10.0.0.1'
            ReferenceTimestamp = $now.AddSeconds(-600)
            TransmitTimestamp  = $now
            OffsetSeconds      = 0.010
            DelaySeconds       = 0.020
            SamplesSent        = 4
            RepliesValid       = 4
            SamplesLostPct     = 0
        }
        foreach ($k in $With.Keys) { $r[$k] = $With[$k] }
        $r
    }

    function New-PdceNtpResult {
        param([hashtable]$With = @{})
        $r = New-NtpResult
        $r['Stratum'] = 2
        $r['OffsetSeconds'] = 0.005
        foreach ($k in $With.Keys) { $r[$k] = $With[$k] }
        $r
    }

    function New-TestDatabase {
        # Minimal database mirroring the real W32TimeKeys.yaml fields the
        # health engine consumes (policy twin paths + dc defaults + overrides).
        $cfg = 'SYSTEM\CurrentControlSet\Services\W32Time\Config'
        $prm = 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        $ncl = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
        $nsv = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'
        $vmi = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider'
        $root = 'SYSTEM\CurrentControlSet\Services\W32Time'
        $polCfg = 'SOFTWARE\Policies\Microsoft\W32Time\Config'
        $polPrm = 'SOFTWARE\Policies\Microsoft\W32Time\Parameters'
        $polNcl = 'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
        @{
            SchemaVersion    = 2
            Verified         = '2026-07-11'
            Keys             = @(
                @{ path = $cfg; value = 'MaxPollInterval'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Global Configuration Settings'; policy_path = $polCfg; gpo_default = 10 }; defaults = @{ dc = 10; member = 15; standalone = 15 }; defaults_overrides = $null; compare = 'exact'; units = 'log2 seconds'; notes = '' }
                @{ path = $cfg; value = 'ClockHoldoverPeriod'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Global Configuration Settings'; policy_path = $polCfg; gpo_default = 7800 }; defaults = @{ dc = 7800; member = 7800; standalone = 7800 }; defaults_overrides = $null; compare = 'exact'; units = 'seconds'; notes = '' }
                @{ path = $cfg; value = 'AnnounceFlags'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Global Configuration Settings'; policy_path = $polCfg; gpo_default = 10 }; defaults = @{ dc = 10; member = 10; standalone = 10; pdce = 5 }; defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = '' }
                @{ path = $cfg; value = 'UtilizeSslTimeData'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Global Configuration Settings'; policy_path = $polCfg; gpo_default = 1 }; defaults = @{ dc = 1; member = 1; standalone = 1 }; defaults_overrides = @(@{ min_build = 26100; value = 0 }); compare = 'exact'; units = $null; notes = '' }
                @{ path = $nsv; value = 'RequireSecureTimeSyncRequests'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Global Configuration Settings'; policy_path = $polCfg; gpo_default = 0 }; defaults = @{ dc = 0; member = 0; standalone = 0 }; defaults_overrides = $null; compare = 'exact'; units = $null; notes = '' }
                @{ path = $prm; value = 'Type'; type = 'REG_SZ'; class = 'config'; gpo = @{ policy = 'Time Providers\Configure Windows NTP Client'; policy_path = $polPrm; gpo_default = 'NT5DS' }; defaults = @{ dc = 'NT5DS'; member = 'NT5DS'; standalone = 'NTP'; pdce = 'NTP' }; defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = '' }
                @{ path = $prm; value = 'NtpServer'; type = 'REG_SZ'; class = 'config'; gpo = @{ policy = 'Time Providers\Configure Windows NTP Client'; policy_path = $polPrm; gpo_default = 'time.windows.com,0x9' }; defaults = @{ dc = $null; member = $null; standalone = 'time.windows.com,0x1'; pdce = $null }; defaults_overrides = $null; compare = 'pdce-exempt'; units = $null; notes = '' }
                @{ path = $ncl; value = 'Enabled'; type = 'REG_DWORD'; class = 'config'; gpo = @{ policy = 'Time Providers\Enable Windows NTP Client'; policy_path = $polNcl; gpo_default = 1 }; defaults = @{ dc = 1; member = 1; standalone = 1 }; defaults_overrides = $null; compare = 'exact'; units = $null; notes = '' }
                @{ path = $vmi; value = 'Enabled'; type = 'REG_DWORD'; class = 'config'; gpo = $null; defaults = @{ dc = 1; member = 1; standalone = 1 }; defaults_overrides = $null; compare = 'exact'; units = $null; notes = '' }
                @{ path = $root; value = 'Start'; type = 'REG_DWORD'; class = 'config'; gpo = $null; defaults = @{ dc = 3; member = 3; standalone = 3 }; defaults_overrides = $null; compare = 'exact'; units = $null; notes = '' }
            )
            InternalSubtrees = @(
                @{ path = 'SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits'; notes = '' }
            )
        }
    }

    function Invoke-Eval {
        # Thin wrapper with healthy defaults; every input overridable.
        param(
            $Target,
            $Tree,
            $ScmStatus,
            $Ntp,
            $PdceNtp,
            [string[]]$Checks = @(),
            [hashtable]$Thresholds = @{},
            $Database
        )
        if ($null -eq $Target) { $Target = New-HealthTarget }
        if ($null -eq $Database) { $Database = New-TestDatabase }
        @(Invoke-WinTimeHealthEvaluation -Target $Target -Tree $Tree -ScmStatus $ScmStatus -Ntp $Ntp -PdceNtp $PdceNtp -Checks $Checks -Thresholds $Thresholds -Database $Database -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z')
    }

    function Invoke-HealthyEval {
        param([string[]]$Checks = @(), [hashtable]$Thresholds = @{})
        Invoke-Eval -Target (New-HealthTarget) -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult) -Checks $Checks -Thresholds $Thresholds
    }

    function Get-CheckRecord {
        param($Records, [string]$Check)
        @($Records | Where-Object { $_.Check -eq $Check })[0]
    }

    function ConvertTo-RefIdRaw {
        # dotted quad -> big-endian raw uint32 (as carried in NTP replies)
        param([string]$Dotted)
        $parts = $Dotted.Split('.')
        return [uint32]((([uint32]$parts[0]) * 16777216) + (([uint32]$parts[1]) * 65536) + (([uint32]$parts[2]) * 256) + ([uint32]$parts[3]))
    }

    function New-LoopNode {
        param(
            [string]$Fqdn,
            [string[]]$Ips,
            [string]$RefIdDotted = $null,
            [int]$Stratum = 3,
            [bool]$Success = $true,
            [bool]$IsRootPdce = $false
        )
        $raw = $null
        $text = $null
        if (-not [string]::IsNullOrEmpty($RefIdDotted)) {
            $raw = ConvertTo-RefIdRaw -Dotted $RefIdDotted
            $text = $RefIdDotted
        }
        @{
            Ntp    = (New-NtpResult -With @{ Success = $Success; Stratum = $Stratum; RefId = $raw; RefIdText = $text })
            Target = (New-HealthTarget -Fqdn $Fqdn -IsRootPdce $IsRootPdce)
            Ips    = $Ips
        }
    }
}

Describe 'NTP packet builder (ConvertTo-WinTimeNtpPacket)' {
    It 'produces a 48-byte packet with first byte 0x1B (LI=0 VN=3 Mode=3)' {
        $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime ([datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc))
        $pkt['Bytes'].Length | Should -Be 48
        $pkt['Bytes'][0] | Should -Be 0x1B
    }

    It 'zeroes every field except the transmit timestamp' {
        $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime ([datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc))
        for ($i = 1; $i -lt 40; $i++) { $pkt['Bytes'][$i] | Should -Be 0 }
    }

    It 'carries T1 in bytes 40-47 and returns the exact same bytes as TransmitBytes' {
        $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime ([datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc))
        $t1Slice = $pkt['Bytes'][40..47]
        for ($i = 0; $i -lt 8; $i++) { $t1Slice[$i] | Should -Be $pkt['TransmitBytes'][$i] }
        # nonzero: a 2026 instant has seconds well above zero
        ($t1Slice -join ',') | Should -Not -Be '0,0,0,0,0,0,0,0'
    }

    It 'encodes T1 within 1 ms of the requested instant (randomized low fraction bits only)' {
        $when = [datetime]::new(2026, 7, 11, 12, 0, 0, 123, [System.DateTimeKind]::Utc)
        $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime $when
        $sec = ConvertFrom-WinTimeBigEndianUInt32 -Buffer $pkt['Bytes'] -Offset 40
        $frac = ConvertFrom-WinTimeBigEndianUInt32 -Buffer $pkt['Bytes'] -Offset 44
        $decoded = ConvertFrom-WinTimeNtpTimestamp -Seconds $sec -Fraction $frac
        [math]::Abs(($decoded - $when).TotalMilliseconds) | Should -BeLessThan 1
        # TransmitDateTime must match the wire bytes exactly
        $pkt['TransmitDateTime'] | Should -Be $decoded
    }

    It 'randomizes the low fraction bits between packets (nonce)' {
        $when = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $signatures = @{}
        for ($i = 0; $i -lt 5; $i++) {
            $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime $when
            $signatures[($pkt['TransmitBytes'] -join ',')] = $true
        }
        $signatures.Count | Should -BeGreaterThan 1
    }
}

Describe 'Big-endian conversion helpers' {
    It 'reads a known u32 vector (0x01020304)' {
        ConvertFrom-WinTimeBigEndianUInt32 -Buffer ([byte[]]@(1, 2, 3, 4)) -Offset 0 | Should -Be ([uint32]16909060)
    }

    It 'reads u32 max (0xFFFFFFFF) without sign trouble' {
        ConvertFrom-WinTimeBigEndianUInt32 -Buffer ([byte[]]@(255, 255, 255, 255)) -Offset 0 | Should -Be ([uint32]4294967295)
    }

    It 'honors the offset for u32' {
        ConvertFrom-WinTimeBigEndianUInt32 -Buffer ([byte[]]@(9, 9, 0, 0, 0, 7)) -Offset 2 | Should -Be ([uint32]7)
    }

    It 'reads a known u64 vector (2^32)' {
        ConvertFrom-WinTimeBigEndianUInt64 -Buffer ([byte[]]@(0, 0, 0, 1, 0, 0, 0, 0)) -Offset 0 | Should -Be ([uint64]4294967296)
    }

    It 'reads u64 max' {
        ConvertFrom-WinTimeBigEndianUInt64 -Buffer ([byte[]]@(255, 255, 255, 255, 255, 255, 255, 255)) -Offset 0 | Should -Be ([uint64]::MaxValue)
    }

    It 'throws on a buffer too short for the read' {
        { ConvertFrom-WinTimeBigEndianUInt32 -Buffer ([byte[]]@(1, 2, 3)) -Offset 0 } | Should -Throw
        { ConvertFrom-WinTimeBigEndianUInt64 -Buffer ([byte[]]@(1, 2, 3, 4, 5, 6, 7)) -Offset 0 } | Should -Throw
    }
}

Describe 'NTP timestamp conversion' {
    It 'maps the all-zero (unset) timestamp to 1900-01-01' {
        ConvertFrom-WinTimeNtpTimestamp -Seconds 0 -Fraction 0 | Should -Be $script:NtpEpoch
    }

    It 'maps 2208988800 to the Unix epoch (1970-01-01)' {
        ConvertFrom-WinTimeNtpTimestamp -Seconds 2208988800 -Fraction 0 |
            Should -Be ([datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc))
    }

    It 'maps 3976214400 to 2026-01-01 (known 2026 vector)' {
        # 1900..2026 = 46021 days (31 leap days; 1900 is not a leap year) * 86400
        ConvertFrom-WinTimeNtpTimestamp -Seconds 3976214400 -Fraction 0 |
            Should -Be ([datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc))
    }

    It 'treats MSB-clear seconds as era 1 (post-2036 pivot)' {
        # era 1 base is 2036-02-07T06:28:16Z
        ConvertFrom-WinTimeNtpTimestamp -Seconds 1 -Fraction 0 |
            Should -Be ([datetime]::new(2036, 2, 7, 6, 28, 17, [System.DateTimeKind]::Utc))
    }

    It 'converts the fraction field (0x80000000 = half a second)' {
        # Decimal literal: the 0x80000000 hex literal parses as a negative
        # Int32 in PowerShell and would throw on the [uint32] cast.
        $dt = ConvertFrom-WinTimeNtpTimestamp -Seconds 2208988800 -Fraction ([uint32]2147483648)
        ($dt - [datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).TotalSeconds | Should -Be 0.5
    }

    It 'converts 1970-01-01 back to seconds 2208988800' {
        $ts = ConvertTo-WinTimeNtpTimestamp -DateTime ([datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc))
        $ts['Seconds'] | Should -Be ([uint32]2208988800)
        $ts['Fraction'] | Should -Be ([uint32]0)
    }

    It 'round-trips a sub-second 2026 instant within one tick' {
        $when = [datetime]::new(2026, 7, 11, 23, 59, 59, [System.DateTimeKind]::Utc).AddTicks(1234567)
        $ts = ConvertTo-WinTimeNtpTimestamp -DateTime $when
        $back = ConvertFrom-WinTimeNtpTimestamp -Seconds $ts['Seconds'] -Fraction $ts['Fraction']
        [math]::Abs(($back - $when).Ticks) | Should -BeLessOrEqual 1
    }

    It 'round-trips a post-2036 (era 1) instant via the seconds wrap' {
        $when = [datetime]::new(2040, 6, 15, 8, 30, 0, [System.DateTimeKind]::Utc)
        $ts = ConvertTo-WinTimeNtpTimestamp -DateTime $when
        # on-wire seconds field must have wrapped below 2^31 (MSB clear)
        ($ts['Seconds'] -lt [uint32]2147483648) | Should -BeTrue
        ConvertFrom-WinTimeNtpTimestamp -Seconds $ts['Seconds'] -Fraction $ts['Fraction'] | Should -Be $when
    }
}

Describe 'Offset/delay sample math' {
    It 'recovers a +0.5 s offset and 0.2 s delay from synthetic T1..T4' {
        # server 0.5 s ahead, 0.1 s path each way, 0.05 s server processing
        $t0 = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $m = Get-WinTimeNtpSampleMath -T1 $t0 -T2 $t0.AddSeconds(0.6) -T3 $t0.AddSeconds(0.65) -T4 $t0.AddSeconds(0.25)
        $m['OffsetSeconds'] | Should -Be 0.5
        $m['DelaySeconds'] | Should -Be 0.2
    }

    It 'recovers a negative offset' {
        $t0 = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        # server 0.3 s behind, symmetric 0.05 s path, no processing time
        $m = Get-WinTimeNtpSampleMath -T1 $t0 -T2 $t0.AddSeconds(-0.25) -T3 $t0.AddSeconds(-0.25) -T4 $t0.AddSeconds(0.1)
        $m['OffsetSeconds'] | Should -Be (-0.3)
        $m['DelaySeconds'] | Should -Be 0.1
    }
}

Describe 'NTP reply parser (ConvertFrom-WinTimeNtpReply)' {
    BeforeAll {
        function New-ServerReply {
            # Crafts a mode-4 reply echoing $T1Bytes as originate; timestamps T2=T3=T1.
            param(
                [byte[]]$T1Bytes,
                [int]$Stratum = 2,
                [byte[]]$RefIdBytes = @(10, 0, 0, 5),
                [int]$FirstByte = 0x24,   # LI=0 VN=4 Mode=4
                [int]$Length = 48
            )
            $buf = New-Object byte[] $Length
            if ($Length -ge 1) { $buf[0] = [byte]$FirstByte }
            if ($Length -ge 2) { $buf[1] = [byte]$Stratum }
            if ($Length -ge 16) {
                for ($i = 0; $i -lt 4; $i++) { $buf[12 + $i] = [byte]$RefIdBytes[$i] }
            }
            if ($Length -ge 48) {
                for ($i = 0; $i -lt 8; $i++) {
                    $buf[24 + $i] = $T1Bytes[$i]   # originate
                    $buf[16 + $i] = $T1Bytes[$i]   # reference
                    $buf[32 + $i] = $T1Bytes[$i]   # T2
                    $buf[40 + $i] = $T1Bytes[$i]   # T3
                }
            }
            return $buf
        }
        $script:Pkt = ConvertTo-WinTimeNtpPacket -TransmitTime ([datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc))
    }

    It 'accepts a valid mode-4 v4 reply and extracts the fields' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes']
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeTrue
        $p['Mode'] | Should -Be 4
        $p['VersionNumber'] | Should -Be 4
        $p['LI'] | Should -Be 0
        $p['Stratum'] | Should -Be 2
        $p['RefIdDotted'] | Should -Be '10.0.0.5'
        $p['RefId'] | Should -Be ([uint32]0x0A000005)
        $p['RefIdAscii'] | Should -BeNullOrEmpty
        $p['TransmitTimestamp'] | Should -Be $script:Pkt['TransmitDateTime']
        $p['ReceiveTimestamp'] | Should -Be $script:Pkt['TransmitDateTime']
    }

    It 'accepts version 3 replies too' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -FirstByte 0x1C  # LI=0 VN=3 Mode=4
        (ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes'])['Valid'] | Should -BeTrue
    }

    It 'rejects a non-server mode' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -FirstByte 0x23  # mode 3
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeFalse
        $p['Reason'] | Should -Match 'mode'
    }

    It 'rejects an unexpected version' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -FirstByte 0x2C  # VN=5 Mode=4
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeFalse
        $p['Reason'] | Should -Match 'version'
    }

    It 'rejects an originate mismatch (stale/spoofed reply)' {
        $tampered = New-Object byte[] 8
        [System.Array]::Copy($script:Pkt['TransmitBytes'], $tampered, 8)
        $tampered[7] = [byte](($tampered[7] + 1) % 256)
        $reply = New-ServerReply -T1Bytes $tampered
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeFalse
        $p['Reason'] | Should -Match 'originate'
    }

    It 'rejects a short packet' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -Length 47
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeFalse
        $p['Reason'] | Should -Match 'short'
    }

    It 'recognizes a kiss-o''-death (stratum 0 + ASCII refid RATE)' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -Stratum 0 -RefIdBytes @(82, 65, 84, 69)  # 'RATE'
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeFalse
        $p['IsKissOfDeath'] | Should -BeTrue
        $p['KissCode'] | Should -Be 'RATE'
    }

    It 'extracts an ASCII refid at stratum 1 (GPS)' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -Stratum 1 -RefIdBytes @(71, 80, 83, 0)  # 'GPS\0'
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['Valid'] | Should -BeTrue
        $p['RefIdAscii'] | Should -Be 'GPS'
    }

    It 'treats stratum 0 with refid 0 as a structurally valid (non-KoD) reply' {
        $reply = New-ServerReply -T1Bytes $script:Pkt['TransmitBytes'] -Stratum 0 -RefIdBytes @(0, 0, 0, 0)
        $p = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $script:Pkt['TransmitBytes']
        $p['IsKissOfDeath'] | Should -BeFalse
        $p['Valid'] | Should -BeTrue
        $p['Stratum'] | Should -Be 0
    }
}

Describe 'Invoke-NtpQuery over loopback UDP' {
    BeforeAll {
        function Start-FakeNtpServer {
            # Background runspace: binds 127.0.0.1:<ephemeral>, answers $ReplyCount
            # requests with a stratum-2 mode-4 reply echoing T1 into originate/T2/T3.
            param([int]$ReplyCount = 4)
            $sync = [hashtable]::Synchronized(@{ Port = 0; Errors = @() })
            $ps = [powershell]::Create()
            $null = $ps.AddScript({
                param($sync, $replyCount)
                try {
                    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)
                    $server = New-Object System.Net.Sockets.UdpClient($ep)
                    $server.Client.ReceiveTimeout = 8000
                    $sync.Port = ([System.Net.IPEndPoint]$server.Client.LocalEndPoint).Port
                    for ($i = 0; $i -lt $replyCount; $i++) {
                        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                        $req = $server.Receive([ref]$remote)
                        $resp = New-Object byte[] 48
                        $resp[0] = 0x24   # LI=0 VN=4 Mode=4
                        $resp[1] = 2      # stratum 2
                        $resp[12] = 10; $resp[13] = 0; $resp[14] = 0; $resp[15] = 5
                        for ($b = 0; $b -lt 8; $b++) {
                            $resp[16 + $b] = $req[40 + $b]  # reference
                            $resp[24 + $b] = $req[40 + $b]  # originate echo
                            $resp[32 + $b] = $req[40 + $b]  # T2
                            $resp[40 + $b] = $req[40 + $b]  # T3
                        }
                        $null = $server.Send($resp, 48, $remote)
                    }
                    $server.Close()
                }
                catch {
                    $sync.Errors += $_.Exception.Message
                }
            }).AddArgument($sync).AddArgument($ReplyCount)
            $handle = $ps.BeginInvoke()
            $deadline = [datetime]::UtcNow.AddSeconds(5)
            while ($sync.Port -eq 0 -and [datetime]::UtcNow -lt $deadline -and $sync.Errors.Count -eq 0) {
                Start-Sleep -Milliseconds 25
            }
            return @{ Sync = $sync; PowerShell = $ps; Handle = $handle }
        }

        function Stop-FakeNtpServer {
            param($Server)
            try { $null = $Server.PowerShell.EndInvoke($Server.Handle) } catch { $null = $_ }
            $Server.PowerShell.Dispose()
        }
    }

    It 'gets valid replies, best sample, stratum and refid from a live socket' {
        $server = Start-FakeNtpServer -ReplyCount 2
        try {
            $server.Sync.Port | Should -BeGreaterThan 0
            $anchor = [datetime]::UtcNow
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-NtpQuery -ComputerName '127.0.0.1' -Samples 2 -TimeoutMilliseconds 3000 -UtcAnchor $anchor -AnchorStopwatch $sw -Port $server.Sync.Port
            $r['Success'] | Should -BeTrue
            $r['SamplesSent'] | Should -Be 2
            $r['RepliesValid'] | Should -Be 2
            $r['SamplesLostPct'] | Should -Be 0
            $r['Stratum'] | Should -Be 2
            $r['LI'] | Should -Be 0
            $r['RefIdText'] | Should -Be '10.0.0.5'
            $r['Error'] | Should -BeNullOrEmpty
            # T2=T3=T1 => offset ~ -rtt/2, delay ~ rtt: tiny on loopback
            [math]::Abs([double]$r['OffsetSeconds']) | Should -BeLessThan 0.5
            [double]$r['DelaySeconds'] | Should -BeGreaterOrEqual 0
            [double]$r['DelaySeconds'] | Should -BeLessThan 1.0
            $r['TransmitTimestamp'] | Should -Not -BeNullOrEmpty
            [math]::Abs(($r['ReferenceTimestamp'] - $anchor).TotalSeconds) | Should -BeLessThan 10
        }
        finally {
            Stop-FakeNtpServer -Server $server
        }
    }

    It 'reports Error (never throws) when nothing answers' {
        # Bind a socket we never read from: probes are swallowed, no ICMP refusal.
        $blackholeEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)
        $blackhole = New-Object System.Net.Sockets.UdpClient($blackholeEp)
        try {
            $port = ([System.Net.IPEndPoint]$blackhole.Client.LocalEndPoint).Port
            $anchor = [datetime]::UtcNow
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-NtpQuery -ComputerName '127.0.0.1' -Samples 1 -TimeoutMilliseconds 200 -UtcAnchor $anchor -AnchorStopwatch $sw -Port $port
            $r['Success'] | Should -BeFalse
            $r['Error'] | Should -Not -BeNullOrEmpty
            $r['Error'] | Should -Match 'no reply|port closed'
            $r['SamplesSent'] | Should -Be 1
            $r['RepliesValid'] | Should -Be 0
            $r['SamplesLostPct'] | Should -Be 100
            $r['Stratum'] | Should -BeNullOrEmpty
        }
        finally {
            $blackhole.Close()
        }
    }
}

Describe 'Health evaluation: healthy DC baseline' {
    BeforeAll {
        $script:Healthy = Invoke-HealthyEval
    }

    It 'emits one record per catalog check, in catalog order' {
        $script:Healthy.Count | Should -Be 9
        ($script:Healthy | ForEach-Object { $_.Check }) -join ',' |
            Should -Be 'Service,NtpQuery,Offset,Stratum,Source,LastSync,Announce,Vmic,SecureTimeSeeding'
    }

    It 'stamps the record shape (PSTypeName, Role, RunId, Timestamp, Data hashtable)' {
        foreach ($r in $script:Healthy) {
            $r.PSObject.TypeNames[0] | Should -Be 'WinTime.HealthRecord'
            $r.Server | Should -Be 'dc1.corp.contoso.com'
            $r.Domain | Should -Be 'corp.contoso.com'
            $r.Role | Should -Be 'Dc'
            $r.RunId | Should -Be 'test-run'
            $r.Timestamp | Should -Be '2026-07-11T12:00:00Z'
            $r.Data | Should -BeOfType [hashtable]
        }
    }

    It 'passes every applicable check on the healthy fixture' {
        foreach ($name in @('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'SecureTimeSeeding')) {
            (Get-CheckRecord $script:Healthy $name).Status | Should -Be 'Pass' -Because $name
        }
        (Get-CheckRecord $script:Healthy 'Vmic').Status | Should -Be 'NotApplicable'
    }

    It 'honors -Checks filtering while preserving catalog order' {
        $r = Invoke-HealthyEval -Checks @('Offset', 'Service')
        $r.Count | Should -Be 2
        $r[0].Check | Should -Be 'Service'
        $r[1].Check | Should -Be 'Offset'
    }

    It 'ignores the fleet-level RefidLoop name in -Checks' {
        $r = Invoke-HealthyEval -Checks @('RefidLoop', 'Service')
        $r.Count | Should -Be 1
        $r[0].Check | Should -Be 'Service'
    }
}

Describe 'Health evaluation: Service check' {
    It 'passes on trigger-start (Start=3), the real domain-joined default' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['Start'] = New-RegVal 'DWord' ([uint32]3)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'trigger-start'
    }

    It 'passes on Start=2 (Automatic), the MS high-accuracy hardening' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['Start'] = New-RegVal 'DWord' ([uint32]2)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'Automatic'
    }

    It 'warns on a genuinely nonstandard Start value' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['Start'] = New-RegVal 'DWord' ([uint32]1)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'nonstandard Start=1'
    }

    It 'fails when the service is not running' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Stopped' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'Stopped'
    }

    It 'fails when disabled (Start=4), even without SCM status' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['Start'] = New-RegVal 'DWord' ([uint32]4)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus $null -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'Start=4'
    }

    It 'warns on a nonstandard service identity (tamper hint)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['ObjectName'] = New-RegVal 'String' 'CORP\evilsvc'
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'evilsvc'
    }

    It 'warns on DelayedAutostart' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time']['DelayedAutostart'] = New-RegVal 'DWord' ([uint32]1)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'DelayedAutostart'
    }

    It 'errors when the SCM status is unavailable but the tree is fine' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus $null -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Service'
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match 'SCM'
    }
}

Describe 'Health evaluation: NtpQuery check' {
    It 'warns above 50% probe loss' {
        $ntp = New-NtpResult -With @{ RepliesValid = 1; SamplesSent = 4; SamplesLostPct = 75 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'NtpQuery'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match '75'
    }

    It 'reports Error (never Fail) with the taxonomy string when no reply came back' {
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply from dc1 (filtered UDP/123, service stopped, or RequireSecureTimeSyncRequests=1 - unverified)'; RepliesValid = 0; SamplesLostPct = 100 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'NtpQuery'
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match 'filtered UDP/123'
    }

    It 'promotes RequireSecureTimeSyncRequests=1 to the primary hint on silence' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer']['RequireSecureTimeSyncRequests'] = New-RegVal 'DWord' ([uint32]1)
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply'; RepliesValid = 0 }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'NtpQuery'
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match '^RequireSecureTimeSyncRequests=1'
    }

    It 'errors when no NTP result exists at all' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $null -PdceNtp $null) 'NtpQuery'
        $r.Status | Should -Be 'Error'
    }
}

Describe 'Health evaluation: Offset check' {
    It 'is NotApplicable on the forest-root PDCe' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $r = Get-CheckRecord (Invoke-Eval -Target $t -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Offset'
        $r.Status | Should -Be 'NotApplicable'
    }

    It 'warns at the warn threshold (default 500 ms)' {
        $ntp = New-NtpResult -With @{ OffsetSeconds = 0.9 }   # 0.9 - 0.005 = 895 ms
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Offset'
        $r.Status | Should -Be 'Warn'
        $r.Data['OffsetVsPdceSeconds'] | Should -Be 0.895
    }

    It 'fails at the fail threshold (default 5000 ms)' {
        $ntp = New-NtpResult -With @{ OffsetSeconds = 6.0 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Offset'
        $r.Status | Should -Be 'Fail'
    }

    It 'honors explicit thresholds' {
        $ntp = New-NtpResult -With @{ OffsetSeconds = 0.9 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult) -Thresholds @{ OffsetWarnMilliseconds = 2000; OffsetFailMilliseconds = 4000 }) 'Offset'
        $r.Status | Should -Be 'Pass'
    }

    It 'is Blocked when NtpQuery failed, naming the blocker' {
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply' }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Offset'
        $r.Status | Should -Be 'Blocked'
        $r.Detail | Should -Match 'NtpQuery'
    }

    It 'errors when the PDCe reference is dead' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult -With @{ Success = $false })) 'Offset'
        $r.Status | Should -Be 'Error'
        $r.Detail | Should -Match 'PDCe'
    }
}

Describe 'Health evaluation: Stratum check' {
    It 'fails on stratum 0' {
        $ntp = New-NtpResult -With @{ Stratum = 0 }
        (Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum').Status | Should -Be 'Fail'
    }

    It 'fails on stratum greater than 15' {
        $ntp = New-NtpResult -With @{ Stratum = 16 }
        (Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum').Status | Should -Be 'Fail'
    }

    It 'fails on LI=3 (unsynchronized)' {
        $ntp = New-NtpResult -With @{ LI = 3 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'leap'
    }

    It 'warns outside the expected band (pdce + depth +/- slack)' {
        $ntp = New-NtpResult -With @{ Stratum = 5 }   # band = 2+1 +/- 1 = 2..4
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum'
        $r.Status | Should -Be 'Warn'
        $r.Data['ExpectedBand'] | Should -Be '2..4'
    }

    It 'adds one to the expected band for an RODC' {
        $t = New-HealthTarget -IsRodc $true
        $ntp = New-NtpResult -With @{ Stratum = 5 }   # band = 2+1+1 +/- 1 = 3..5
        (Get-CheckRecord (Invoke-Eval -Target $t -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum').Status | Should -Be 'Pass'
    }

    It 'warns when stratum <= the PDCe stratum (outside hierarchy)' {
        $ntp = New-NtpResult -With @{ Stratum = 2 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'outside the domain hierarchy'
    }

    It 'suppresses hierarchy warnings for declared known-reliable servers' {
        $ntp = New-NtpResult -With @{ Stratum = 2 }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult) -Thresholds @{ KnownReliableTimeServers = @('dc1.corp.contoso.com') }) 'Stratum'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'known-reliable'
    }

    It 'degrades to absolute rules when the PDCe reference is unavailable' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp $null) 'Stratum'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'absolute rules'
    }

    It 'is Blocked when NtpQuery failed' {
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply' }
        (Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Stratum').Status | Should -Be 'Blocked'
    }
}

Describe 'Health evaluation: Source check' {
    It 'fails on Type=NoSync' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['Type'] = New-RegVal 'String' 'NoSync'
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'NoSync'
    }

    It 'fails when the NtpClient provider is disabled via the policy twin (policy wins)' {
        $tree = New-HealthyTree
        $tree['SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'] = @{ Enabled = New-RegVal 'DWord' ([uint32]0) }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'NtpClient provider disabled'
    }

    It 'warns on Type=NTP on a non-PDCe DC (mis-scoped PDCe GPO)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['Type'] = New-RegVal 'String' 'NTP'
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'mis-scoped'
    }

    It 'passes Type=NTP for a declared known-reliable server' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['Type'] = New-RegVal 'String' 'NTP'
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult) -Thresholds @{ KnownReliableTimeServers = @('DC1.CORP.CONTOSO.COM') }) 'Source'
        $r.Status | Should -Be 'Pass'
    }

    It 'passes the root PDCe with Type=NTP and an external peer list' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['Type'] = New-RegVal 'String' 'NTP'
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['NtpServer'] = New-RegVal 'String' 'ptbtime1.ptb.de,0x8 ptbtime2.ptb.de,0x8'
        $ntp = New-NtpResult -With @{ Stratum = 2 }
        $r = Get-CheckRecord (Invoke-Eval -Target $t -Tree $tree -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'ptbtime1'
    }

    It 'warns on the root PDCe with NTP but no peer list' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Parameters']['Type'] = New-RegVal 'String' 'NTP'
        $r = Get-CheckRecord (Invoke-Eval -Target $t -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult -With @{ Stratum = 2 }) -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'peer list'
    }

    It 'warns on the root PDCe stuck on NT5DS' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $r = Get-CheckRecord (Invoke-Eval -Target $t -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult -With @{ Stratum = 2 }) -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'NT5DS'
    }

    It 'warns on a stratum-1 LOCL refid (free-running local clock)' {
        $ntp = New-NtpResult -With @{ Stratum = 1; RefIdText = 'LOCL'; RefId = [uint32]0x4C4F434C }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'LOCL'
    }

    It 'warns on refid 0 at stratum >= 2' {
        $ntp = New-NtpResult -With @{ RefId = [uint32]0; RefIdText = '0.0.0.0' }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'refid 0'
    }

    It 'still reports the registry layer when NTP is blocked (transport independence)' {
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply' }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Source'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'NT5DS'
        $r.Detail | Should -Match 'blocked by NtpQuery'
    }
}

Describe 'Health evaluation: LastSync check (auto thresholds)' {
    It 'passes at age 600 s and derives warn 2048 from MaxPollInterval 10' {
        $r = Get-CheckRecord (Invoke-HealthyEval) 'LastSync'
        $r.Status | Should -Be 'Pass'
        $r.Data['WarnSeconds'] | Should -Be 2048
        $r.Data['FailSeconds'] | Should -Be 7800
        $r.Data['AgeSeconds'] | Should -Be 600
    }

    It 'lets the MaxPollInterval policy twin win (6 -> warn 128)' {
        $tree = New-HealthyTree
        $tree['SOFTWARE\Policies\Microsoft\W32Time\Config'] = @{ MaxPollInterval = New-RegVal 'DWord' ([uint32]6) }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'LastSync'
        $r.Data['WarnSeconds'] | Should -Be 128
        $r.Data['PolicyApplied'] | Should -BeTrue
        $r.Status | Should -Be 'Warn'   # age 600 > 128
    }

    It 'falls back to the DB dc default (10 -> 2048) when the value is absent' {
        $tree = New-HealthyTree
        $null = $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config'].Remove('MaxPollInterval')
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'LastSync'
        $r.Data['WarnSeconds'] | Should -Be 2048
    }

    It 'falls back to ClockHoldoverPeriod 7800 when the value is absent (pre-1709)' {
        $tree = New-HealthyTree
        $null = $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config'].Remove('ClockHoldoverPeriod')
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'LastSync'
        $r.Data['FailSeconds'] | Should -Be 7800
    }

    It 'warns between warn and fail thresholds' {
        $now = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $ntp = New-NtpResult -With @{ ReferenceTimestamp = $now.AddSeconds(-3000) }
        (Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'LastSync').Status | Should -Be 'Warn'
    }

    It 'fails beyond ClockHoldoverPeriod' {
        $now = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $ntp = New-NtpResult -With @{ ReferenceTimestamp = $now.AddSeconds(-9000) }
        (Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'LastSync').Status | Should -Be 'Fail'
    }

    It 'honors explicit thresholds over auto derivation' {
        $now = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $ntp = New-NtpResult -With @{ ReferenceTimestamp = $now.AddSeconds(-9000) }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult) -Thresholds @{ LastSyncWarnSeconds = 10000; LastSyncFailSeconds = 20000 }) 'LastSync'
        $r.Status | Should -Be 'Pass'
    }

    It 'fails as never-synchronized when the reference timestamp is the NTP zero marker' {
        $ntp = New-NtpResult -With @{ ReferenceTimestamp = $script:NtpEpoch }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'LastSync'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'never'
    }

    It 'still evaluates with default thresholds when the registry tree is missing' {
        $r = Get-CheckRecord (Invoke-Eval -Tree $null -ScmStatus $null -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'LastSync'
        $r.Status | Should -Be 'Pass'
        $r.Data['WarnSeconds'] | Should -Be 2048
    }
}

Describe 'Health evaluation: Announce check' {
    It 'passes AnnounceFlags=5 on the root PDCe' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'] = New-RegVal 'DWord' ([uint32]5)
        (Get-CheckRecord (Invoke-Eval -Target $t -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult -With @{ Stratum = 2 }) -PdceNtp (New-PdceNtpResult)) 'Announce').Status | Should -Be 'Pass'
    }

    It 'warns AnnounceFlags=10 on the root PDCe (set 5 per MS convention)' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $r = Get-CheckRecord (Invoke-Eval -Target $t -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp (New-NtpResult -With @{ Stratum = 2 }) -PdceNtp (New-PdceNtpResult)) 'Announce'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'set 5'
    }

    It 'fails the root PDCe with no timeserv bits' {
        $t = New-HealthTarget -IsRootPdce $true -DomainDepth 0
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'] = New-RegVal 'DWord' ([uint32]4)
        (Get-CheckRecord (Invoke-Eval -Target $t -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult -With @{ Stratum = 2 }) -PdceNtp (New-PdceNtpResult)) 'Announce').Status | Should -Be 'Fail'
    }

    It 'passes AnnounceFlags=10 on an ordinary DC' {
        (Get-CheckRecord (Invoke-HealthyEval) 'Announce').Status | Should -Be 'Pass'
    }

    It 'warns on AlwaysReliable (0x4) on an ordinary DC (time hijack risk)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'] = New-RegVal 'DWord' ([uint32]14)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Announce'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'hijack'
    }

    It 'allows AlwaysReliable for a declared known-reliable server' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'] = New-RegVal 'DWord' ([uint32]14)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult) -Thresholds @{ KnownReliableTimeServers = @('dc1.corp.contoso.com') }) 'Announce'
        $r.Status | Should -Be 'Pass'
    }

    It 'warns when a DC advertises nothing (no timeserv bits)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'] = New-RegVal 'DWord' ([uint32]0)
        (Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Announce').Status | Should -Be 'Warn'
    }
}

Describe 'Health evaluation: Vmic check' {
    BeforeAll {
        function New-HyperVTree {
            param([string]$Build = '20348')
            $tree = New-HealthyTree
            $tree['SYSTEM\CurrentControlSet\Control\SystemInformation'] = @{
                SystemManufacturer = New-RegVal 'String' 'Microsoft Corporation'
                SystemProductName  = New-RegVal 'String' 'Virtual Machine'
            }
            $tree['SOFTWARE\Microsoft\Windows NT\CurrentVersion'] = @{
                CurrentBuildNumber = New-RegVal 'String' $Build
            }
            $tree
        }
    }

    It 'is NotApplicable on physical hardware' {
        $r = Get-CheckRecord (Invoke-HealthyEval) 'Vmic'
        $r.Status | Should -Be 'NotApplicable'
        $r.Detail | Should -Match 'physical'
    }

    It 'is NotApplicable on a non-Hyper-V guest' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Control\SystemInformation'] = @{
            SystemManufacturer = New-RegVal 'String' 'VMware, Inc.'
            SystemProductName  = New-RegVal 'String' 'VMware Virtual Platform'
        }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Vmic'
        $r.Status | Should -Be 'NotApplicable'
        $r.Detail | Should -Match 'non-Hyper-V'
    }

    It 'passes a post-2016 Hyper-V guest with VMIC enabled by default' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HyperVTree) -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Vmic'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'boot/resume'
    }

    It 'fails a pre-2016 Hyper-V guest with VMIC enabled (host-sync pattern)' {
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HyperVTree -Build '9600') -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Vmic'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'pre-2016'
    }

    It 'passes a Hyper-V guest with VMIC explicitly disabled' {
        $tree = New-HyperVTree -Build '9600'
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider'] = @{ Enabled = New-RegVal 'DWord' ([uint32]0) }
        (Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'Vmic').Status | Should -Be 'Pass'
    }

    It 'warns when refid 0 shows VMIC actively steering (keys on refid+manufacturer)' {
        $ntp = New-NtpResult -With @{ RefId = [uint32]0; RefIdText = '0.0.0.0' }
        $r = Get-CheckRecord (Invoke-Eval -Tree (New-HyperVTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Vmic'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'steering'
    }
}

Describe 'Health evaluation: SecureTimeSeeding check' {
    It 'passes when UtilizeSslTimeData=0' {
        $r = Get-CheckRecord (Invoke-HealthyEval) 'SecureTimeSeeding'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'disabled'
    }

    It 'reports Info (as Pass) with the 2025-default note when effective 1 on a DC' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['UtilizeSslTimeData'] = New-RegVal 'DWord' ([uint32]1)
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'SecureTimeSeeding'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match '^Info:'
        $r.Detail | Should -Match '26100'
    }

    It 'resolves the absent value to 0 on build 26100+ via defaults_overrides' {
        $tree = New-HealthyTree
        $null = $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config'].Remove('UtilizeSslTimeData')
        $tree['SOFTWARE\Microsoft\Windows NT\CurrentVersion']['CurrentBuildNumber'] = New-RegVal 'String' '26100'
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'SecureTimeSeeding'
        $r.Status | Should -Be 'Pass'
        $r.Detail | Should -Match 'default'
        $r.Data['UtilizeSslTimeData'] | Should -Be 0
    }

    It 'resolves the absent value to 1 on pre-26100 builds (Info)' {
        $tree = New-HealthyTree
        $null = $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config'].Remove('UtilizeSslTimeData')
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'SecureTimeSeeding'
        $r.Data['UtilizeSslTimeData'] | Should -Be 1
        $r.Detail | Should -Match '^Info:'
    }

    It 'lets the policy twin win (policy 0 over operational 1)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['UtilizeSslTimeData'] = New-RegVal 'DWord' ([uint32]1)
        $tree['SOFTWARE\Policies\Microsoft\W32Time\Config'] = @{ UtilizeSslTimeData = New-RegVal 'DWord' ([uint32]0) }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'SecureTimeSeeding'
        $r.Status | Should -Be 'Pass'
        $r.Data['PolicyApplied'] | Should -BeTrue
        $r.Data['UtilizeSslTimeData'] | Should -Be 0
    }

    It 'warns when STS state shows a large estimate divergence (active steering)' {
        $tree = New-HealthyTree
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['UtilizeSslTimeData'] = New-RegVal 'DWord' ([uint32]1)
        $now = [datetime]::new(2026, 7, 11, 12, 0, 0, [System.DateTimeKind]::Utc)
        $estimate = [uint64]$now.AddHours(2).ToFileTimeUtc()
        $tree['SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits'] = @{
            SecureTimeEstimated  = New-RegVal 'QWord' $estimate
            SecureTimeConfidence = New-RegVal 'DWord' ([uint32]6)
        }
        $r = Get-CheckRecord (Invoke-Eval -Tree $tree -ScmStatus 'Running' -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)) 'SecureTimeSeeding'
        $r.Status | Should -Be 'Warn'
        $r.Detail | Should -Match 'diverges'
        $r.Data['SecureTimeConfidence'] | Should -Be 6
    }
}

Describe 'Health evaluation: transport independence and Samba' {
    It 'reports Error for registry checks but still evaluates UDP checks when the tree is null' {
        $records = Invoke-Eval -Tree $null -ScmStatus $null -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)
        foreach ($name in @('Service', 'Announce', 'Vmic', 'SecureTimeSeeding')) {
            $r = Get-CheckRecord $records $name
            $r.Status | Should -Be 'Error' -Because $name
            $r.Detail | Should -Match 'scan failed' -Because $name
        }
        (Get-CheckRecord $records 'Source').Status | Should -Be 'Error'
        (Get-CheckRecord $records 'NtpQuery').Status | Should -Be 'Pass'
        (Get-CheckRecord $records 'Offset').Status | Should -Be 'Pass'
        (Get-CheckRecord $records 'Stratum').Status | Should -Be 'Pass'
        (Get-CheckRecord $records 'LastSync').Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable for registry checks when no W32Time key exists (Samba DC)' {
        $sambaTree = @{
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion'       = @{ CurrentBuildNumber = New-RegVal 'String' '20348' }
            'SYSTEM\CurrentControlSet\Control\SystemInformation' = @{ SystemManufacturer = New-RegVal 'String' 'Dell Inc.'; SystemProductName = New-RegVal 'String' 'PowerEdge R650' }
        }
        $records = Invoke-Eval -Tree $sambaTree -ScmStatus $null -Ntp (New-NtpResult) -PdceNtp (New-PdceNtpResult)
        foreach ($name in @('Service', 'Source', 'Announce', 'Vmic', 'SecureTimeSeeding')) {
            (Get-CheckRecord $records $name).Status | Should -Be 'NotApplicable' -Because $name
        }
        # UDP checks unaffected
        (Get-CheckRecord $records 'NtpQuery').Status | Should -Be 'Pass'
        (Get-CheckRecord $records 'Stratum').Status | Should -Be 'Pass'
    }

    It 'blocks Offset/Stratum/LastSync but not the Source registry layer on NtpQuery failure' {
        $ntp = New-NtpResult -With @{ Success = $false; Error = 'no reply (filtered UDP/123, ...)' }
        $records = Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)
        foreach ($name in @('Offset', 'Stratum', 'LastSync')) {
            $r = Get-CheckRecord $records $name
            $r.Status | Should -Be 'Blocked' -Because $name
            $r.Detail | Should -Match 'NtpQuery' -Because $name
        }
        (Get-CheckRecord $records 'Source').Status | Should -Be 'Pass'
        (Get-CheckRecord $records 'Service').Status | Should -Be 'Pass'
    }
}

Describe 'Get-WinTimeRefidLoopFinding (fleet-level RefidLoop)' {
    It 'fails every member of a two-node refid cycle (time island) and spares the tail' {
        $all = @{
            'dc1.corp.contoso.com' = New-LoopNode -Fqdn 'dc1.corp.contoso.com' -Ips @('10.0.0.1') -RefIdDotted '10.0.0.2'
            'dc2.corp.contoso.com' = New-LoopNode -Fqdn 'dc2.corp.contoso.com' -Ips @('10.0.0.2') -RefIdDotted '10.0.0.1'
            'dc3.corp.contoso.com' = New-LoopNode -Fqdn 'dc3.corp.contoso.com' -Ips @('10.0.0.3') -RefIdDotted '10.0.0.1'
        }
        $findings = @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z')
        $fails = @($findings | Where-Object { $_.Status -eq 'Fail' })
        $fails.Count | Should -Be 2
        (@($fails | ForEach-Object { $_.Server }) | Sort-Object) -join ',' | Should -Be 'dc1.corp.contoso.com,dc2.corp.contoso.com'
        $fails[0].Check | Should -Be 'RefidLoop'
        $fails[0].Detail | Should -Match 'time island'
        @($findings | Where-Object { $_.Server -eq 'dc3.corp.contoso.com' }).Count | Should -Be 0
    }

    It 'fails a self-loop (DC refid pointing at its own IP)' {
        $all = @{
            'dc5.corp.contoso.com' = New-LoopNode -Fqdn 'dc5.corp.contoso.com' -Ips @('10.0.0.5') -RefIdDotted '10.0.0.5'
        }
        $findings = @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z')
        $findings.Count | Should -Be 1
        $findings[0].Status | Should -Be 'Fail'
    }

    It 'downgrades a cycle containing a declared known-reliable member to Warn' {
        $all = @{
            'dc1.corp.contoso.com' = New-LoopNode -Fqdn 'dc1.corp.contoso.com' -Ips @('10.0.0.1') -RefIdDotted '10.0.0.2'
            'dc2.corp.contoso.com' = New-LoopNode -Fqdn 'dc2.corp.contoso.com' -Ips @('10.0.0.2') -RefIdDotted '10.0.0.1'
        }
        $findings = @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z' -KnownReliableTimeServers @('DC1.CORP.CONTOSO.COM'))
        @($findings | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be 0
        @($findings | Where-Object { $_.Status -eq 'Warn' }).Count | Should -Be 2
    }

    It 'warns once for an unknown upstream on a non-PDCe DC' {
        $all = @{
            'dc4.corp.contoso.com' = New-LoopNode -Fqdn 'dc4.corp.contoso.com' -Ips @('10.0.0.4') -RefIdDotted '203.0.113.7'
        }
        $findings = @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z')
        $findings.Count | Should -Be 1
        $findings[0].Status | Should -Be 'Warn'
        $findings[0].Detail | Should -Match '203\.0\.113\.7'
        $findings[0].Detail | Should -Match 'unknown upstream'
    }

    It 'never flags the root PDCe for an external upstream' {
        $all = @{
            'pdce.contoso.com' = New-LoopNode -Fqdn 'pdce.contoso.com' -Ips @('10.0.0.10') -RefIdDotted '192.53.103.108' -Stratum 2 -IsRootPdce $true
        }
        @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z').Count | Should -Be 0
    }

    It 'skips stratum-1, refid-0, and failed nodes' {
        $gpsNode = New-LoopNode -Fqdn 'gps.corp.contoso.com' -Ips @('10.0.0.20') -Stratum 1
        $gpsNode['Ntp']['RefIdText'] = 'GPS'
        $all = @{
            'gps.corp.contoso.com'  = $gpsNode
            'dead.corp.contoso.com' = New-LoopNode -Fqdn 'dead.corp.contoso.com' -Ips @('10.0.0.21') -Success $false
            'vmic.corp.contoso.com' = New-LoopNode -Fqdn 'vmic.corp.contoso.com' -Ips @('10.0.0.22') -RefIdDotted '0.0.0.0'
        }
        @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z').Count | Should -Be 0
    }

    It 'emits well-formed HealthRecords with domain and role from the target' {
        $all = @{
            'dc4.corp.contoso.com' = New-LoopNode -Fqdn 'dc4.corp.contoso.com' -Ips @('10.0.0.4') -RefIdDotted '203.0.113.7'
        }
        $f = @(Get-WinTimeRefidLoopFinding -AllResults $all -RunId 'test-run' -Timestamp '2026-07-11T12:00:00Z')[0]
        $f.PSObject.TypeNames[0] | Should -Be 'WinTime.HealthRecord'
        $f.Domain | Should -Be 'corp.contoso.com'
        $f.Role | Should -Be 'Dc'
        $f.RunId | Should -Be 'test-run'
    }
}

Describe 'Culture safety' {
    BeforeAll {
        # Pseudo German culture: real de-DE when the runtime has ICU data,
        # otherwise an invariant clone with German separators (this sandbox
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

    It 'formats numeric details invariantly under de-DE culture' {
        $original = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = Get-TestGermanCulture
            # Control probe: the German-style culture really is in effect.
            ([double]905.5).ToString() | Should -Be '905,5'
            $ntp = New-NtpResult -With @{ OffsetSeconds = 0.9105 }
            $r = Get-CheckRecord (Invoke-Eval -Tree (New-HealthyTree) -ScmStatus 'Running' -Ntp $ntp -PdceNtp (New-PdceNtpResult)) 'Offset'
            # 905.5 ms must render with a period, never a comma
            $r.Detail | Should -Match '905\.5 ms'
        }
        finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $original
        }
    }
}
