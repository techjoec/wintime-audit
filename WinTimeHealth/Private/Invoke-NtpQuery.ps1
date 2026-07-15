# Invoke-NtpQuery.ps1 - SNTP (NTPv3 mode-3) client for Get-WinTimeHealth phase 2
# (DESIGN section 8) plus its pure packet/timestamp helpers. The helpers live in
# this file because they are inseparable from the wire client and are
# unit-tested directly; all functions here are private module functions.

function ConvertFrom-WinTimeBigEndianUInt32 {
<#
.SYNOPSIS
Reads a big-endian unsigned 32-bit integer from a byte buffer.

.DESCRIPTION
NTP wire format is big-endian. [System.BitConverter] is little-endian on every
platform this module supports, so the bytes are assembled manually
(most-significant byte first) instead of using BitConverter with reversal.

.PARAMETER Buffer
Source byte array.

.PARAMETER Offset
Zero-based index of the first (most significant) byte.

.OUTPUTS
System.UInt32

.EXAMPLE
ConvertFrom-WinTimeBigEndianUInt32 -Buffer ([byte[]]@(1,2,3,4)) -Offset 0
# 16909060 (0x01020304)

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 2147483647)]
        [int]$Offset
    )

    if ($Offset + 4 -gt $Buffer.Length) {
        throw "ConvertFrom-WinTimeBigEndianUInt32: buffer too short (need 4 bytes at offset $Offset, have $($Buffer.Length))."
    }
    $acc = [uint64]0
    for ($i = 0; $i -lt 4; $i++) {
        $acc = ($acc -shl 8) -bor [uint64]$Buffer[$Offset + $i]
    }
    return [uint32]$acc
}

function ConvertFrom-WinTimeBigEndianUInt64 {
<#
.SYNOPSIS
Reads a big-endian unsigned 64-bit integer from a byte buffer.

.DESCRIPTION
Companion to ConvertFrom-WinTimeBigEndianUInt32 for full 64-bit NTP timestamp
fields (32-bit seconds + 32-bit fraction). Manual big-endian assembly; no
BitConverter.

.PARAMETER Buffer
Source byte array.

.PARAMETER Offset
Zero-based index of the first (most significant) byte.

.OUTPUTS
System.UInt64

.EXAMPLE
ConvertFrom-WinTimeBigEndianUInt64 -Buffer $reply -Offset 40

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([uint64])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 2147483647)]
        [int]$Offset
    )

    if ($Offset + 8 -gt $Buffer.Length) {
        throw "ConvertFrom-WinTimeBigEndianUInt64: buffer too short (need 8 bytes at offset $Offset, have $($Buffer.Length))."
    }
    $acc = [uint64]0
    for ($i = 0; $i -lt 8; $i++) {
        $acc = ($acc -shl 8) -bor [uint64]$Buffer[$Offset + $i]
    }
    return $acc
}

function ConvertFrom-WinTimeNtpTimestamp {
<#
.SYNOPSIS
Converts an NTP timestamp (seconds + fraction since 1900-01-01) to a UTC
DateTime.

.DESCRIPTION
NTP timestamps are 32-bit unsigned seconds since 1900-01-01T00:00:00Z plus a
32-bit fraction in units of 2^-32 seconds. The 32-bit seconds field wraps
(era 0 ends 2036-02-07T06:28:16Z), so the standard era-pivot trick is applied:
a seconds value with the most-significant bit SET belongs to era 0
(1968..2036, base 1900-01-01); MSB CLEAR means era 1 (2036..2104, base
2036-02-07T06:28:16Z). This is the same pivot used by ntpd and Apache
commons-net and keeps the conversion correct until 2104 for any timestamp
produced after 1968.

A raw all-zero timestamp is the NTP "unset" marker; it is special-cased to the
1900-01-01 epoch (callers treat a 1900-era ReferenceTimestamp as
"never synchronized").

.PARAMETER Seconds
The 32-bit big-endian seconds field.

.PARAMETER Fraction
The 32-bit big-endian fraction field (units of 2^-32 s).

.OUTPUTS
System.DateTime (Kind = Utc)

.EXAMPLE
ConvertFrom-WinTimeNtpTimestamp -Seconds 2208988800 -Fraction 0
# 1970-01-01T00:00:00Z

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Seconds,

        [Parameter(Mandatory = $true)]
        [uint32]$Fraction
    )

    $era0Epoch = [datetime]::new(1900, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    if ($Seconds -eq [uint32]0 -and $Fraction -eq [uint32]0) {
        # NTP "unset" marker -> epoch (never synchronized).
        return $era0Epoch
    }

    # MSB set (>= 2^31) = era 0. Decimal literal: 0x80000000 parses as a
    # negative Int32 in PowerShell and would break the uint32 comparison.
    if ($Seconds -ge [uint32]2147483648) {
        $base = $era0Epoch
    }
    else {
        # Era 1 base: 1900-01-01 + 2^32 seconds = 2036-02-07T06:28:16Z.
        $base = $era0Epoch.AddTicks(42949672960000000)
    }

    # 1 tick = 100 ns; fraction unit = 2^-32 s (~0.23 ns), rounded to ticks.
    $ticks = ([long]$Seconds * [long]10000000) + [long][math]::Round(([double]$Fraction) * 10000000.0 / 4294967296.0)
    return $base.AddTicks($ticks)
}

function ConvertTo-WinTimeNtpTimestamp {
<#
.SYNOPSIS
Converts a UTC DateTime to NTP timestamp fields (seconds + fraction).

.DESCRIPTION
Inverse of ConvertFrom-WinTimeNtpTimestamp. Seconds are counted from
1900-01-01T00:00:00Z and returned modulo 2^32 (the on-wire seconds field wraps
into era 1 after 2036-02-07T06:28:16Z; the era-pivot in the From- conversion
recovers the original instant). Integer tick arithmetic avoids double-precision
loss on the ~4e16-tick magnitudes involved.

.PARAMETER DateTime
The instant to convert. Local-kind values are converted to UTC first;
unspecified-kind values are assumed to already be UTC.

.OUTPUTS
System.Collections.Hashtable: @{ Seconds = [uint32]; Fraction = [uint32] }

.EXAMPLE
ConvertTo-WinTimeNtpTimestamp -DateTime ([datetime]::new(1970,1,1,0,0,0,'Utc'))
# @{ Seconds = 2208988800; Fraction = 0 }

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$DateTime
    )

    $utc = $DateTime
    if ($utc.Kind -eq [System.DateTimeKind]::Local) {
        $utc = $utc.ToUniversalTime()
    }
    $era0Epoch = [datetime]::new(1900, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $ticks = ($utc - $era0Epoch).Ticks
    if ($ticks -lt 0) {
        throw 'ConvertTo-WinTimeNtpTimestamp: instants before 1900-01-01 cannot be represented.'
    }

    $remainderTicks = $ticks % 10000000
    # (ticks - remainder) is exactly divisible; quotient (~4e9) is exact in double.
    $totalSeconds = [long](($ticks - $remainderTicks) / 10000000)
    # remainder < 1e7 so the scaled fraction is always < 2^32 (no overflow).
    $fraction = [uint32][math]::Round(([double]$remainderTicks) * 4294967296.0 / 10000000.0)

    return @{
        # decimal mask: 0xFFFFFFFF parses as Int32 -1 in PowerShell
        Seconds  = [uint32]($totalSeconds -band [long]4294967295)
        Fraction = $fraction
    }
}

function ConvertTo-WinTimeNtpPacket {
<#
.SYNOPSIS
Builds a 48-byte NTPv3 mode-3 (client) request packet.

.DESCRIPTION
First byte 0x1B = LI 0 (00) | VN 3 (011) | Mode 3 client (011). All fields are
zero except the Transmit Timestamp (bytes 40-47), which carries the caller's
T1. The low 16 bits of the fraction are randomized (~15 microseconds of
jitter): the server echoes this timestamp verbatim as the Originate Timestamp,
so the random bits act as an anti-spoofing/stale-reply nonce that replies must
echo to be accepted.

.PARAMETER TransmitTime
The client transmit instant (T1), normally UtcAnchor + AnchorStopwatch.Elapsed.

.OUTPUTS
System.Collections.Hashtable:
@{ Bytes = [byte[]] (48); TransmitBytes = [byte[]] (8, the exact T1 field
   bytes to match against the reply's originate field);
   TransmitDateTime = [datetime] (T1 as actually encoded, including the
   randomized fraction bits - use this in offset math) }

.EXAMPLE
$pkt = ConvertTo-WinTimeNtpPacket -TransmitTime ([datetime]::UtcNow)

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$TransmitTime
    )

    $packet = New-Object byte[] 48
    $packet[0] = 0x1B    # LI=0, VN=3, Mode=3 (client)

    $ts = ConvertTo-WinTimeNtpTimestamp -DateTime $TransmitTime
    $seconds = [uint32]$ts['Seconds']
    # Randomize the low 16 fraction bits (max ~15 us) as a reply nonce.
    $fraction = ([uint32]($ts['Fraction'] -band 0xFFFF0000)) -bor [uint32](Get-Random -Minimum 0 -Maximum 65536)

    $packet[40] = [byte](($seconds -shr 24) -band 0xFF)
    $packet[41] = [byte](($seconds -shr 16) -band 0xFF)
    $packet[42] = [byte](($seconds -shr 8) -band 0xFF)
    $packet[43] = [byte]($seconds -band 0xFF)
    $packet[44] = [byte](($fraction -shr 24) -band 0xFF)
    $packet[45] = [byte](($fraction -shr 16) -band 0xFF)
    $packet[46] = [byte](($fraction -shr 8) -band 0xFF)
    $packet[47] = [byte]($fraction -band 0xFF)

    $transmitBytes = New-Object byte[] 8
    [System.Array]::Copy($packet, 40, $transmitBytes, 0, 8)

    return @{
        Bytes            = $packet
        TransmitBytes    = $transmitBytes
        # T1 as actually sent (randomized fraction included) for exact math.
        TransmitDateTime = (ConvertFrom-WinTimeNtpTimestamp -Seconds $seconds -Fraction $fraction)
    }
}

function ConvertFrom-WinTimeNtpReply {
<#
.SYNOPSIS
Parses and validates a server NTP reply against the request that was sent.

.DESCRIPTION
Validation per DESIGN section 8: length >= 48, Mode = 4 (server), version 3 or
4, and the reply's Originate Timestamp must byte-for-byte echo the request's
(randomized) Transmit Timestamp. Extracts LI, Stratum, RefId (raw uint32,
dotted-quad text, and ASCII text when stratum < 2), ReferenceTimestamp,
ReceiveTimestamp (T2) and TransmitTimestamp (T3).

Kiss-o'-Death recognition: stratum 0 with a printable-ASCII refid (RATE, DENY,
RSTR, ...) marks the reply IsKissOfDeath with the kiss code; such replies are
not Valid samples. A stratum-0 reply with a non-ASCII refid (e.g. 0) is
structurally valid so the Stratum health check can Fail on it.

.PARAMETER Buffer
The received datagram.

.PARAMETER TransmitBytes
The 8 T1 bytes sent in the request (from ConvertTo-WinTimeNtpPacket).

.OUTPUTS
System.Collections.Hashtable with keys: Valid, Reason, LI, VersionNumber,
Mode, Stratum, RefId, RefIdDotted, RefIdAscii, IsKissOfDeath, KissCode,
ReferenceTimestamp, ReceiveTimestamp, TransmitTimestamp.

.EXAMPLE
ConvertFrom-WinTimeNtpReply -Buffer $datagram -TransmitBytes $pkt['TransmitBytes']

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [byte[]]$TransmitBytes
    )

    $result = @{
        Valid              = $false
        Reason             = $null
        LI                 = $null
        VersionNumber      = $null
        Mode               = $null
        Stratum            = $null
        RefId              = $null
        RefIdDotted        = $null
        RefIdAscii         = $null
        IsKissOfDeath      = $false
        KissCode           = $null
        ReferenceTimestamp = $null
        ReceiveTimestamp   = $null
        TransmitTimestamp  = $null
    }

    if ($Buffer.Length -lt 48) {
        $result['Reason'] = "short packet ($($Buffer.Length) bytes, need 48)"
        return $result
    }

    $b0 = [int]$Buffer[0]
    $result['LI'] = ($b0 -shr 6) -band 0x3
    $result['VersionNumber'] = ($b0 -shr 3) -band 0x7
    $result['Mode'] = $b0 -band 0x7
    $result['Stratum'] = [int]$Buffer[1]

    if ($result['Mode'] -ne 4) {
        $result['Reason'] = "not a server reply (mode $($result['Mode']))"
        return $result
    }
    if ($result['VersionNumber'] -ne 3 -and $result['VersionNumber'] -ne 4) {
        $result['Reason'] = "unexpected NTP version $($result['VersionNumber'])"
        return $result
    }
    for ($i = 0; $i -lt 8; $i++) {
        if ($Buffer[24 + $i] -ne $TransmitBytes[$i]) {
            $result['Reason'] = 'originate timestamp mismatch (stale or spoofed reply)'
            return $result
        }
    }

    $result['RefId'] = ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 12
    $result['RefIdDotted'] = '{0}.{1}.{2}.{3}' -f [int]$Buffer[12], [int]$Buffer[13], [int]$Buffer[14], [int]$Buffer[15]

    # ASCII refid is only meaningful below stratum 2 (KoD codes at stratum 0,
    # reference source tags like GPS/PPS/LOCL at stratum 1).
    if ($result['Stratum'] -lt 2) {
        $allAsciiOrNul = $true
        $chars = ''
        for ($i = 12; $i -le 15; $i++) {
            $b = [int]$Buffer[$i]
            if ($b -eq 0) { continue }
            if ($b -lt 0x20 -or $b -gt 0x7E) { $allAsciiOrNul = $false; break }
            $chars += [char]$b
        }
        if ($allAsciiOrNul -and $chars.Length -gt 0) {
            $result['RefIdAscii'] = $chars
        }
    }

    if ($result['Stratum'] -eq 0 -and $null -ne $result['RefIdAscii']) {
        $result['IsKissOfDeath'] = $true
        $result['KissCode'] = $result['RefIdAscii']
        $result['Reason'] = "kiss-o'-death '$($result['RefIdAscii'])'"
        return $result
    }

    $result['ReferenceTimestamp'] = ConvertFrom-WinTimeNtpTimestamp -Seconds (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 16) -Fraction (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 20)
    $result['ReceiveTimestamp'] = ConvertFrom-WinTimeNtpTimestamp -Seconds (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 32) -Fraction (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 36)
    $result['TransmitTimestamp'] = ConvertFrom-WinTimeNtpTimestamp -Seconds (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 40) -Fraction (ConvertFrom-WinTimeBigEndianUInt32 -Buffer $Buffer -Offset 44)
    $result['Valid'] = $true
    return $result
}

function Get-WinTimeNtpSampleMath {
<#
.SYNOPSIS
Computes the per-sample NTP clock offset and round-trip delay.

.DESCRIPTION
Standard SNTP math: offset = ((T2 - T1) + (T3 - T4)) / 2 and
delay = (T4 - T1) - (T3 - T2), where T1/T4 are client transmit/receive
instants and T2/T3 are the server receive/transmit timestamps from the reply.

.PARAMETER T1
Client transmit instant.

.PARAMETER T2
Server receive timestamp.

.PARAMETER T3
Server transmit timestamp.

.PARAMETER T4
Client receive instant.

.OUTPUTS
System.Collections.Hashtable: @{ OffsetSeconds = [double]; DelaySeconds = [double] }

.EXAMPLE
Get-WinTimeNtpSampleMath -T1 $t1 -T2 $p['ReceiveTimestamp'] -T3 $p['TransmitTimestamp'] -T4 $t4

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)][datetime]$T1,
        [Parameter(Mandatory = $true)][datetime]$T2,
        [Parameter(Mandatory = $true)][datetime]$T3,
        [Parameter(Mandatory = $true)][datetime]$T4
    )

    $offset = (($T2 - $T1).TotalSeconds + ($T3 - $T4).TotalSeconds) / 2.0
    $delay = ($T4 - $T1).TotalSeconds - ($T3 - $T2).TotalSeconds
    return @{
        OffsetSeconds = $offset
        DelaySeconds  = $delay
    }
}

function Get-WinTimeNtpSocketErrorText {
<#
.SYNOPSIS
Maps a SocketException from an NTP probe to the DESIGN section 8 error
taxonomy string.

.DESCRIPTION
10054/ConnectionReset (and the POSIX ConnectionRefused equivalent surfaced by
.NET on non-Windows hosts) means an ICMP port-unreachable came back: the port
is closed. 10060/TimedOut means no reply at all. Name-resolution errors get
their own message; everything else falls through to a generic description.

.PARAMETER Exception
The SocketException (already unwrapped from any MethodInvocationException).

.PARAMETER ComputerName
Probe target, for message interpolation.

.OUTPUTS
System.String

.EXAMPLE
Get-WinTimeNtpSocketErrorText -Exception $sockEx -ComputerName dc1.corp.example

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Sockets.SocketException]$Exception,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    $code = $Exception.SocketErrorCode
    if ($code -eq [System.Net.Sockets.SocketError]::ConnectionReset -or
        $code -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
        return "port closed - w32time down or NtpServer provider disabled on $ComputerName (UDP/123 unreachable, $code)"
    }
    if ($code -eq [System.Net.Sockets.SocketError]::TimedOut) {
        return "no reply from $ComputerName (filtered UDP/123, service stopped, or RequireSecureTimeSyncRequests=1 - unverified)"
    }
    if ($code -eq [System.Net.Sockets.SocketError]::HostNotFound -or
        $code -eq [System.Net.Sockets.SocketError]::NoData -or
        $code -eq [System.Net.Sockets.SocketError]::TryAgain) {
        return "DNS resolution failed for $ComputerName ($code)"
    }
    return "socket error $code querying ${ComputerName}: $($Exception.Message)"
}

function Invoke-NtpQuery {
<#
.SYNOPSIS
Sends SNTP (NTPv3 mode-3) client probes to one host and returns the best
(minimum-delay) sample.

.DESCRIPTION
Implements the phase-2 UDP/123 transport of Get-WinTimeHealth (DESIGN
section 8). Per sample: a fresh UdpClient on an ephemeral port (never binds
123) sends a 48-byte mode-3 NTPv3 packet whose Transmit Timestamp (T1, with
randomized low fraction bits as a nonce) is derived from the shared
UtcAnchor + AnchorStopwatch pair (monotonic; the admin host's absolute clock
error cancels in the differential offset used by the Offset check). Replies
must be mode 4, version 3 or 4, at least 48 bytes, and echo T1 exactly as the
Originate Timestamp; non-matching datagrams are discarded and the socket keeps
listening until the per-sample timeout. Offset and delay per valid sample use
the standard formulas; the minimum-delay sample wins.

Failure taxonomy: SocketException ConnectionReset/10054 => "port closed -
w32time down or NtpServer provider disabled"; TimedOut/10060 => "no reply
(filtered UDP/123, service stopped, or RequireSecureTimeSyncRequests=1 -
unverified)". A Kiss-o'-Death reply (stratum 0 + ASCII refid such as
RATE/DENY) produces an Error naming the kiss code. No UDP reply is always an
Error (never Fail) at the health-check layer.

.PARAMETER ComputerName
Target host (canonical FQDN, or an IP literal).

.PARAMETER Samples
Number of probes to send (best-of-N, minimum delay wins). Default 4.

.PARAMETER TimeoutMilliseconds
Per-sample receive timeout (explicit Client.ReceiveTimeout). Default 1500.

.PARAMETER UtcAnchor
DateTime.UtcNow captured once per run by the orchestrator.

.PARAMETER AnchorStopwatch
Stopwatch started at the moment UtcAnchor was captured; T1/T4 are
UtcAnchor + Elapsed.

.PARAMETER Port
UDP port to probe. Default 123; overridable for loopback tests only.

.OUTPUTS
System.Collections.Hashtable: @{ Success; Error; Stratum; LI; RefId;
RefIdText; ReferenceTimestamp; TransmitTimestamp; OffsetSeconds;
DelaySeconds; SamplesSent; RepliesValid; SamplesLostPct }

.EXAMPLE
$anchor = [datetime]::UtcNow; $sw = [System.Diagnostics.Stopwatch]::StartNew()
Invoke-NtpQuery -ComputerName dc1.corp.example.com -Samples 4 -TimeoutMilliseconds 1500 -UtcAnchor $anchor -AnchorStopwatch $sw

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$Samples = 4,

        [Parameter()]
        [ValidateRange(50, 60000)]
        [int]$TimeoutMilliseconds = 1500,

        [Parameter(Mandatory = $true)]
        [datetime]$UtcAnchor,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$AnchorStopwatch,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 123
    )

    $result = @{
        Success            = $false
        Error              = $null
        Stratum            = $null
        LI                 = $null
        RefId              = $null
        RefIdText          = $null
        ReferenceTimestamp = $null
        TransmitTimestamp  = $null
        OffsetSeconds      = $null
        DelaySeconds       = $null
        SamplesSent        = 0
        RepliesValid       = 0
        SamplesLostPct     = $null
    }

    $bestSample = $null
    $lastError = $null
    $kissCode = $null

    for ($sample = 0; $sample -lt $Samples; $sample++) {
        $udp = $null
        try {
            # Fresh client per probe: ephemeral local port (never bind 123) and
            # no cross-probe stale-reply confusion.
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Connect($ComputerName, $Port)
            $udp.Client.ReceiveTimeout = $TimeoutMilliseconds

            $t1Wall = $UtcAnchor + $AnchorStopwatch.Elapsed
            $pkt = ConvertTo-WinTimeNtpPacket -TransmitTime $t1Wall
            $null = $udp.Send($pkt['Bytes'], $pkt['Bytes'].Length)
            $result['SamplesSent'] = [int]$result['SamplesSent'] + 1

            # Keep listening until the per-sample deadline: datagrams that fail
            # validation (stale replies, noise) are discarded, not fatal.
            $probeWatch = [System.Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                $remainingMs = $TimeoutMilliseconds - [int]$probeWatch.ElapsedMilliseconds
                if ($remainingMs -le 0) {
                    if ($null -eq $lastError) {
                        $lastError = "no reply from $ComputerName (filtered UDP/123, service stopped, or RequireSecureTimeSyncRequests=1 - unverified)"
                    }
                    break
                }
                $udp.Client.ReceiveTimeout = $remainingMs
                $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $reply = $udp.Receive([ref]$remote)
                $t4 = $UtcAnchor + $AnchorStopwatch.Elapsed

                $parsed = ConvertFrom-WinTimeNtpReply -Buffer $reply -TransmitBytes $pkt['TransmitBytes']
                if ($parsed['IsKissOfDeath']) {
                    $kissCode = $parsed['KissCode']
                    $lastError = "kiss-o'-death from $ComputerName (refid '$($parsed['KissCode'])') - server refuses service"
                    break
                }
                if (-not $parsed['Valid']) {
                    $lastError = "invalid reply from ${ComputerName}: $($parsed['Reason'])"
                    Write-Verbose "Invoke-NtpQuery: discarded datagram from ${ComputerName}: $($parsed['Reason'])"
                    continue
                }

                $math = Get-WinTimeNtpSampleMath -T1 $pkt['TransmitDateTime'] -T2 $parsed['ReceiveTimestamp'] -T3 $parsed['TransmitTimestamp'] -T4 $t4
                $result['RepliesValid'] = [int]$result['RepliesValid'] + 1
                $entry = @{
                    Offset = $math['OffsetSeconds']
                    Delay  = $math['DelaySeconds']
                    Parsed = $parsed
                }
                if ($null -eq $bestSample -or [double]$entry['Delay'] -lt [double]$bestSample['Delay']) {
                    $bestSample = $entry
                }
                break
            }
        }
        catch [System.Net.Sockets.SocketException] {
            # PowerShell may hand us the MethodInvocationException wrapper; unwrap.
            $sockEx = $_.Exception
            if ($sockEx -isnot [System.Net.Sockets.SocketException] -and $null -ne $sockEx.InnerException) {
                $sockEx = $sockEx.InnerException
            }
            $lastError = Get-WinTimeNtpSocketErrorText -Exception $sockEx -ComputerName $ComputerName
            Write-Verbose "Invoke-NtpQuery: sample $($sample + 1)/$Samples to ${ComputerName}: $lastError"
        }
        catch {
            $lastError = "NTP probe to $ComputerName failed: $($_.Exception.Message)"
            Write-Verbose "Invoke-NtpQuery: $lastError"
        }
        finally {
            if ($null -ne $udp) { $udp.Close() }
        }
    }

    if ([int]$result['SamplesSent'] -gt 0) {
        $result['SamplesLostPct'] = [int][math]::Round(100.0 * ([int]$result['SamplesSent'] - [int]$result['RepliesValid']) / [int]$result['SamplesSent'])
    }
    else {
        $result['SamplesLostPct'] = 100
    }

    if ($null -ne $bestSample) {
        $parsed = $bestSample['Parsed']
        $result['Success'] = $true
        $result['Stratum'] = $parsed['Stratum']
        $result['LI'] = $parsed['LI']
        $result['RefId'] = $parsed['RefId']
        if ([int]$parsed['Stratum'] -lt 2 -and $null -ne $parsed['RefIdAscii']) {
            $result['RefIdText'] = $parsed['RefIdAscii']
        }
        else {
            $result['RefIdText'] = $parsed['RefIdDotted']
        }
        $result['ReferenceTimestamp'] = $parsed['ReferenceTimestamp']
        $result['TransmitTimestamp'] = $parsed['TransmitTimestamp']
        $result['OffsetSeconds'] = $bestSample['Offset']
        $result['DelaySeconds'] = $bestSample['Delay']
    }
    else {
        if ($null -ne $kissCode) {
            # KoD wins the error message even when later probes timed out.
            $result['Error'] = "kiss-o'-death from $ComputerName (refid '$kissCode') - server refuses service"
        }
        elseif ($null -ne $lastError) {
            $result['Error'] = $lastError
        }
        else {
            $result['Error'] = "no valid NTP reply from $ComputerName"
        }
    }

    return $result
}
