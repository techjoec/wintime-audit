function ConvertFrom-RegFile {
    <#
    .SYNOPSIS
        Parses a Windows Registry Editor Version 5.00 export (.reg) into a registry tree hashtable.

    .DESCRIPTION
        Reads a .reg baseline file and returns a hashtable with two entries:

          Tree       - hashtable keyed by registry path RELATIVE to HKLM (OrdinalIgnoreCase),
                       each value a hashtable of valueName -> @{ Kind = <RegistryValueKind name>;
                       Data = <object> }. DWORD data is normalized [uint32], QWORD [uint64].
                       The default value (@=) is stored under the name ''.
          Provenance - hashtable with SourceDCs, Timestamp, OsBuilds, ModuleVersion,
                       SchemaVersion, Pdce (parsed from leading '; key: value' comment lines,
                       $null when absent) and Raw (string[] of every comment line in the file).

        Encoding is sniffed from the BOM: UTF-16LE and UTF-8 are honored; anything else is
        decoded as ANSI (Latin-1, a lossless 1:1 byte map).

        Supported value layouts: "name"="string" (unescaping \\ and \"), @= default value,
        dword:HEX8, hex: (REG_BINARY), hex(2): (REG_EXPAND_SZ, UTF-16LE with trailing NUL),
        hex(7): (REG_MULTI_SZ, UTF-16LE NUL-separated, double-NUL terminated; trailing empty
        strings are indistinguishable from the terminator and are dropped - documented),
        hex(b): (REG_QWORD, 8 bytes little-endian), and generic hex(X): captured as raw bytes
        with Kind 'Unknown'. Backslash line continuations are honored on hex data lines only.
        Comment lines require ';' as the first non-whitespace character.

        Rejected with a terminating error: REGEDIT4 exports (re-export as v5), deletion syntax
        ([-key] sections and "name"=- values), and sections outside HKEY_LOCAL_MACHINE.

    .PARAMETER Path
        Path to the .reg file to parse.

    .OUTPUTS
        System.Collections.Hashtable. @{ Tree = <hashtable>; Provenance = <hashtable> }.

    .EXAMPLE
        $baseline = ConvertFrom-RegFile -Path .\dc-baseline.reg
        $baseline.Tree['SYSTEM\CurrentControlSet\Services\W32Time\Config']['AnnounceFlags'].Data
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    # Literal @{} initializers use culture-aware case-insensitivity; the tree contract
    # requires OrdinalIgnoreCase (registry semantics), hence the explicit comparer.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    # Scans a double-quoted token starting at $Start (the opening quote); regedit escapes are
    # limited to \\ and \" but any backslash-escaped character is taken literally (lenient).
    function Read-QuotedString {
        param([string]$Text, [int]$Start, [int]$LineNumber)
        $sb = New-Object System.Text.StringBuilder
        $i = $Start + 1
        while ($i -lt $Text.Length) {
            $c = $Text[$i]
            if ($c -eq '\') {
                if ($i + 1 -ge $Text.Length) {
                    throw "Line ${LineNumber}: dangling escape character at end of quoted string (continuations are not valid inside quoted strings)."
                }
                [void]$sb.Append($Text[$i + 1])
                $i += 2
                continue
            }
            if ($c -eq '"') {
                return @{ Value = $sb.ToString(); NextIndex = $i + 1 }
            }
            [void]$sb.Append($c)
            $i++
        }
        throw "Line ${LineNumber}: unterminated quoted string."
    }

    # Parses 'aa,bb,cc' into byte[]; empty tokens (e.g. a trailing comma before a
    # continuation break) are tolerated and skipped.
    function ConvertFrom-HexByteList {
        param([string]$Text, [int]$LineNumber)
        $list = New-Object 'System.Collections.Generic.List[byte]'
        foreach ($token in $Text.Split(',')) {
            $t = $token.Trim()
            if ($t.Length -eq 0) { continue }
            try {
                $list.Add([System.Convert]::ToByte($t, 16))
            }
            catch {
                throw "Line ${LineNumber}: invalid hex byte token '$t'."
            }
        }
        return , $list.ToArray()
    }

    # Decodes UTF-16LE bytes from a hex(2)/hex(7) payload into a string.
    function ConvertFrom-Utf16Payload {
        param([byte[]]$Bytes, [int]$LineNumber)
        if (($Bytes.Length % 2) -ne 0) {
            throw "Line ${LineNumber}: UTF-16LE payload has an odd byte count ($($Bytes.Length))."
        }
        return [System.Text.Encoding]::Unicode.GetString($Bytes)
    }

    $resolvedPath = $Path
    if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
        $resolvedPath = Join-Path -Path (Get-Location).ProviderPath -ChildPath $resolvedPath
    }
    if (-not [System.IO.File]::Exists($resolvedPath)) {
        throw "Registry baseline file not found: '$resolvedPath'."
    }
    Write-Verbose -Message "Parsing .reg file '$resolvedPath'."

    # -- BOM sniff ------------------------------------------------------------
    $bytes = [System.IO.File]::ReadAllBytes($resolvedPath)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $content = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $content = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    else {
        # No BOM: treat as ANSI. Latin-1 (28591) maps every byte 1:1 and cannot throw.
        $content = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
    }

    $lines = $content -split "\r\n|\n|\r"

    $tree = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    $rawComments = New-Object 'System.Collections.Generic.List[string]'
    $provenance = @{
        SourceDCs     = $null
        Timestamp     = $null
        OsBuilds      = $null
        ModuleVersion = $null
        SchemaVersion = $null
        Pdce          = $null
    }
    $knownProvKeys = @('SourceDCs', 'Timestamp', 'OsBuilds', 'ModuleVersion', 'SchemaVersion', 'Pdce')

    $headerSeen = $false
    $sectionSeen = $false
    $currentPath = $null
    $hklmLong = 'HKEY_LOCAL_MACHINE\'
    $hklmShort = 'HKLM\'

    $i = 0
    while ($i -lt $lines.Count) {
        $lineNo = $i + 1
        $trim = $lines[$i].Trim()
        $i++

        if ($trim.Length -eq 0) { continue }

        # Comments: ';' must be the first non-whitespace character.
        if ($trim[0] -eq ';') {
            $rawComments.Add($trim)
            if (-not $sectionSeen -and $trim -match '^;\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*(.*)$') {
                # Leading '; key: value' provenance comments (before the first section).
                $pKey = $Matches[1]
                $pVal = $Matches[2].Trim()
                foreach ($known in $knownProvKeys) {
                    if ([string]::Equals($known, $pKey, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $provenance[$known] = $pVal
                        break
                    }
                }
            }
            continue
        }

        if (-not $headerSeen) {
            if ($trim -eq 'REGEDIT4') {
                throw "'$resolvedPath' is a REGEDIT4 (ANSI, v4) export. Re-export it as 'Windows Registry Editor Version 5.00'."
            }
            if ($trim -eq 'Windows Registry Editor Version 5.00') {
                $headerSeen = $true
                continue
            }
            throw "Line ${lineNo}: '$resolvedPath' does not start with the required 'Windows Registry Editor Version 5.00' header."
        }

        # -- Section header ---------------------------------------------------
        if ($trim[0] -eq '[') {
            if ($trim[$trim.Length - 1] -ne ']') {
                throw "Line ${lineNo}: malformed section header (missing closing ']'): $trim"
            }
            $keyName = $trim.Substring(1, $trim.Length - 2)
            if ($keyName.Length -gt 0 -and $keyName[0] -eq '-') {
                throw "Line ${lineNo}: key deletion syntax '[-...]' is not allowed in a baseline .reg file."
            }
            if ($keyName.StartsWith($hklmLong, [System.StringComparison]::OrdinalIgnoreCase)) {
                $relative = $keyName.Substring($hklmLong.Length)
            }
            elseif ($keyName.StartsWith($hklmShort, [System.StringComparison]::OrdinalIgnoreCase)) {
                $relative = $keyName.Substring($hklmShort.Length)
            }
            else {
                throw "Line ${lineNo}: section '[$keyName]' is not under HKEY_LOCAL_MACHINE; only HKLM baselines are supported."
            }
            if ($relative.Length -eq 0) {
                throw "Line ${lineNo}: section must name a subkey under HKEY_LOCAL_MACHINE, not the hive root."
            }
            $currentPath = $relative
            if (-not $tree.ContainsKey($currentPath)) {
                $tree[$currentPath] = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
            }
            $sectionSeen = $true
            continue
        }

        # -- Value line -------------------------------------------------------
        if ($null -eq $currentPath) {
            throw "Line ${lineNo}: value line found outside of any [section]: $trim"
        }

        if ($trim[0] -eq '@') {
            $valueName = ''
            $rest = $trim.Substring(1).TrimStart()
        }
        elseif ($trim[0] -eq '"') {
            $parsedName = Read-QuotedString -Text $trim -Start 0 -LineNumber $lineNo
            $valueName = $parsedName.Value
            $rest = $trim.Substring($parsedName.NextIndex).TrimStart()
        }
        else {
            throw "Line ${lineNo}: unrecognized line: $trim"
        }

        if ($rest.Length -eq 0 -or $rest[0] -ne '=') {
            throw "Line ${lineNo}: expected '=' after value name: $trim"
        }
        $data = $rest.Substring(1).Trim()

        if ($data -eq '-') {
            throw "Line ${lineNo}: value deletion syntax (`"name`"=-) is not allowed in a baseline .reg file."
        }

        if ($data.Length -eq 0) {
            throw "Line ${lineNo}: missing data after '=': $trim"
        }

        if ($data[0] -eq '"') {
            # REG_SZ
            $parsedData = Read-QuotedString -Text $data -Start 0 -LineNumber $lineNo
            $tail = $data.Substring($parsedData.NextIndex).Trim()
            if ($tail.Length -ne 0) {
                throw "Line ${lineNo}: unexpected content after closing quote: $tail"
            }
            $tree[$currentPath][$valueName] = @{ Kind = 'String'; Data = $parsedData.Value }
            continue
        }

        if ($data -match '^(?i)dword:([0-9a-fA-F]{1,8})\s*$') {
            $tree[$currentPath][$valueName] = @{ Kind = 'DWord'; Data = [uint32][System.Convert]::ToUInt32($Matches[1], 16) }
            continue
        }

        if ($data -match '^(?i)hex(\([0-9a-fA-F]+\))?:') {
            # Backslash line continuations are valid on hex data lines only.
            while ($data.EndsWith('\')) {
                if ($i -ge $lines.Count) {
                    throw "Line ${lineNo}: hex data continuation '\' at end of file."
                }
                $data = $data.Substring(0, $data.Length - 1).TrimEnd() + $lines[$i].Trim()
                $i++
            }
            if (-not ($data -match '^(?i)hex(?:\(([0-9a-fA-F]+)\))?:(.*)$')) {
                throw "Line ${lineNo}: malformed hex data: $data"
            }
            $typeCode = ''
            if ($Matches.ContainsKey(1) -and $null -ne $Matches[1]) {
                $typeCode = $Matches[1].ToLowerInvariant()
            }
            $payload = ConvertFrom-HexByteList -Text $Matches[2] -LineNumber $lineNo

            if ($typeCode -eq '') {
                # hex: REG_BINARY
                $tree[$currentPath][$valueName] = @{ Kind = 'Binary'; Data = $payload }
            }
            elseif ($typeCode -eq '2') {
                # hex(2): REG_EXPAND_SZ - UTF-16LE, strip the single trailing NUL terminator.
                $s = ConvertFrom-Utf16Payload -Bytes $payload -LineNumber $lineNo
                if ($s.Length -gt 0 -and $s[$s.Length - 1] -eq [char]0) {
                    $s = $s.Substring(0, $s.Length - 1)
                }
                $tree[$currentPath][$valueName] = @{ Kind = 'ExpandString'; Data = $s }
            }
            elseif ($typeCode -eq '7') {
                # hex(7): REG_MULTI_SZ - NUL-separated strings, double-NUL terminated.
                # Trailing empty strings are indistinguishable from the terminator; dropped.
                $s = ConvertFrom-Utf16Payload -Bytes $payload -LineNumber $lineNo
                $parts = $s.Split([char]0)
                $end = $parts.Length
                while ($end -gt 0 -and $parts[$end - 1].Length -eq 0) { $end-- }
                [string[]]$strings = @()
                if ($end -gt 0) { [string[]]$strings = $parts[0..($end - 1)] }
                $tree[$currentPath][$valueName] = @{ Kind = 'MultiString'; Data = $strings }
            }
            elseif ($typeCode -eq 'b') {
                # hex(b): REG_QWORD - 8 bytes little-endian.
                if ($payload.Length -ne 8) {
                    throw "Line ${lineNo}: REG_QWORD (hex(b)) requires exactly 8 bytes, got $($payload.Length)."
                }
                $tree[$currentPath][$valueName] = @{ Kind = 'QWord'; Data = [uint64][System.BitConverter]::ToUInt64($payload, 0) }
            }
            else {
                # Generic hex(X): raw bytes, kind not modeled -> 'Unknown'.
                $tree[$currentPath][$valueName] = @{ Kind = 'Unknown'; Data = $payload }
            }
            continue
        }

        throw "Line ${lineNo}: unrecognized data format: $data"
    }

    if (-not $headerSeen) {
        throw "'$resolvedPath' does not contain the required 'Windows Registry Editor Version 5.00' header."
    }

    $provenance['Raw'] = [string[]]$rawComments.ToArray()
    return @{ Tree = $tree; Provenance = $provenance }
}
