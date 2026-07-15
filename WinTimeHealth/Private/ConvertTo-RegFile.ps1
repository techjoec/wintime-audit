function ConvertTo-RegFile {
    <#
    .SYNOPSIS
        Writes a registry tree hashtable to a Windows Registry Editor Version 5.00 (.reg) baseline file.

    .DESCRIPTION
        Serializes a registry tree (hashtable keyed by path relative to HKLM, each value a
        hashtable of valueName -> @{ Kind; Data }) into a v5 .reg file:

          - Encoding UTF-16LE with BOM (via [IO.File]::WriteAllText), CRLF line endings.
          - First line is the audit banner comment
            '; WinTimeHealth AUDIT BASELINE - do not merge into a registry', followed by
            '; key: value' provenance comment lines, then the
            'Windows Registry Editor Version 5.00' header.
          - Sections sorted OrdinalIgnoreCase by path; value names sorted OrdinalIgnoreCase
            within each section. The default value (name '') is emitted as '@='.
          - Value layouts: String as "name"="..." (escaping \ and "), DWord as
            dword:xxxxxxxx (lowercase hex), QWord as hex(b): (8 bytes little-endian),
            ExpandString as hex(2): (UTF-16LE plus trailing NUL), MultiString as hex(7):
            (UTF-16LE, NUL-separated, double-NUL terminated), Binary as hex:.
          - Hex byte lists wrap with backslash continuations at ~76 columns with a
            two-space continuation indent (regedit style).

        Kinds 'None' and 'Unknown' cannot be expressed losslessly in a mergeable v5 layout
        and are rejected with a terminating error (baselines contain only documented,
        mergeable value types).

        Note: a MultiString whose last element is an empty string cannot be distinguished
        from the double-NUL terminator by any v5 parser; such trailing empty strings do not
        survive a write/parse roundtrip (empty strings in the middle are preserved).

    .PARAMETER Tree
        Registry tree hashtable: key = path relative to HKLM, value = hashtable of
        valueName -> @{ Kind = <RegistryValueKind name>; Data = <object> }.

    .PARAMETER Path
        Destination file path. The containing directory must already exist.

    .PARAMETER Provenance
        Optional hashtable of provenance metadata written as '; key: value' comment lines.
        Known keys (SourceDCs, Timestamp, OsBuilds, ModuleVersion, SchemaVersion, Pdce) are
        emitted first in that order, then any other keys sorted; a 'Raw' key is ignored
        (it is the parser's echo of all comment lines). Null values are skipped; array
        values are joined with ', '.

    .OUTPUTS
        None.

    .EXAMPLE
        ConvertTo-RegFile -Tree $tree -Path C:\baselines\dc.reg -Provenance @{
            SourceDCs = 'dc1.contoso.com'; Timestamp = '2026-07-11T00:00:00Z' }
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [hashtable]$Tree,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Position = 2)]
        [hashtable]$Provenance
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    # Regedit escapes exactly backslash and double quote inside quoted tokens.
    function Get-EscapedRegString {
        param([string]$Value)
        if ($null -eq $Value) { $Value = '' }
        return $Value.Replace('\', '\\').Replace('"', '\"')
    }

    # Formats a provenance value: arrays joined with ', ', scalars via InvariantCulture.
    function Format-ProvenanceValue {
        param($Value)
        if ($Value -is [string]) { return $Value }
        if ($Value -is [System.Collections.IEnumerable]) {
            $parts = New-Object 'System.Collections.Generic.List[string]'
            foreach ($item in $Value) {
                $parts.Add([System.Convert]::ToString($item, [System.Globalization.CultureInfo]::InvariantCulture))
            }
            return ($parts.ToArray() -join ', ')
        }
        return [System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    # Appends '<Prefix>aa,bb,cc,...' wrapping with trailing '\' at ~76 columns and a
    # two-space continuation indent, regedit style.
    function Add-HexDataLine {
        param(
            [System.Text.StringBuilder]$Builder,
            [string]$Prefix,
            [byte[]]$Bytes,
            [string]$NewLine
        )
        $line = New-Object System.Text.StringBuilder
        [void]$line.Append($Prefix)
        for ($i = 0; $i -lt $Bytes.Length; $i++) {
            $token = $Bytes[$i].ToString('x2', [System.Globalization.CultureInfo]::InvariantCulture)
            if ($i -lt $Bytes.Length - 1) { $token = $token + ',' }
            # Break before this token would push past ~76 cols; require at least one
            # token (or the prefix) already on the line so progress is always made.
            if (($line.Length + $token.Length) -gt 76 -and $line.Length -gt 2) {
                [void]$Builder.Append($line.ToString()).Append('\').Append($NewLine)
                $line = New-Object System.Text.StringBuilder
                [void]$line.Append('  ')
            }
            [void]$line.Append($token)
        }
        [void]$Builder.Append($line.ToString()).Append($NewLine)
    }

    $resolvedPath = $Path
    if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
        $resolvedPath = Join-Path -Path (Get-Location).ProviderPath -ChildPath $resolvedPath
    }

    $nl = "`r`n"
    $sb = New-Object System.Text.StringBuilder

    # -- Banner + provenance comments -----------------------------------------
    [void]$sb.Append('; WinTimeHealth AUDIT BASELINE - do not merge into a registry').Append($nl)
    $knownProvKeys = @('SourceDCs', 'Timestamp', 'OsBuilds', 'ModuleVersion', 'SchemaVersion', 'Pdce')
    if ($null -ne $Provenance) {
        foreach ($known in $knownProvKeys) {
            if ($Provenance.ContainsKey($known) -and $null -ne $Provenance[$known]) {
                [void]$sb.Append('; ').Append($known).Append(': ').Append((Format-ProvenanceValue -Value $Provenance[$known])).Append($nl)
            }
        }
        # Any extra keys (except the parser's Raw echo), sorted for deterministic output.
        $extraKeys = New-Object 'System.Collections.Generic.List[string]'
        foreach ($provKey in $Provenance.Keys) {
            $isKnown = $false
            foreach ($known in $knownProvKeys) {
                if ([string]::Equals($known, [string]$provKey, [System.StringComparison]::OrdinalIgnoreCase)) { $isKnown = $true; break }
            }
            if (-not $isKnown -and -not [string]::Equals('Raw', [string]$provKey, [System.StringComparison]::OrdinalIgnoreCase)) {
                $extraKeys.Add([string]$provKey)
            }
        }
        $extraArray = $extraKeys.ToArray()
        [System.Array]::Sort($extraArray, [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($extraKey in $extraArray) {
            if ($null -ne $Provenance[$extraKey]) {
                [void]$sb.Append('; ').Append($extraKey).Append(': ').Append((Format-ProvenanceValue -Value $Provenance[$extraKey])).Append($nl)
            }
        }
    }

    # -- v5 header ------------------------------------------------------------
    [void]$sb.Append('Windows Registry Editor Version 5.00').Append($nl).Append($nl)

    # -- Sections, sorted OrdinalIgnoreCase -----------------------------------
    $sectionPaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($treeKey in $Tree.Keys) { $sectionPaths.Add([string]$treeKey) }
    $sortedPaths = $sectionPaths.ToArray()
    [System.Array]::Sort($sortedPaths, [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($sectionPath in $sortedPaths) {
        [void]$sb.Append('[HKEY_LOCAL_MACHINE\').Append($sectionPath).Append(']').Append($nl)

        $values = $Tree[$sectionPath]
        if ($null -eq $values) { $values = @{} }
        if ($values -isnot [System.Collections.IDictionary]) {
            throw "Tree section '$sectionPath' is not a hashtable of valueName -> @{ Kind; Data }."
        }

        $valueNames = New-Object 'System.Collections.Generic.List[string]'
        foreach ($valueKey in $values.Keys) { $valueNames.Add([string]$valueKey) }
        $sortedNames = $valueNames.ToArray()
        [System.Array]::Sort($sortedNames, [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($valueName in $sortedNames) {
            $entry = $values[$valueName]
            if ($entry -isnot [System.Collections.IDictionary] -or -not $entry.Contains('Kind')) {
                throw "Value '$sectionPath\$valueName' is not an @{ Kind; Data } hashtable."
            }
            $kind = [string]$entry['Kind']
            $data = $null
            if ($entry.Contains('Data')) { $data = $entry['Data'] }

            # Default value is written as '@='; everything else quoted + escaped.
            if ($valueName -eq '') {
                $lhs = '@='
            }
            else {
                $lhs = '"' + (Get-EscapedRegString -Value $valueName) + '"='
            }

            switch ($kind) {
                'String' {
                    [void]$sb.Append($lhs).Append('"').Append((Get-EscapedRegString -Value ([string]$data))).Append('"').Append($nl)
                }
                'DWord' {
                    $u32 = [System.Convert]::ToUInt32($data, $invariant)
                    [void]$sb.Append($lhs).Append('dword:').Append($u32.ToString('x8', $invariant)).Append($nl)
                }
                'QWord' {
                    $u64 = [System.Convert]::ToUInt64($data, $invariant)
                    Add-HexDataLine -Builder $sb -Prefix ($lhs + 'hex(b):') -Bytes ([System.BitConverter]::GetBytes($u64)) -NewLine $nl
                }
                'ExpandString' {
                    # UTF-16LE payload with a single trailing NUL terminator.
                    $payload = [System.Text.Encoding]::Unicode.GetBytes(([string]$data) + [char]0)
                    Add-HexDataLine -Builder $sb -Prefix ($lhs + 'hex(2):') -Bytes $payload -NewLine $nl
                }
                'MultiString' {
                    # Each string NUL-terminated, then one final NUL => double-NUL end.
                    [string[]]$strings = @()
                    if ($null -ne $data) { [string[]]$strings = @($data) }
                    $joined = New-Object System.Text.StringBuilder
                    foreach ($s in $strings) {
                        if ($null -eq $s) { $s = '' }
                        [void]$joined.Append($s).Append([char]0)
                    }
                    [void]$joined.Append([char]0)
                    $payload = [System.Text.Encoding]::Unicode.GetBytes($joined.ToString())
                    Add-HexDataLine -Builder $sb -Prefix ($lhs + 'hex(7):') -Bytes $payload -NewLine $nl
                }
                'Binary' {
                    [byte[]]$bytes = @()
                    if ($null -ne $data) { [byte[]]$bytes = @($data) }
                    Add-HexDataLine -Builder $sb -Prefix ($lhs + 'hex:') -Bytes $bytes -NewLine $nl
                }
                default {
                    throw "Value '$sectionPath\$valueName' has kind '$kind', which cannot be serialized to a v5 .reg baseline (supported: String, ExpandString, MultiString, DWord, QWord, Binary)."
                }
            }
        }

        # Blank line after each section, regedit style.
        [void]$sb.Append($nl)
    }

    Write-Verbose -Message "Writing .reg baseline '$resolvedPath' ($($sortedPaths.Count) section(s))."

    # UTF-16LE with BOM, identical on Desktop and Core editions.
    $encoding = New-Object System.Text.UnicodeEncoding($false, $true)
    [System.IO.File]::WriteAllText($resolvedPath, $sb.ToString(), $encoding)
}
