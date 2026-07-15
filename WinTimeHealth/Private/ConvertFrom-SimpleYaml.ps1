function ConvertFrom-SimpleYaml {
<#
.SYNOPSIS
Parses the constrained YAML subset used by Data/W32TimeKeys.yaml into nested
hashtables and arrays.

.DESCRIPTION
Deliberately minimal YAML reader with no external dependencies. Supported
syntax (exactly what the W32Time key database uses):

  - comments: full-line and trailing '#' outside quoted strings
  - block mappings indented with spaces (2-space convention)
  - block sequences: '- ' items that are inline flow maps ('- { k: v }'),
    nested block maps ('- path: ...'), or plain scalars
  - one-level inline flow maps '{ k: v, ... }' with plain or quoted keys
  - scalars: decimal integers, hex 0x... (parsed unsigned: [uint32] when the
    value fits, else [uint64]), booleans, null/~, single- and double-quoted
    strings (with '' and \\ \" \n \t \r escapes), plain strings
  - '>-' folded block scalars (newlines folded to single spaces, trailing
    whitespace stripped)

Anything outside this subset (anchors, aliases, tags, multi-document streams,
flow sequences, nested flow collections, other block-scalar styles, tab
indentation) raises a terminating error rather than misparsing.

.PARAMETER Path
Path to the YAML file to parse.

.PARAMETER Content
YAML text to parse directly.

.OUTPUTS
System.Collections.Hashtable

.EXAMPLE
ConvertFrom-SimpleYaml -Path (Join-Path $moduleRoot 'Data\W32TimeKeys.yaml')

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Content')]
        [AllowEmptyString()]
        [string]$Content
    )

    # --- nested helpers (kept inside so the file defines exactly one function) ---

    function Get-IndentWidth {
        param([string]$Line, [int]$LineNumber)
        $i = 0
        while ($i -lt $Line.Length -and $Line[$i] -eq ' ') { $i++ }
        if ($i -lt $Line.Length -and $Line[$i] -eq "`t") {
            throw "SimpleYaml: tab character in indentation at line $LineNumber; only spaces are supported."
        }
        return $i
    }

    # Strips a trailing comment. A '#' starts a comment only at column 0 or when
    # preceded by whitespace, and only outside quoted strings.
    function Get-CommentFreeLine {
        param([string]$Line)
        $inSingle = $false
        $inDouble = $false
        $i = 0
        while ($i -lt $Line.Length) {
            $c = $Line[$i]
            if ($inDouble) {
                if ($c -eq '\') { $i++ }
                elseif ($c -eq '"') { $inDouble = $false }
            }
            elseif ($inSingle) {
                if ($c -eq "'") {
                    if (($i + 1) -lt $Line.Length -and $Line[$i + 1] -eq "'") { $i++ } else { $inSingle = $false }
                }
            }
            else {
                if ($c -eq '"') { $inDouble = $true }
                elseif ($c -eq "'") { $inSingle = $true }
                elseif ($c -eq '#') {
                    if ($i -eq 0) { return '' }
                    $prev = $Line[$i - 1]
                    if ($prev -eq ' ' -or $prev -eq "`t") { return $Line.Substring(0, $i) }
                }
            }
            $i++
        }
        return $Line
    }

    # Advances $State.Index past blank and comment-only lines. True if a
    # significant line remains.
    function Move-ToSignificantLine {
        param([hashtable]$State)
        while ($State['Index'] -lt $State['Count']) {
            $stripped = Get-CommentFreeLine -Line ([string]$State['Lines'][$State['Index']])
            if ($stripped.Trim().Length -gt 0) { return $true }
            $State['Index'] = $State['Index'] + 1
        }
        return $false
    }

    # Comment-stripped view of the current line. Call only after
    # Move-ToSignificantLine returned $true.
    function Get-CurrentLineInfo {
        param([hashtable]$State)
        $lineNumber = $State['Index'] + 1
        $stripped = (Get-CommentFreeLine -Line ([string]$State['Lines'][$State['Index']])).TrimEnd()
        $indent = Get-IndentWidth -Line $stripped -LineNumber $lineNumber
        return @{
            Text       = $stripped
            Body       = $stripped.Substring($indent)
            Indent     = $indent
            LineNumber = $lineNumber
        }
    }

    # Reads a quoted string starting at $Start; returns @{ Value; End } where
    # End is the index just past the closing quote.
    function Read-QuotedString {
        param([string]$Text, [int]$Start, [int]$LineNumber)
        $quote = $Text[$Start]
        $sb = New-Object System.Text.StringBuilder
        $i = $Start + 1
        while ($i -lt $Text.Length) {
            $c = $Text[$i]
            if ($quote -eq '"') {
                if ($c -eq '\') {
                    if (($i + 1) -ge $Text.Length) {
                        throw "SimpleYaml: dangling escape at end of double-quoted string at line $LineNumber."
                    }
                    $n = [string]$Text[$i + 1]
                    switch ($n) {
                        '\' { [void]$sb.Append('\') }
                        '"' { [void]$sb.Append('"') }
                        'n' { [void]$sb.Append("`n") }
                        't' { [void]$sb.Append("`t") }
                        'r' { [void]$sb.Append("`r") }
                        default { throw "SimpleYaml: unsupported escape sequence '\$n' in double-quoted string at line $LineNumber." }
                    }
                    $i += 2
                    continue
                }
                if ($c -eq '"') { return @{ Value = $sb.ToString(); End = $i + 1 } }
            }
            else {
                if ($c -eq "'") {
                    if (($i + 1) -lt $Text.Length -and $Text[$i + 1] -eq "'") {
                        [void]$sb.Append("'")
                        $i += 2
                        continue
                    }
                    return @{ Value = $sb.ToString(); End = $i + 1 }
                }
            }
            [void]$sb.Append($c)
            $i++
        }
        throw "SimpleYaml: unterminated quoted string at line $LineNumber."
    }

    # Converts one scalar token to a typed value.
    function ConvertFrom-YamlScalar {
        param([string]$Text, [int]$LineNumber)
        $t = $Text.Trim()
        if ($t.Length -eq 0) { return $null }
        $first = $t[0]
        if ($first -eq '"' -or $first -eq "'") {
            $parsed = Read-QuotedString -Text $t -Start 0 -LineNumber $LineNumber
            if ($parsed['End'] -ne $t.Length) {
                throw "SimpleYaml: unexpected characters after closing quote at line $LineNumber : '$t'."
            }
            return $parsed['Value']
        }
        if ($first -eq '&' -or $first -eq '*' -or $first -eq '!') {
            throw "SimpleYaml: anchors, aliases and tags are not supported (line $LineNumber): '$t'."
        }
        if ($t -eq 'null' -or $t -eq '~') { return $null }
        if ($t -eq 'true') { return $true }
        if ($t -eq 'false') { return $false }
        if ($t -match '^0[xX][0-9A-Fa-f]+$') {
            # Hex parses unsigned; downcast to [uint32] when it fits (DWORD data).
            $u = [uint64]0
            try { $u = [System.Convert]::ToUInt64($t.Substring(2), 16) }
            catch { throw "SimpleYaml: hex literal out of range at line $LineNumber : '$t'." }
            if ($u -le [uint32]::MaxValue) { return [uint32]$u }
            return $u
        }
        if ($t -match '^-?[0-9]+$') {
            $invariant = [System.Globalization.CultureInfo]::InvariantCulture
            $style = [System.Globalization.NumberStyles]::Integer
            $intVal = 0
            if ([int]::TryParse($t, $style, $invariant, [ref]$intVal)) { return $intVal }
            $longVal = [long]0
            if ([long]::TryParse($t, $style, $invariant, [ref]$longVal)) { return $longVal }
            $ulongVal = [uint64]0
            if ([uint64]::TryParse($t, $style, $invariant, [ref]$ulongVal)) { return $ulongVal }
            throw "SimpleYaml: integer literal out of range at line $LineNumber : '$t'."
        }
        return $t
    }

    # Parses a one-level inline flow map '{ k: v, ... }' (must close on the same line).
    function ConvertFrom-YamlFlowMap {
        param([string]$Text, [int]$LineNumber)
        $t = $Text.Trim()
        if (-not $t.EndsWith('}')) {
            throw "SimpleYaml: inline map must open and close on the same line (line $LineNumber): '$t'."
        }
        $inner = $t.Substring(1, $t.Length - 2)
        $map = @{}
        if ($inner.Trim().Length -eq 0) { return $map }

        # Split on top-level commas, honoring quoted strings; reject nesting.
        $segments = New-Object System.Collections.ArrayList
        $sb = New-Object System.Text.StringBuilder
        $i = 0
        while ($i -lt $inner.Length) {
            $c = $inner[$i]
            if ($c -eq '"' -or $c -eq "'") {
                $q = Read-QuotedString -Text $inner -Start $i -LineNumber $LineNumber
                [void]$sb.Append($inner.Substring($i, $q['End'] - $i))
                $i = $q['End']
                continue
            }
            if ($c -eq '{' -or $c -eq '[') {
                throw "SimpleYaml: nested flow collections are not supported (line $LineNumber)."
            }
            if ($c -eq ',') {
                [void]$segments.Add($sb.ToString())
                $sb = New-Object System.Text.StringBuilder
                $i++
                continue
            }
            [void]$sb.Append($c)
            $i++
        }
        [void]$segments.Add($sb.ToString())

        foreach ($segRaw in $segments) {
            $seg = ([string]$segRaw).Trim()
            if ($seg.Length -eq 0) {
                throw "SimpleYaml: empty entry in inline map at line $LineNumber."
            }
            $key = $null
            $valueText = $null
            if ($seg[0] -eq '"' -or $seg[0] -eq "'") {
                $q = Read-QuotedString -Text $seg -Start 0 -LineNumber $LineNumber
                $key = $q['Value']
                $rest = $seg.Substring($q['End']).TrimStart()
                if ($rest.Length -eq 0 -or $rest[0] -ne ':') {
                    throw "SimpleYaml: expected ':' after quoted key in inline map at line $LineNumber."
                }
                $valueText = $rest.Substring(1).Trim()
            }
            else {
                $m = [regex]::Match($seg, '^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$')
                if (-not $m.Success) {
                    throw "SimpleYaml: cannot parse inline map entry '$seg' at line $LineNumber."
                }
                $key = $m.Groups[1].Value
                $valueText = $m.Groups[2].Value.Trim()
            }
            if ($map.ContainsKey($key)) {
                throw "SimpleYaml: duplicate key '$key' in inline map at line $LineNumber."
            }
            if ($valueText.Length -eq 0) {
                throw "SimpleYaml: missing value for key '$key' in inline map at line $LineNumber."
            }
            $map[$key] = ConvertFrom-YamlScalar -Text $valueText -LineNumber $LineNumber
        }
        return $map
    }

    # Reads a '>-' folded block scalar: lines indented deeper than the key,
    # folded with single spaces, trailing whitespace stripped.
    function Read-FoldedScalar {
        param([hashtable]$State, [int]$KeyIndent, [int]$LineNumber)
        $parts = New-Object System.Collections.ArrayList
        while ($State['Index'] -lt $State['Count']) {
            $raw = [string]$State['Lines'][$State['Index']]
            if ($raw.Trim().Length -eq 0) {
                $State['Index'] = $State['Index'] + 1
                continue
            }
            $indent = Get-IndentWidth -Line $raw -LineNumber ($State['Index'] + 1)
            if ($indent -le $KeyIndent) { break }
            [void]$parts.Add($raw.Trim())
            $State['Index'] = $State['Index'] + 1
        }
        if ($parts.Count -eq 0) {
            throw "SimpleYaml: folded scalar '>-' declared at line $LineNumber has no content."
        }
        return ($parts.ToArray() -join ' ')
    }

    # Parses map entries at exactly $Indent until a shallower line ends the map.
    function Read-BlockMap {
        param([hashtable]$State, [int]$Indent)
        $map = @{}
        while (Move-ToSignificantLine -State $State) {
            $info = Get-CurrentLineInfo -State $State
            if ($info['Indent'] -lt $Indent) { break }
            if ($info['Indent'] -gt $Indent) {
                throw "SimpleYaml: unexpected indentation at line $($info['LineNumber']) (expected $Indent spaces, found $($info['Indent']))."
            }
            $body = [string]$info['Body']
            if ($body.StartsWith('- ')) {
                throw "SimpleYaml: sequence item at line $($info['LineNumber']) where a mapping entry was expected."
            }
            $m = [regex]::Match($body, '^([A-Za-z_][A-Za-z0-9_]*):(?:[ \t]+(.*))?$')
            if (-not $m.Success) {
                throw "SimpleYaml: unsupported syntax at line $($info['LineNumber']): '$body'."
            }
            $key = $m.Groups[1].Value
            if ($map.ContainsKey($key)) {
                throw "SimpleYaml: duplicate mapping key '$key' at line $($info['LineNumber'])."
            }
            $rest = ''
            if ($m.Groups[2].Success) { $rest = $m.Groups[2].Value.Trim() }
            $State['Index'] = $State['Index'] + 1

            if ($rest.Length -eq 0) {
                # Nested structure (or empty value).
                $value = $null
                if (Move-ToSignificantLine -State $State) {
                    $next = Get-CurrentLineInfo -State $State
                    if ($next['Indent'] -gt $Indent) {
                        if (([string]$next['Body']).StartsWith('- ')) {
                            $value = Read-BlockSequence -State $State -Indent $next['Indent']
                        }
                        else {
                            $value = Read-BlockMap -State $State -Indent $next['Indent']
                        }
                    }
                    elseif ($next['Indent'] -eq $Indent -and ([string]$next['Body']).StartsWith('- ')) {
                        $value = Read-BlockSequence -State $State -Indent $Indent
                    }
                }
                $map[$key] = $value
            }
            elseif ($rest -eq '>-') {
                $map[$key] = Read-FoldedScalar -State $State -KeyIndent $Indent -LineNumber $info['LineNumber']
            }
            elseif ($rest[0] -eq '>' -or $rest[0] -eq '|') {
                throw "SimpleYaml: block scalar style '$rest' is not supported (only '>-') at line $($info['LineNumber'])."
            }
            elseif ($rest[0] -eq '{') {
                $map[$key] = ConvertFrom-YamlFlowMap -Text $rest -LineNumber $info['LineNumber']
            }
            elseif ($rest[0] -eq '[') {
                throw "SimpleYaml: flow sequences are not supported (line $($info['LineNumber']))."
            }
            else {
                $map[$key] = ConvertFrom-YamlScalar -Text $rest -LineNumber $info['LineNumber']
            }
        }
        return $map
    }

    # Parses '- ' items at exactly $Indent; returns an array.
    function Read-BlockSequence {
        param([hashtable]$State, [int]$Indent)
        $items = New-Object System.Collections.ArrayList
        while (Move-ToSignificantLine -State $State) {
            $info = Get-CurrentLineInfo -State $State
            if ($info['Indent'] -lt $Indent) { break }
            if ($info['Indent'] -gt $Indent) {
                throw "SimpleYaml: unexpected indentation at line $($info['LineNumber']) (expected $Indent spaces, found $($info['Indent']))."
            }
            $body = [string]$info['Body']
            if (-not $body.StartsWith('- ')) { break }
            $rest = $body.Substring(2).Trim()
            if ($rest.Length -eq 0) {
                throw "SimpleYaml: empty sequence item at line $($info['LineNumber']) is not supported."
            }
            if ($rest[0] -eq '{') {
                [void]$items.Add((ConvertFrom-YamlFlowMap -Text $rest -LineNumber $info['LineNumber']))
                $State['Index'] = $State['Index'] + 1
            }
            elseif ($rest[0] -eq '[') {
                throw "SimpleYaml: flow sequences are not supported (line $($info['LineNumber']))."
            }
            elseif ([regex]::IsMatch($rest, '^[A-Za-z_][A-Za-z0-9_]*:([ \t]|$)')) {
                # Block-map item ('- path: ...'): rewrite '- ' as two spaces and
                # reparse this line as the first entry of a map at Indent+2.
                $State['Lines'][$State['Index']] = (' ' * ($Indent + 2)) + $rest
                [void]$items.Add((Read-BlockMap -State $State -Indent ($Indent + 2)))
            }
            else {
                [void]$items.Add((ConvertFrom-YamlScalar -Text $rest -LineNumber $info['LineNumber']))
                $State['Index'] = $State['Index'] + 1
            }
        }
        return , $items.ToArray()
    }

    # --- main body ---

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $resolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "SimpleYaml: file not found: '$resolved'."
        }
        $text = [System.IO.File]::ReadAllText($resolved)
    }
    else {
        $text = $Content
    }

    $lines = [string[]]($text -split "\r\n|\n|\r")
    $state = @{ Lines = $lines; Count = $lines.Count; Index = 0 }

    if (-not (Move-ToSignificantLine -State $state)) { return @{} }
    $first = Get-CurrentLineInfo -State $state
    if ($first['Indent'] -ne 0) {
        throw "SimpleYaml: top-level content must start at column 0 (line $($first['LineNumber']))."
    }
    if (([string]$first['Body']).StartsWith('- ')) {
        $result = Read-BlockSequence -State $state -Indent 0
    }
    else {
        $result = Read-BlockMap -State $state -Indent 0
    }
    if (Move-ToSignificantLine -State $state) {
        $info = Get-CurrentLineInfo -State $state
        throw "SimpleYaml: unparsed content remaining at line $($info['LineNumber']): '$($info['Body'])'."
    }
    if ($result -is [array]) { return , $result }
    return $result
}
