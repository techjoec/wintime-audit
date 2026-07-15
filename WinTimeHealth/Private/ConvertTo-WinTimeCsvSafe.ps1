function ConvertTo-WinTimeCsvSafe {
    <#
    .SYNOPSIS
    Projects WinTime records to injection-safe CSV text lines.

    .DESCRIPTION
    Flattens each input record to an ordered [pscustomobject] restricted to the
    requested columns, then serializes via ConvertTo-Csv -NoTypeInformation and
    returns the resulting text lines (header first).

    Field handling (DESIGN section 10, report safety):
    - Arrays (REG_MULTI_SZ Data/Expected) are joined with '|'.
    - Hashtable data (HealthRecord Data) flattens to compact JSON (depth 6).
    - Numbers render with InvariantCulture; DateTime/DateTimeOffset as ISO-8601.
    - Every string field is guarded against OWASP CSV formula injection and
      terminal/control-character injection: every C0 control character
      (0x00-0x1F) and DEL (0x7F) is stripped (CR, LF and TAB become a space,
      the rest are removed outright), and a field whose first character is
      '=', '+', '-' or '@', OR that contained any control character, is
      prefixed with a single quote.

    .PARAMETER InputObject
    The records to project. May be null or empty; a header-only line is still
    produced so report files stay well-formed.

    .PARAMETER ColumnOrder
    Column (property) names in output order. Properties missing from a record
    render as empty fields.

    .OUTPUTS
    System.String. CSV text lines; the caller joins and writes them via
    Write-WinTimeReportFile.

    .EXAMPLE
    $lines = ConvertTo-WinTimeCsvSafe -InputObject $records -ColumnOrder 'Server','ValueName','Data'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ColumnOrder
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    # Renders one leaf value to text. Guard=$true marks string-typed content
    # that must additionally pass the formula-injection guard below.
    $formatLeaf = {
        param($Value)
        if ($null -eq $Value) { return @{ Text = ''; Guard = $false } }
        if ($Value -is [string]) { return @{ Text = $Value; Guard = $true } }
        if ($Value -is [System.Collections.IDictionary]) {
            # HealthRecord Data contract: hashtable flattens to compact JSON.
            return @{ Text = (ConvertTo-Json -InputObject $Value -Compress -Depth 6); Guard = $true }
        }
        if ($Value -is [datetime]) { return @{ Text = $Value.ToString('o', $invariant); Guard = $false } }
        if ($Value -is [System.DateTimeOffset]) { return @{ Text = $Value.ToString('o', $invariant); Guard = $false } }
        if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
            # REG_MULTI_SZ projection: join elements with '|'.
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($element in $Value) {
                if ($null -eq $element) {
                    $parts.Add('')
                } elseif ($element -is [string]) {
                    $parts.Add($element)
                } else {
                    $parts.Add([string]::Format($invariant, '{0}', $element))
                }
            }
            return @{ Text = ($parts -join '|'); Guard = $true }
        }
        # Numbers, booleans, guids, enums: invariant scalar rendering.
        return @{ Text = [string]::Format($invariant, '{0}', $Value); Guard = $false }
    }

    # OWASP CSV formula-injection guard: control chars to spaces, then
    # single-quote-prefix fields led by '=', '+', '-' or '@'.
    # Every C0 control character (0x00-0x1F, which includes CR/LF/TAB) and
    # DEL (0x7F) is replaced with a space - not just CR/LF/TAB - because
    # ValueName/Data/Note are sourced from remote registry reads on the
    # scanned (potentially compromised) DC and could otherwise carry ANSI
    # escape sequences (ESC), BEL, or embedded NULs into the report.
    $sanitize = {
        param([string]$Text)
        $clean = $Text -replace '[\x00-\x1F\x7F]', ' '
        if ($clean.Length -gt 0) {
            $first = $clean[0]
            if ($first -eq '=' -or $first -eq '+' -or $first -eq '-' -or $first -eq '@') {
                $clean = "'" + $clean
            }
        }
        return $clean
    }

    $records = @($InputObject | Where-Object { $null -ne $_ })
    if ($records.Count -eq 0) {
        # Header-only output for empty runs (matches ConvertTo-Csv quoting).
        $headerCells = foreach ($name in $ColumnOrder) { '"' + ($name -replace '"', '""') + '"' }
        return ($headerCells -join ',')
    }

    $projected = foreach ($record in $records) {
        $row = [ordered]@{}
        foreach ($column in $ColumnOrder) {
            $value = $null
            if ($record -is [System.Collections.IDictionary]) {
                if ($record.Contains($column)) { $value = $record[$column] }
            } else {
                $property = $record.PSObject.Properties[$column]
                if ($null -ne $property) { $value = $property.Value }
            }
            $leaf = & $formatLeaf $value
            if ($leaf.Guard) {
                $row[$column] = & $sanitize $leaf.Text
            } else {
                $row[$column] = $leaf.Text
            }
        }
        [pscustomobject]$row
    }

    Write-Verbose ([string]::Format($invariant, 'ConvertTo-WinTimeCsvSafe: projected {0} record(s) into {1} column(s).', $records.Count, $ColumnOrder.Count))
    return ($projected | ConvertTo-Csv -NoTypeInformation)
}
