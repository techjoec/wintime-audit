function Get-W32TimeDatabase {
<#
.SYNOPSIS
Loads, validates and caches the W32Time registry key database
(Data/W32TimeKeys.yaml).

.DESCRIPTION
Parses the canonical YAML database with ConvertFrom-SimpleYaml, validates it
(schema_version must be 2; every key entry must carry path, value, type, class
and a known compare mode), normalizes optional fields so consumers can rely on
key presence under Set-StrictMode, and returns:

  @{
    SchemaVersion    = [int]     # always 2
    Verified         = [string]  # 'verified' stamp from the YAML
    Keys             = [array]   # entry hashtables: path, value, type, class,
                                 # gpo (@{policy;policy_path;gpo_default} or $null),
                                 # defaults (@{dc;member;standalone;pdce?}),
                                 # defaults_overrides (array or $null),
                                 # compare, units, notes (plus 'os' when present)
    InternalSubtrees = [array]   # @{path;notes} runtime-state subtrees
  }

The default-path load is cached in script (module) scope; subsequent calls
return the cached object.

.PARAMETER Path
Alternate database file to load (testing seam). When omitted the canonical
Data\W32TimeKeys.yaml relative to the module root is used and the result is
cached; explicit -Path loads bypass the cache and are never cached.

.OUTPUTS
System.Collections.Hashtable

.EXAMPLE
$db = Get-W32TimeDatabase
$db['Keys'] | Where-Object { $_['compare'] -eq 'exact' }

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Path
    )

    $useCache = [string]::IsNullOrEmpty($Path)
    if ($useCache) {
        # Guarded read: the cache variable does not exist on first call.
        $cacheVar = Get-Variable -Name W32TimeDatabaseCache -Scope Script -ErrorAction SilentlyContinue
        if ($null -ne $cacheVar -and $null -ne $cacheVar.Value) {
            Write-Verbose 'Get-W32TimeDatabase: returning cached database.'
            return $cacheVar.Value
        }
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        $Path = Join-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'Data') -ChildPath 'W32TimeKeys.yaml'
    }

    Write-Verbose ("Get-W32TimeDatabase: loading '{0}'." -f $Path)
    $raw = ConvertFrom-SimpleYaml -Path $Path

    if (-not $raw.ContainsKey('schema_version')) {
        throw "W32Time database '$Path' has no schema_version field; this module requires schema_version 2."
    }
    $schemaVersion = $raw['schema_version']
    if ($schemaVersion -ne 2) {
        throw "W32Time database '$Path' declares schema_version '$schemaVersion' but this module requires schema_version 2. Upgrade the module and database together."
    }
    if (-not $raw.ContainsKey('keys') -or $null -eq $raw['keys']) {
        throw "W32Time database '$Path' has no 'keys' section."
    }

    $validCompare = @('exact', 'pdce-exempt', 'ignore')
    $requiredFields = @('path', 'value', 'type', 'class', 'compare')
    $offenders = New-Object System.Collections.ArrayList
    $entries = @($raw['keys'])

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        if ($entry -isnot [hashtable]) {
            [void]$offenders.Add(('entry #{0}: not a mapping' -f ($i + 1)))
            continue
        }
        $label = 'entry #{0}' -f ($i + 1)
        if ($entry.ContainsKey('path') -and $null -ne $entry['path'] -and $entry.ContainsKey('value') -and $null -ne $entry['value']) {
            $label = 'entry #{0} ({1}\{2})' -f ($i + 1), $entry['path'], $entry['value']
        }
        foreach ($field in $requiredFields) {
            if (-not $entry.ContainsKey($field) -or $null -eq $entry[$field]) {
                [void]$offenders.Add(("{0}: missing required field '{1}'" -f $label, $field))
            }
        }
        if ($entry.ContainsKey('compare') -and $null -ne $entry['compare']) {
            $cmp = [string]$entry['compare']
            $known = $false
            foreach ($candidate in $validCompare) {
                if ([string]::Equals($cmp, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) { $known = $true; break }
            }
            if (-not $known) {
                [void]$offenders.Add(("{0}: unknown compare value '{1}' (expected one of: {2})" -f $label, $cmp, ($validCompare -join ', ')))
            }
        }
    }
    if ($offenders.Count -gt 0) {
        throw ("W32Time database '{0}' failed validation:`n - {1}" -f $Path, ($offenders.ToArray() -join "`n - "))
    }

    # Normalize optional fields so StrictMode consumers can index them directly.
    $optionalNullFields = @('gpo', 'defaults_overrides', 'units', 'notes', 'os')
    foreach ($entry in $entries) {
        foreach ($field in $optionalNullFields) {
            if (-not $entry.ContainsKey($field)) { $entry[$field] = $null }
        }
        if (-not $entry.ContainsKey('defaults') -or $null -eq $entry['defaults']) { $entry['defaults'] = @{} }
        if ($null -ne $entry['defaults_overrides']) { $entry['defaults_overrides'] = @($entry['defaults_overrides']) }
    }

    $subtrees = @()
    if ($raw.ContainsKey('internal_subtrees') -and $null -ne $raw['internal_subtrees']) {
        $subtrees = @($raw['internal_subtrees'])
    }

    $verified = ''
    if ($raw.ContainsKey('verified') -and $null -ne $raw['verified']) {
        $verified = [string]$raw['verified']
    }

    $database = @{
        SchemaVersion    = [int]$schemaVersion
        Verified         = $verified
        Keys             = $entries
        InternalSubtrees = $subtrees
    }

    if ($useCache) {
        Set-Variable -Name W32TimeDatabaseCache -Scope Script -Value $database
    }
    return $database
}
