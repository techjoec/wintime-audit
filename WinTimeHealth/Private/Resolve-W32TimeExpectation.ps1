function Resolve-W32TimeExpectation {
<#
.SYNOPSIS
Resolves the expected (Microsoft-default) value of a W32Time database entry
for a given role and OS build.

.DESCRIPTION
Centralizes role/OS/pdce default resolution (DESIGN section 5). Resolution
order:

  1. Role default from the entry's 'defaults' block:
       Role RootPdce -> defaults.pdce when that key exists, otherwise the DC
                        default; Role Dc -> defaults.dc, falling back to
                        defaults.member when no dc key exists.
  2. The FIRST matching entry of 'defaults_overrides' (build-conditional
     defaults) replaces the role default. An override matches when
     min_build/max_build (both inclusive, either may be absent) bracket
     -OsBuild and its optional role filter matches ('dc' matches both Dc and
     RootPdce; member/standalone never match DC roles). Overrides are only
     applied when the build is known (-OsBuild greater than 0).

Returns @{ Expected = <value or $null>; Source = 'MSDefault';
OsConditional = <bool: entry carries defaults_overrides> }. Callers use
OsConditional to add a note when the build is unknown but the default is
OS-dependent.

.PARAMETER Entry
A key entry hashtable from Get-W32TimeDatabase (fields: defaults,
defaults_overrides, ...).

.PARAMETER Role
Target role: 'Dc' or 'RootPdce'.

.PARAMETER OsBuild
Target CurrentBuildNumber; 0 means unknown (overrides are skipped).

.OUTPUTS
System.Collections.Hashtable

.EXAMPLE
Resolve-W32TimeExpectation -Entry $entry -Role RootPdce -OsBuild 26100

.NOTES
Private helper; not exported. Windows PowerShell 5.1 compatible.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Entry,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Dc', 'RootPdce')]
        [string]$Role,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$OsBuild = 0
    )

    $defaults = @{}
    if ($Entry.ContainsKey('defaults') -and $Entry['defaults'] -is [hashtable]) {
        $defaults = $Entry['defaults']
    }

    # DC default with member fallback (a DC is a domain member; omitted role = member).
    $dcDefault = $null
    if ($defaults.ContainsKey('dc')) { $dcDefault = $defaults['dc'] }
    elseif ($defaults.ContainsKey('member')) { $dcDefault = $defaults['member'] }

    $expected = $dcDefault
    if ($Role -eq 'RootPdce' -and $defaults.ContainsKey('pdce')) {
        $expected = $defaults['pdce']
    }

    $overrides = @()
    $osConditional = $false
    if ($Entry.ContainsKey('defaults_overrides') -and $null -ne $Entry['defaults_overrides']) {
        $overrides = @($Entry['defaults_overrides'])
        $osConditional = ($overrides.Count -gt 0)
    }

    if ($osConditional -and $OsBuild -gt 0) {
        foreach ($override in $overrides) {
            if ($override -isnot [hashtable]) {
                throw "Resolve-W32TimeExpectation: malformed defaults_overrides item (not a mapping) in entry '$($Entry['path'])\$($Entry['value'])'."
            }
            if (-not $override.ContainsKey('value')) {
                throw "Resolve-W32TimeExpectation: defaults_overrides item without 'value' in entry '$($Entry['path'])\$($Entry['value'])'."
            }
            $matchesBuild = $true
            if ($override.ContainsKey('min_build') -and $null -ne $override['min_build']) {
                if ($OsBuild -lt [long]$override['min_build']) { $matchesBuild = $false }
            }
            if ($matchesBuild -and $override.ContainsKey('max_build') -and $null -ne $override['max_build']) {
                if ($OsBuild -gt [long]$override['max_build']) { $matchesBuild = $false }
            }
            if ($matchesBuild -and $override.ContainsKey('role') -and $null -ne $override['role']) {
                # Role filter 'dc' covers both Dc and RootPdce (a root PDCe is a DC);
                # member/standalone filters never match the DC-focused roles here.
                if (-not [string]::Equals([string]$override['role'], 'dc', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $matchesBuild = $false
                }
            }
            if ($matchesBuild) {
                $expected = $override['value']
                break
            }
        }
    }

    return @{
        Expected      = $expected
        Source        = 'MSDefault'
        OsConditional = $osConditional
    }
}
