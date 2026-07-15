function Select-WinTimeTargetSet {
<#
.SYNOPSIS
Applies the Included*/Excluded* target filters to a set of discovered targets.

.DESCRIPTION
Pure filter helper for Resolve-WinTimeTarget (no Active Directory dependency,
unit-testable). Included* lists build the candidate set (absent or empty
means all candidates); Excluded* lists then remove members - Exclude always
wins. Wildcards are supported via -like (case-insensitive). Filters are
applied in order: domains, then sites, then domain controllers.
Domain-controller patterns match either the FQDN or the short host label.

.PARAMETER Targets
Discovered target objects; the ComputerName, Domain and Site properties are
consulted.

.PARAMETER IncludedDomains
Domain name patterns that build the candidate set (absent = all domains).

.PARAMETER ExcludedDomains
Domain name patterns removed from the candidate set.

.PARAMETER IncludedSites
Site name patterns that build the candidate set (absent = all sites).

.PARAMETER ExcludedSites
Site name patterns removed from the candidate set.

.PARAMETER IncludedDomainControllers
DC name patterns (FQDN or short label) that build the candidate set.

.PARAMETER ExcludedDomainControllers
DC name patterns (FQDN or short label) removed from the candidate set.

.OUTPUTS
The filtered target objects (possibly none).
#>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [object[]]$Targets,
        [SupportsWildcards()][string[]]$IncludedDomains,
        [SupportsWildcards()][string[]]$ExcludedDomains,
        [SupportsWildcards()][string[]]$IncludedSites,
        [SupportsWildcards()][string[]]$ExcludedSites,
        [SupportsWildcards()][string[]]$IncludedDomainControllers,
        [SupportsWildcards()][string[]]$ExcludedDomainControllers
    )

    if ($null -eq $Targets) { return @() }

    function Test-WinTimeAnyPattern {
        param([string[]]$Values, [string[]]$Patterns)
        foreach ($pattern in $Patterns) {
            foreach ($value in $Values) {
                # -like is case-insensitive by default (registry/DNS semantics).
                if ($value -like $pattern) { return $true }
            }
        }
        return $false
    }

    function Get-WinTimeDcMatchValue {
        # A DC pattern may name the FQDN or just the short host label.
        param($Target)
        $fqdn = [string]$Target.ComputerName
        $values = @($fqdn)
        $dot = $fqdn.IndexOf('.')
        if ($dot -gt 0) { $values += $fqdn.Substring(0, $dot) }
        return ,$values
    }

    $current = @($Targets)

    # 1. Domains
    if ($null -ne $IncludedDomains -and $IncludedDomains.Count -gt 0) {
        $current = @($current | Where-Object { Test-WinTimeAnyPattern -Values @([string]$_.Domain) -Patterns $IncludedDomains })
    }
    if ($null -ne $ExcludedDomains -and $ExcludedDomains.Count -gt 0) {
        $current = @($current | Where-Object { -not (Test-WinTimeAnyPattern -Values @([string]$_.Domain) -Patterns $ExcludedDomains) })
    }

    # 2. Sites
    if ($null -ne $IncludedSites -and $IncludedSites.Count -gt 0) {
        $current = @($current | Where-Object { Test-WinTimeAnyPattern -Values @([string]$_.Site) -Patterns $IncludedSites })
    }
    if ($null -ne $ExcludedSites -and $ExcludedSites.Count -gt 0) {
        $current = @($current | Where-Object { -not (Test-WinTimeAnyPattern -Values @([string]$_.Site) -Patterns $ExcludedSites) })
    }

    # 3. Domain controllers
    if ($null -ne $IncludedDomainControllers -and $IncludedDomainControllers.Count -gt 0) {
        $current = @($current | Where-Object { Test-WinTimeAnyPattern -Values (Get-WinTimeDcMatchValue -Target $_) -Patterns $IncludedDomainControllers })
    }
    if ($null -ne $ExcludedDomainControllers -and $ExcludedDomainControllers.Count -gt 0) {
        $current = @($current | Where-Object { -not (Test-WinTimeAnyPattern -Values (Get-WinTimeDcMatchValue -Target $_) -Patterns $ExcludedDomainControllers) })
    }

    # Emit elements (callers collect with @(...)); empty set emits nothing.
    return $current
}

function Resolve-WinTimeTarget {
<#
.SYNOPSIS
Discovers all domain controllers in the current forest and returns filtered
scan targets plus the forest-root PDC emulator.

.DESCRIPTION
Implements DESIGN section 6. One DirectorySearcher query against
CN=Sites,CN=Configuration,(forest root DN) yields every DC (dNSHostName), its
site (RDN two above the server object) and its domain (DC= suffix of
serverReference) in a single round trip - no per-DC RPC binds. RODC tagging
uses one LDAP query per domain (primaryGroupID=521). DomainDepth is computed
from the domain DN component count relative to the forest root DN. The
forest-root PDCe comes from Forest.RootDomain.PdcRoleOwner.Name; a detection
failure is reported via the Warnings output, never a throw.

Windows-only runtime (System.DirectoryServices); requires a domain-joined
host or an explicit -Credential.

.PARAMETER Credential
Optional alternate credential; flows into every DirectoryContext and
DirectoryEntry used for discovery.

.PARAMETER IncludedDomains
Domain name patterns that build the candidate set (absent = all domains).

.PARAMETER ExcludedDomains
Domain name patterns removed from the candidate set (Exclude always wins).

.PARAMETER IncludedSites
Site name patterns that build the candidate set.

.PARAMETER ExcludedSites
Site name patterns removed from the candidate set.

.PARAMETER IncludedDomainControllers
DC name patterns (FQDN or short label) that build the candidate set.

.PARAMETER ExcludedDomainControllers
DC name patterns removed from the candidate set.

.OUTPUTS
hashtable with keys:
  Targets  - array of [pscustomobject] @{ ComputerName; Domain; Site;
             IsRootPdce; IsRodc; DomainDepth } (filtered)
  RootPdce - forest-root PDCe FQDN, or $null when detection failed
  Warnings - string[] of non-fatal discovery problems (PDCe/RODC failures,
             skipped stale server objects, ...)
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [System.Management.Automation.PSCredential]$Credential,
        [SupportsWildcards()][string[]]$IncludedDomains,
        [SupportsWildcards()][string[]]$ExcludedDomains,
        [SupportsWildcards()][string[]]$IncludedSites,
        [SupportsWildcards()][string[]]$ExcludedSites,
        [SupportsWildcards()][string[]]$IncludedDomainControllers,
        [SupportsWildcards()][string[]]$ExcludedDomainControllers
    )

    function Split-WinTimeDn {
        # Splits a distinguished name into components, honoring backslash escapes.
        param([string]$DistinguishedName)
        $parts = New-Object System.Collections.Generic.List[string]
        $builder = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $DistinguishedName.Length; $i++) {
            $ch = $DistinguishedName[$i]
            if ($ch -eq '\' -and ($i + 1) -lt $DistinguishedName.Length) {
                $null = $builder.Append($ch)
                $i++
                $null = $builder.Append($DistinguishedName[$i])
                continue
            }
            if ($ch -eq ',') {
                $parts.Add($builder.ToString().Trim())
                $null = $builder.Clear()
                continue
            }
            $null = $builder.Append($ch)
        }
        if ($builder.Length -gt 0) { $parts.Add($builder.ToString().Trim()) }
        return ,$parts.ToArray()
    }

    function Get-WinTimeRdnValue {
        # 'CN=Site\, One' -> 'Site, One'
        param([string]$Component)
        $idx = $Component.IndexOf('=')
        $value = $Component
        if ($idx -ge 0) { $value = $Component.Substring($idx + 1) }
        return ($value -replace '\\(.)', '$1')
    }

    function Get-WinTimeDomainDnComponentList {
        # Emits the DC= components (normalized) of a DN, in order; callers
        # collect with @(...).
        param([string[]]$Components)
        $dcParts = @()
        foreach ($component in $Components) {
            if ($component -match '^(?i)DC=') {
                $dcParts += ('DC=' + (Get-WinTimeRdnValue -Component $component))
            }
        }
        return $dcParts
    }

    $warnings = New-Object System.Collections.Generic.List[string]
    $networkCredential = $null
    if ($null -ne $Credential) { $networkCredential = $Credential.GetNetworkCredential() }

    # --- forest handle (DESIGN section 6) ---
    $forest = $null
    try {
        if ($null -ne $Credential) {
            $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Credential.UserName, $networkCredential.Password)
        } else {
            $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest')
        }
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($context)
    } catch {
        throw ('forest discovery failed: {0} (Active Directory discovery requires a domain-joined Windows host; pass -Credential for cross-forest use)' -f $_.Exception.Message)
    }

    $rootDomainDns = [string]$forest.RootDomain.Name
    $rootDnParts = @()
    foreach ($label in $rootDomainDns.Split('.')) {
        if (-not [string]::IsNullOrEmpty($label)) { $rootDnParts += ('DC=' + $label) }
    }
    $rootDn = [string]::Join(',', $rootDnParts)

    # Root PDCe: failure is loud (warning) but never fatal - callers disable
    # PdceExempt handling when RootPdce is $null.
    $rootPdce = $null
    try {
        $rootPdce = [string]$forest.RootDomain.PdcRoleOwner.Name
        if ([string]::IsNullOrEmpty($rootPdce)) {
            $rootPdce = $null
            $warnings.Add('forest-root PDCe detection returned an empty name - PdceExempt handling will be disabled')
        }
    } catch {
        $rootPdce = $null
        $warnings.Add(('forest-root PDCe detection failed: {0} - PdceExempt handling will be disabled' -f $_.Exception.Message))
    }

    # --- ONE query against the config NC: every DC + site + domain ---
    $serverRows = New-Object System.Collections.Generic.List[object]
    $searchRoot = $null
    $searcher = $null
    $searchResults = $null
    try {
        $sitesPath = 'LDAP://CN=Sites,CN=Configuration,' + $rootDn
        if ($null -ne $Credential) {
            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry($sitesPath, $Credential.UserName, $networkCredential.Password)
        } else {
            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry($sitesPath)
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot, '(&(objectClass=server)(dNSHostName=*))', ([string[]]@('dNSHostName', 'serverReference', 'distinguishedName')))
        $searcher.PageSize = 1000
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searchResults = $searcher.FindAll()
        foreach ($searchResult in $searchResults) {
            $row = @{ DnsHostName = $null; ServerReference = $null; ServerDn = $null }
            foreach ($pair in @(@('dnshostname', 'DnsHostName'), @('serverreference', 'ServerReference'), @('distinguishedname', 'ServerDn'))) {
                $ldapName = $pair[0]
                $rowKey = $pair[1]
                if ($searchResult.Properties.Contains($ldapName) -and $searchResult.Properties[$ldapName].Count -gt 0) {
                    $row[$rowKey] = [string]$searchResult.Properties[$ldapName][0]
                }
            }
            $serverRows.Add($row)
        }
    } catch {
        throw ('configuration-NC server enumeration failed under {0}: {1}' -f $sitesPath, $_.Exception.Message)
    } finally {
        if ($null -ne $searchResults) { $searchResults.Dispose() }
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $searchRoot) { $searchRoot.Dispose() }
    }

    # --- parse rows: site, domain, depth ---
    $parsedRows = New-Object System.Collections.Generic.List[object]
    $distinctDomains = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $depthWarned = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $serverRows) {
        $dnsHostName = [string]$row['DnsHostName']
        if ([string]::IsNullOrEmpty($dnsHostName)) { continue }

        # Site = RDN two above the server object: CN=<srv>,CN=Servers,CN=<site>,...
        $site = ''
        if (-not [string]::IsNullOrEmpty([string]$row['ServerDn'])) {
            $serverDnParts = Split-WinTimeDn -DistinguishedName ([string]$row['ServerDn'])
            if ($serverDnParts.Count -ge 3 -and $serverDnParts[2] -match '^(?i)CN=') {
                $site = Get-WinTimeRdnValue -Component $serverDnParts[2]
            }
        }
        if ([string]::IsNullOrEmpty($site)) {
            $warnings.Add(('could not determine the site of {0} from its server object DN' -f $dnsHostName))
        }

        # Domain = DC= suffix of serverReference (the computer object DN).
        # Stale server objects without serverReference still become targets
        # (they will report unreachable - surfacing cruft is a feature); the
        # domain is then approximated from the DNS suffix.
        $domainDns = ''
        $domainDnParts = @()
        if (-not [string]::IsNullOrEmpty([string]$row['ServerReference'])) {
            $referenceParts = Split-WinTimeDn -DistinguishedName ([string]$row['ServerReference'])
            $domainDnParts = @(Get-WinTimeDomainDnComponentList -Components $referenceParts)
            $domainLabels = @()
            foreach ($part in $domainDnParts) { $domainLabels += (Get-WinTimeRdnValue -Component $part) }
            $domainDns = [string]::Join('.', $domainLabels)
        }
        if ([string]::IsNullOrEmpty($domainDns)) {
            $dot = $dnsHostName.IndexOf('.')
            if ($dot -gt 0) { $domainDns = $dnsHostName.Substring($dot + 1) }
            $warnings.Add(('server object for {0} has no serverReference (stale metadata?) - domain approximated as ''{1}''' -f $dnsHostName, $domainDns))
            foreach ($label in $domainDns.Split('.')) {
                if (-not [string]::IsNullOrEmpty($label)) { $domainDnParts += ('DC=' + $label) }
            }
        }

        # DomainDepth = DC-component count relative to the forest root DN.
        $domainDn = [string]::Join(',', $domainDnParts)
        $depth = 0
        if ([string]::Equals($domainDn, $rootDn, [System.StringComparison]::OrdinalIgnoreCase)) {
            $depth = 0
        } elseif ($domainDn.EndsWith((',' + $rootDn), [System.StringComparison]::OrdinalIgnoreCase)) {
            $depth = $domainDnParts.Count - $rootDnParts.Count
        } else {
            # Separate tree in the same forest: not on the root DN chain; its
            # DCs sync one hop below the forest root PDCe, approximate as 1.
            $depth = 1
            if ($depthWarned.Add($domainDns)) {
                $warnings.Add(('domain {0} is not on the forest-root DN chain (separate tree) - DomainDepth approximated as 1' -f $domainDns))
            }
        }

        $null = $distinctDomains.Add($domainDns)
        $parsedRows.Add(@{ Dns = $dnsHostName; Domain = $domainDns; Site = $site; Depth = $depth })
    }

    # --- RODC tagging: one LDAP query per domain (primaryGroupID=521) ---
    $rodcNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domainDns in $distinctDomains) {
        $domainRoot = $null
        $rodcSearcher = $null
        $rodcResults = $null
        try {
            $domainPath = 'LDAP://' + $domainDns
            if ($null -ne $Credential) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry($domainPath, $Credential.UserName, $networkCredential.Password)
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry($domainPath)
            }
            $rodcSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainRoot, '(&(objectCategory=computer)(primaryGroupID=521))', ([string[]]@('dNSHostName', 'sAMAccountName')))
            $rodcSearcher.PageSize = 1000
            $rodcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $rodcResults = $rodcSearcher.FindAll()
            foreach ($rodcResult in $rodcResults) {
                if ($rodcResult.Properties.Contains('dnshostname') -and $rodcResult.Properties['dnshostname'].Count -gt 0) {
                    $null = $rodcNames.Add([string]$rodcResult.Properties['dnshostname'][0])
                }
                if ($rodcResult.Properties.Contains('samaccountname') -and $rodcResult.Properties['samaccountname'].Count -gt 0) {
                    # sAMAccountName of a computer object is '<host>$'.
                    $null = $rodcNames.Add(([string]$rodcResult.Properties['samaccountname'][0]).TrimEnd('$'))
                }
            }
        } catch {
            $warnings.Add(('RODC detection failed for domain {0}: {1} - IsRodc will be false there' -f $domainDns, $_.Exception.Message))
        } finally {
            if ($null -ne $rodcResults) { $rodcResults.Dispose() }
            if ($null -ne $rodcSearcher) { $rodcSearcher.Dispose() }
            if ($null -ne $domainRoot) { $domainRoot.Dispose() }
        }
    }

    # --- build canonical target objects ---
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($row in $parsedRows) {
        $fqdn = [string]$row['Dns']
        $shortName = $fqdn
        $dot = $fqdn.IndexOf('.')
        if ($dot -gt 0) { $shortName = $fqdn.Substring(0, $dot) }
        $targets.Add([pscustomobject]@{
            ComputerName = $fqdn
            Domain       = [string]$row['Domain']
            Site         = [string]$row['Site']
            IsRootPdce   = ($null -ne $rootPdce -and [string]::Equals($fqdn, $rootPdce, [System.StringComparison]::OrdinalIgnoreCase))
            IsRodc       = ($rodcNames.Contains($fqdn) -or $rodcNames.Contains($shortName))
            DomainDepth  = [int]$row['Depth']
        })
    }

    $filtered = @(Select-WinTimeTargetSet -Targets $targets.ToArray() `
        -IncludedDomains $IncludedDomains -ExcludedDomains $ExcludedDomains `
        -IncludedSites $IncludedSites -ExcludedSites $ExcludedSites `
        -IncludedDomainControllers $IncludedDomainControllers -ExcludedDomainControllers $ExcludedDomainControllers)

    Write-Verbose ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
        'Resolve-WinTimeTarget: {0} DC(s) discovered, {1} after filtering, {2} warning(s); root PDCe: {3}',
        $targets.Count, $filtered.Count, $warnings.Count, $(if ($null -ne $rootPdce) { $rootPdce } else { '<unknown>' })))

    return @{
        Targets  = $filtered
        RootPdce = $rootPdce
        Warnings = $warnings.ToArray()
    }
}
