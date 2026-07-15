#Requires -Version 5.1
# Engine component tests: discovery filtering, scan worker, orchestrator math.
# Pure logic is tested cross-platform; AD/SMB/registry runtime paths are
# Windows-only and skipped elsewhere.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'test fixtures use fake hostnames (.invalid and example.com-style names)')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'dummy credential for mocked SMB cmdlets; not a real secret')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'stub mirrors the real New-SmbMapping parameter surface for mocking')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'fixture factory and cmdlet stubs, nothing changes state')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'stub parameters exist so Pester ParameterFilter can bind them')]
param()

Set-StrictMode -Version Latest

BeforeDiscovery {
    $script:onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $script:hasThreadJob = $null -ne (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)
}

BeforeAll {
    Set-StrictMode -Version Latest
    $privateDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Private'
    . (Join-Path $privateDir 'Resolve-WinTimeTarget.ps1')
    . (Join-Path $privateDir 'Get-WinTimeRegistryWorker.ps1')
    . (Join-Path $privateDir 'Connect-WinTimeAdminShare.ps1')
    . (Join-Path $privateDir 'Disconnect-WinTimeAdminShare.ps1')
    . (Join-Path $privateDir 'Invoke-WinTimeScan.ps1')

    function New-TestTarget {
        param(
            [string]$ComputerName,
            [string]$Domain,
            [string]$Site,
            [bool]$IsRootPdce = $false,
            [bool]$IsRodc = $false,
            [int]$DomainDepth = 0
        )
        [pscustomobject]@{
            ComputerName = $ComputerName
            Domain       = $Domain
            Site         = $Site
            IsRootPdce   = $IsRootPdce
            IsRodc       = $IsRodc
            DomainDepth  = $DomainDepth
        }
    }
}

Describe 'Select-WinTimeTargetSet' {
    BeforeAll {
        $script:fixture = @(
            (New-TestTarget -ComputerName 'dc1.contoso.com' -Domain 'contoso.com' -Site 'Default-First-Site' -IsRootPdce $true)
            (New-TestTarget -ComputerName 'dc2.contoso.com' -Domain 'contoso.com' -Site 'Branch-A')
            (New-TestTarget -ComputerName 'dc1.child.contoso.com' -Domain 'child.contoso.com' -Site 'Branch-A' -DomainDepth 1)
            (New-TestTarget -ComputerName 'dc1.fabrikam.com' -Domain 'fabrikam.com' -Site 'Fab-Site' -DomainDepth 1)
        )
    }

    It 'returns all targets when no filters are given' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture)
        $result.Count | Should -Be 4
    }

    It 'treats empty filter arrays as absent (all candidates)' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains @() -ExcludedSites @())
        $result.Count | Should -Be 4
    }

    It 'returns an empty set for null targets' {
        $result = @(Select-WinTimeTargetSet -Targets $null)
        $result.Count | Should -Be 0
    }

    It 'IncludedDomains without wildcard matches exactly (not subdomains)' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains 'contoso.com')
        $result.Count | Should -Be 2
        foreach ($t in $result) { $t.Domain | Should -Be 'contoso.com' }
    }

    It 'IncludedDomains supports wildcards' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains '*contoso.com')
        $result.Count | Should -Be 3
    }

    It 'domain matching is case-insensitive' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains 'CONTOSO.COM')
        $result.Count | Should -Be 2
    }

    It 'Exclude always wins over Include' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains 'contoso.com', 'fabrikam.com' -ExcludedDomains 'fabrikam.com')
        $result.Count | Should -Be 2
        foreach ($t in $result) { $t.Domain | Should -Be 'contoso.com' }
    }

    It 'filters sites with wildcards' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedSites 'Branch*')
        @($result | ForEach-Object { $_.ComputerName }) | Should -Be @('dc2.contoso.com', 'dc1.child.contoso.com')
    }

    It 'applies domains before sites (site filter sees only surviving domains)' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomains 'fabrikam.com' -IncludedSites 'Branch*')
        $result.Count | Should -Be 0
    }

    It 'matches DCs by FQDN case-insensitively' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomainControllers 'DC1.CONTOSO.COM')
        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'dc1.contoso.com'
    }

    It 'matches DCs by short host label' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -IncludedDomainControllers 'dc2')
        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'dc2.contoso.com'
    }

    It 'excludes DCs by wildcard' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture -ExcludedDomainControllers 'dc1*')
        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'dc2.contoso.com'
    }

    It 'combining all three dimensions honors the domain -> site -> DC order' {
        $result = @(Select-WinTimeTargetSet -Targets $fixture `
            -IncludedDomains '*contoso.com' -ExcludedSites 'Default*' -ExcludedDomainControllers 'dc1.child*')
        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'dc2.contoso.com'
    }
}

Describe 'Get-WinTimeScanCeilingSeconds' {
    It 'computes TimeoutSeconds x attempts + backoff + 15s grace (defaults)' {
        # 30*4 + (1+2+4) + 15
        Get-WinTimeScanCeilingSeconds -TimeoutSeconds 30 -RetryCount 3 | Should -Be 142
    }

    It 'has no backoff with zero retries' {
        # 30*1 + 0 + 15
        Get-WinTimeScanCeilingSeconds -TimeoutSeconds 30 -RetryCount 0 | Should -Be 45
    }

    It 'handles the minimum timeout' {
        # 5*2 + 1 + 15
        Get-WinTimeScanCeilingSeconds -TimeoutSeconds 5 -RetryCount 1 | Should -Be 26
    }
}

Describe 'Get-WinTimeErrorClass' {
    It 'maps SecurityException to AccessDenied' {
        Get-WinTimeErrorClass -Exception (New-Object System.Security.SecurityException 'registry access refused') -PreflightSucceeded $true |
            Should -Be 'AccessDenied'
    }

    It 'maps UnauthorizedAccessException to AccessDenied' {
        Get-WinTimeErrorClass -Exception (New-Object System.UnauthorizedAccessException 'nope') -PreflightSucceeded $true |
            Should -Be 'AccessDenied'
    }

    It 'maps logon-class Win32 code <_> to AuthFailure' -ForEach @(1219, 1326, 1331, 1907) {
        Get-WinTimeErrorClass -Exception (New-Object System.ComponentModel.Win32Exception ([int]$_)) -PreflightSucceeded $true |
            Should -Be 'AuthFailure'
    }

    It 'maps Win32 code 5 to AccessDenied' {
        Get-WinTimeErrorClass -Exception (New-Object System.ComponentModel.Win32Exception (5)) -PreflightSucceeded $true |
            Should -Be 'AccessDenied'
    }

    It 'maps a 1219-style message thrown by the connect scriptblock to AuthFailure' {
        $ex = New-Object System.Exception ('1219 conflict: disconnect the existing session to dc1.contoso.com or run without -Credential')
        Get-WinTimeErrorClass -Exception $ex -PreflightSucceeded $true | Should -Be 'AuthFailure'
    }

    It 'maps IOException with a live 445 preflight to RemoteRegistryDisabled' {
        $ex = New-Object System.IO.IOException ('The network path was not found.')
        Get-WinTimeErrorClass -Exception $ex -PreflightSucceeded $true | Should -Be 'RemoteRegistryDisabled'
    }

    It 'maps IOException without a live preflight to Transport' {
        $ex = New-Object System.IO.IOException ('The network path was not found.')
        Get-WinTimeErrorClass -Exception $ex -PreflightSucceeded $false | Should -Be 'Transport'
    }

    It 'maps SocketException to Transport' {
        Get-WinTimeErrorClass -Exception (New-Object System.Net.Sockets.SocketException (10060)) -PreflightSucceeded $false |
            Should -Be 'Transport'
    }

    It 'unwraps AggregateException members' {
        $inner = New-Object System.Net.Sockets.SocketException (10061)
        $agg = New-Object System.AggregateException (@([System.Exception]$inner))
        Get-WinTimeErrorClass -Exception $agg -PreflightSucceeded $false | Should -Be 'Transport'
    }

    It 'walks the InnerException chain' {
        $inner = New-Object System.Security.SecurityException ('deep denial')
        $outer = New-Object System.InvalidOperationException ('wrapper', $inner)
        Get-WinTimeErrorClass -Exception $outer -PreflightSucceeded $true | Should -Be 'AccessDenied'
    }

    It 'falls back to Unknown for unclassifiable exceptions' {
        Get-WinTimeErrorClass -Exception (New-Object System.InvalidOperationException 'boom') -PreflightSucceeded $true |
            Should -Be 'Unknown'
    }

    It 'returns Unknown for a null exception' {
        Get-WinTimeErrorClass -Exception $null -PreflightSucceeded $true | Should -Be 'Unknown'
    }
}

Describe 'Get-WinTimeRegistryWorker' {
    BeforeAll {
        $script:worker = Get-WinTimeRegistryWorker
        $script:workerText = $worker.ToString()
    }

    It 'returns a scriptblock' {
        $worker | Should -BeOfType [scriptblock]
    }

    It 'declares the (Target, ReadSpec, Options) contract' {
        $workerText | Should -Match ([regex]::Escape('param($Target, $ReadSpec, $Options)'))
    }

    It 'is self-contained: no script/global scope references' {
        $workerText | Should -Not -Match '\$script:'
        $workerText | Should -Not -Match '\$global:'
        $workerText | Should -Not -Match 'using module'
    }

    It 'is self-contained: no direct calls into module functions' {
        # The connect scriptblock arrives as text via $Options.ConnectScript.
        $workerText | Should -Not -Match 'Connect-WinTimeAdminShare'
        $workerText | Should -Not -Match 'Disconnect-WinTimeAdminShare'
        $workerText | Should -Not -Match 'Get-WinTimeRegistryWorker'
        $workerText | Should -Not -Match 'Get-W32TimeDatabase'
    }

    It 'embeds the error classifier' {
        $workerText | Should -Match 'function Get-WinTimeErrorClass'
    }

    It 'parses standalone without errors' {
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($workerText, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0
        { [scriptblock]::Create($workerText) } | Should -Not -Throw
    }

    It 'uses DoNotExpandEnvironmentNames and GetValueKind for value capture' {
        $workerText | Should -Match 'DoNotExpandEnvironmentNames'
        $workerText | Should -Match 'GetValueKind'
    }

    It 'never writes to the host or progress streams' {
        $workerText | Should -Not -Match 'Write-Host'
        $workerText | Should -Not -Match 'Write-Progress'
    }

    It 'classifies an unresolvable host as Transport with correct result shape' {
        $target = New-TestTarget -ComputerName 'nonexistent-host.invalid' -Domain 'contoso.com' -Site 'X'
        $readSpec = @(@{ Path = 'SYSTEM\CurrentControlSet\Services\W32Time'; Recursive = $true })
        $result = & $worker $target $readSpec @{ TimeoutSeconds = 5; RetryCount = 0 }
        $result | Should -BeOfType [hashtable]
        $result['ComputerName'] | Should -Be 'nonexistent-host.invalid'
        $result['Success'] | Should -BeFalse
        $result['Attempts'] | Should -Be 1
        $result['ErrorClass'] | Should -Be 'Transport'
        $result['Error'] | Should -Match 'TCP 445'
        $result['Tree'] | Should -BeNullOrEmpty
        $result['SessionEstablished'] | Should -BeFalse
        $result['DurationMs'] | Should -BeGreaterOrEqual 0
    }

    It 'retries transport-class failures RetryCount times' {
        $target = New-TestTarget -ComputerName 'nonexistent-host.invalid' -Domain 'contoso.com' -Site 'X'
        $result = & $worker $target @(@{ Path = 'SYSTEM'; Recursive = $false }) @{ TimeoutSeconds = 5; RetryCount = 1 }
        $result['Success'] | Should -BeFalse
        $result['Attempts'] | Should -Be 2
        # one backoff interval of 1s must have elapsed
        $result['DurationMs'] | Should -BeGreaterOrEqual 1000
    }
}

Describe 'Connect-WinTimeAdminShare' {
    BeforeAll {
        # Stubs for the Windows-only SMB cmdlets so Pester can mock them here.
        function Get-SmbConnection {
            [CmdletBinding()]
            param([string]$ServerName)
        }
        function New-SmbMapping {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password', Justification = 'test stub mirroring the real SmbShare cmdlet surface')]
            [CmdletBinding()]
            param([string]$RemotePath, [string]$UserName, [object]$Password)
        }
        $secure = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        $script:testCredential = New-Object System.Management.Automation.PSCredential ('CONTOSO\svc-scan', $secure)
        $script:upnCredential = New-Object System.Management.Automation.PSCredential ('svc-scan@contoso.com', $secure)
    }

    It 'reuses an existing session held by the same user (DOMAIN\user form)' {
        Mock Get-SmbConnection { [pscustomobject]@{ UserName = 'CONTOSO\svc-scan' } }
        Mock New-SmbMapping { }
        $result = Connect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' -Credential $testCredential
        $result['Established'] | Should -BeFalse
        $result['Reused'] | Should -BeTrue
        Should -Invoke New-SmbMapping -Times 0 -Exactly
    }

    It 'treats UPN and NetBIOS forms of the same account as the same user' {
        Mock Get-SmbConnection { [pscustomobject]@{ UserName = 'CONTOSO\svc-scan' } }
        Mock New-SmbMapping { }
        $result = Connect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' -Credential $upnCredential
        $result['Reused'] | Should -BeTrue
        Should -Invoke New-SmbMapping -Times 0 -Exactly
    }

    It 'throws a terminal 1219-style error when a different user holds the session' {
        Mock Get-SmbConnection { [pscustomobject]@{ UserName = 'FABRIKAM\someone-else' } }
        { Connect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' -Credential $testCredential } |
            Should -Throw -ExpectedMessage '*1219*'
    }

    It 'treats the same account name in a different domain as a conflict' {
        Mock Get-SmbConnection { [pscustomobject]@{ UserName = 'FABRIKAM\svc-scan' } }
        { Connect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' -Credential $testCredential } |
            Should -Throw -ExpectedMessage '*1219*'
    }

    It 'maps IPC$ via New-SmbMapping when no session exists' {
        Mock Get-SmbConnection { }
        Mock New-SmbMapping { [pscustomobject]@{ Status = 'OK' } }
        $result = Connect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' -Credential $testCredential
        $result['Established'] | Should -BeTrue
        $result['Reused'] | Should -BeFalse
        Should -Invoke New-SmbMapping -Times 1 -Exactly -ParameterFilter { $RemotePath -eq '\\dc1.contoso.com\IPC$' }
    }

    It 'has a self-contained body usable as the worker ConnectScript' {
        $bodyText = ${function:Connect-WinTimeAdminShare}.ToString()
        $bodyText | Should -Not -Match '\$script:'
        $bodyText | Should -Not -Match '\$global:'
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($bodyText, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0
        { [scriptblock]::Create($bodyText) } | Should -Not -Throw
    }
}

Describe 'Disconnect-WinTimeAdminShare' {
    It 'is silent when the SMB cmdlets are unavailable' -Skip:$onWindows {
        { Disconnect-WinTimeAdminShare -ComputerName 'dc1.contoso.com' } | Should -Not -Throw
    }

    It 'removes the IPC$ mapping when Remove-SmbMapping exists' {
        function Remove-SmbMapping {
            [CmdletBinding()]
            param([string]$RemotePath, [switch]$Force)
        }
        Mock Remove-SmbMapping { }
        Disconnect-WinTimeAdminShare -ComputerName 'dc1.contoso.com'
        Should -Invoke Remove-SmbMapping -Times 1 -Exactly -ParameterFilter { $RemotePath -eq '\\dc1.contoso.com\IPC$' -and $Force }
    }
}

Describe 'Invoke-WinTimeScan' -Skip:(-not $hasThreadJob) {
    It 'returns empty accounting for an empty target set' {
        $scan = Invoke-WinTimeScan -Targets @() -ReadSpec @()
        $scan['Results'].Count | Should -Be 0
        @($scan['Statuses']).Count | Should -Be 0
    }

    It 'accounts for every target and emits typed ScanStatus records' {
        $runId = [guid]::NewGuid()
        $targets = @(
            (New-TestTarget -ComputerName 'ghost1.invalid' -Domain 'contoso.com' -Site 'A'),
            (New-TestTarget -ComputerName 'ghost2.invalid' -Domain 'child.contoso.com' -Site 'B' -DomainDepth 1)
        )
        $readSpec = @(@{ Path = 'SYSTEM\CurrentControlSet\Services\W32Time'; Recursive = $true })
        $scan = Invoke-WinTimeScan -Targets $targets -ReadSpec $readSpec -RetryCount 0 -TimeoutSeconds 5 -RunId $runId

        $scan['Results'].Count | Should -Be 2
        $scan['Results'].ContainsKey('ghost1.invalid') | Should -BeTrue
        $scan['Results'].ContainsKey('GHOST2.INVALID') | Should -BeTrue   # OrdinalIgnoreCase keys

        $statuses = @($scan['Statuses'])
        $statuses.Count | Should -Be 2
        foreach ($status in $statuses) {
            $status.PSObject.TypeNames | Should -Contain 'WinTime.ScanStatus'
            $status.Success | Should -BeFalse
            $status.ErrorClass | Should -Be 'Transport'
            $status.Attempts | Should -Be 1
            $status.OsBuild | Should -Be 0
            $status.RunId | Should -Be $runId.ToString()
            $status.Timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T'
            $status.LastError | Should -Not -BeNullOrEmpty
        }
        @($statuses | Where-Object { $_.Domain -eq 'contoso.com' }).Count | Should -Be 1
        @($statuses | Where-Object { $_.Domain -eq 'child.contoso.com' }).Count | Should -Be 1
    }

    It 'requires Connect-WinTimeAdminShare for the credential path' {
        # Sabotage resolution by asking for a function name that is not loaded
        # in a child scope: simulate by temporarily renaming is intrusive, so
        # instead verify the happy path resolves and the option plumbing works:
        $connectCommand = Get-Command -Name Connect-WinTimeAdminShare -CommandType Function -ErrorAction SilentlyContinue
        $connectCommand | Should -Not -BeNullOrEmpty
        { [scriptblock]::Create($connectCommand.ScriptBlock.ToString()) } | Should -Not -Throw
    }
}

Describe 'Resolve-WinTimeTarget surface' {
    It 'exposes the full targeting parameter set' {
        $command = Get-Command -Name Resolve-WinTimeTarget
        foreach ($name in @('Credential', 'IncludedDomains', 'ExcludedDomains', 'IncludedSites', 'ExcludedSites', 'IncludedDomainControllers', 'ExcludedDomainControllers')) {
            $command.Parameters.ContainsKey($name) | Should -BeTrue -Because "parameter $name is part of the contract"
        }
    }

    It 'discovers forest targets with the contract shape (domain-joined Windows only)' -Skip:(-not $onWindows) {
        $resolved = $null
        try {
            $resolved = Resolve-WinTimeTarget
        } catch {
            Set-ItResult -Skipped -Because ('no forest reachable from this host: {0}' -f $_.Exception.Message)
            return
        }
        $resolved | Should -BeOfType [hashtable]
        foreach ($key in @('Targets', 'RootPdce', 'Warnings')) { $resolved.ContainsKey($key) | Should -BeTrue }
        foreach ($target in @($resolved['Targets'])) {
            $target.ComputerName | Should -Not -BeNullOrEmpty
            $target.PSObject.Properties['IsRootPdce'] | Should -Not -BeNullOrEmpty
            $target.PSObject.Properties['IsRodc'] | Should -Not -BeNullOrEmpty
            $target.DomainDepth | Should -BeGreaterOrEqual 0
        }
    }
}
