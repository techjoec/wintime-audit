# WinTimeHealth module manifest (DESIGN.md sections 2 and 12).
@{
    RootModule           = 'WinTimeHealth.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'c52a1d4d-6297-42e1-95dd-f8358f371794'
    Author               = 'wintime-audit contributors'
    CompanyName          = 'wintime-audit'
    Copyright            = '(c) 2026 wintime-audit contributors. MIT License.'
    Description          = 'Audits Windows Time service (W32Time) configuration and live health across a multi-domain Active Directory forest, concurrently, over SMB remote registry (winreg, TCP/445) and SNTP (UDP/123) - no WinRM required. Includes baseline capture to auditable .reg files.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FormatsToProcess     = @('Formats/WinTimeHealth.Format.ps1xml')
    FunctionsToExport    = @(
        'Get-WinTimeConfig',
        'Get-WinTimeHealth',
        'Export-WinTimeConfigBaseline'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    FileList             = @(
        'WinTimeHealth.psd1',
        'WinTimeHealth.psm1',
        'PSScriptAnalyzerSettings.psd1',
        'Data/W32TimeKeys.yaml',
        'Formats/WinTimeHealth.Format.ps1xml',
        'Public/Get-WinTimeConfig.ps1',
        'Public/Get-WinTimeHealth.ps1',
        'Public/Export-WinTimeConfigBaseline.ps1',
        'Private/Compare-W32TimeConfig.ps1',
        'Private/Connect-WinTimeAdminShare.ps1',
        'Private/ConvertFrom-RegFile.ps1',
        'Private/ConvertFrom-SimpleYaml.ps1',
        'Private/ConvertTo-RegFile.ps1',
        'Private/ConvertTo-WinTimeCsvSafe.ps1',
        'Private/Disconnect-WinTimeAdminShare.ps1',
        'Private/Get-W32TimeDatabase.ps1',
        'Private/Get-WinTimeRegistryWorker.ps1',
        'Private/Invoke-NtpQuery.ps1',
        'Private/Invoke-WinTimeHealthEvaluation.ps1',
        'Private/Invoke-WinTimeScan.ps1',
        'Private/New-WinTimeHtmlReport.ps1',
        'Private/Resolve-W32TimeExpectation.ps1',
        'Private/Resolve-WinTimeTarget.ps1',
        'Private/Write-WinTimeReportFile.ps1',
        'Private/Write-WinTimeSummary.ps1'
    )
    PrivateData          = @{
        PSData = @{
            Tags         = @('W32Time', 'NTP', 'ActiveDirectory', 'TimeSync', 'Audit', 'DomainController', 'Windows')
            LicenseUri   = 'https://github.com/example/wintime-audit/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/example/wintime-audit'
            ReleaseNotes = 'See CHANGELOG.md at the repository root: https://github.com/example/wintime-audit/blob/master/CHANGELOG.md'
        }
    }
}
