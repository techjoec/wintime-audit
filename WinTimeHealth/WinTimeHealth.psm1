# WinTimeHealth root module.
# Load-time guards, dot-sourcing of Private/ and Public/, database schema
# validation and explicit exports (DESIGN.md section 12).

Set-StrictMode -Version Latest

# --- Guard: PowerShell version ---------------------------------------------
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw ("WinTimeHealth requires PowerShell 5.1 or later; this session runs {0}." -f $PSVersionTable.PSVersion)
}

# --- Guard: language mode ---------------------------------------------------
# CLM/WDAC-constrained sessions cannot host the .NET registry/socket code the
# scan engine uses, so fail loudly at import instead of mysteriously mid-scan.
if ([string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw ("WinTimeHealth requires FullLanguage mode; this session runs '{0}'. Constrained language (CLM/WDAC) hosts cannot run the module's .NET registry and socket code." -f $ExecutionContext.SessionState.LanguageMode)
}

# --- Platform detection ------------------------------------------------------
# Non-Windows platforms may import the module (unit tests, tooling, report
# post-processing); the scan cmdlets consult this flag and throw early.
# Note: deliberately NOT named $psEdition - that collides (case-insensitively)
# with the read-only automatic variable $PSEdition and PSScriptAnalyzer's
# PSAvoidAssignmentToAutomaticVariable rule correctly flags it as an error.
$currentPsEdition = 'Desktop'
if ($PSVersionTable.ContainsKey('PSEdition') -and $null -ne $PSVersionTable['PSEdition']) {
    $currentPsEdition = [string]$PSVersionTable['PSEdition']
}
$script:IsWindowsPlatform = $true
if ($currentPsEdition -eq 'Core') {
    $script:IsWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
}
if (-not $script:IsWindowsPlatform) {
    Write-Verbose 'WinTimeHealth: non-Windows platform - module loads for tests/tooling, scan cmdlets will throw.'
}

# --- Guard: ThreadJob ---------------------------------------------------------
# Deliberately NOT a RequiredModules pin: PowerShell 7.6 renamed the in-box
# module to Microsoft.PowerShell.ThreadJob, so a name pin breaks somewhere.
# Resolve the command instead (DESIGN.md section 7).
$threadJobCommand = Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue
if ($null -eq $threadJobCommand) {
    # DESIGN.md section 12 mandates an actionable throw at import time
    # whenever Start-ThreadJob cannot be resolved - unconditionally, not
    # only on Windows PowerShell 5.1 Desktop. PowerShell 7.6 renamed the
    # in-box module to Microsoft.PowerShell.ThreadJob (hence resolving the
    # command instead of pinning a module name), but Core builds that lack
    # any ThreadJob-providing module must fail loudly here too, not degrade
    # to a Write-Warning that defers the failure until the first scan call.
    throw "WinTimeHealth requires the ThreadJob module. Install it with: Install-Module ThreadJob -Scope CurrentUser (Windows PowerShell 5.1) or Install-Module Microsoft.PowerShell.ThreadJob -Scope CurrentUser (PowerShell 7.6+)."
}

# --- Dot-source Private/ then Public/ (each sorted by file name) --------------
foreach ($folderName in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folderName
    if (-not (Test-Path -LiteralPath $folderPath)) { continue }
    $scriptFiles = @(Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -File | Sort-Object -Property Name)
    foreach ($scriptFile in $scriptFiles) {
        try {
            . $scriptFile.FullName
        } catch {
            throw ("WinTimeHealth: failed to load '{0}': {1}" -f $scriptFile.FullName, $_.Exception.Message)
        }
    }
}

# --- Guard: database schema ----------------------------------------------------
# Get-W32TimeDatabase validates schema_version == 2 (throws with an upgrade
# message otherwise) and caches the parsed database for the session.
$null = Get-W32TimeDatabase

Export-ModuleMember -Function @(
    'Get-WinTimeConfig',
    'Get-WinTimeHealth',
    'Export-WinTimeConfigBaseline'
) -Cmdlet @() -Alias @()
