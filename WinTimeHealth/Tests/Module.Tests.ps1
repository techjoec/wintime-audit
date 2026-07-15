# Module.Tests.ps1 - manifest, packaging, export surface and 5.1-syntax
# hygiene for the WinTimeHealth module (DESIGN.md sections 11 and 12).
# Unlike the unit test files, this suite imports the BUILT module - it must
# import successfully cross-platform (Windows-only .NET usage stays inside
# function bodies).

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeDiscovery {
    $script:HasScriptAnalyzer = ($null -ne (Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1))
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    # This test file's own source necessarily contains the literal detection
    # substrings (' ?? ', ') ? ', ...) inside string literals/comments below -
    # exclude it from the crude text heuristic scan (self-match false
    # positive); the AST-based PSSA check further down still covers it.
    $script:SelfTestPath = $PSCommandPath
    $script:ManifestPath = Join-Path $script:ModuleRoot 'WinTimeHealth.psd1'
    $script:PsmPath = Join-Path $script:ModuleRoot 'WinTimeHealth.psm1'
    $script:PublicDir = Join-Path $script:ModuleRoot 'Public'
    $script:ExpectedFunctions = @('Get-WinTimeConfig', 'Get-WinTimeHealth', 'Export-WinTimeConfigBaseline')
    # DESIGN section 8 check catalog, FINAL.
    $script:CheckCatalog = @('Service', 'NtpQuery', 'Offset', 'Stratum', 'Source', 'LastSync', 'Announce', 'Vmic', 'RefidLoop', 'SecureTimeSeeding')
    # Private inventory per DESIGN section 2: FileList entries may not exist
    # yet while components build in parallel; Test-ModuleManifest errors about
    # THOSE files (and only those) are tolerated.
    $script:PrivateInventory = @(
        'Compare-W32TimeConfig.ps1', 'Connect-WinTimeAdminShare.ps1', 'ConvertFrom-RegFile.ps1',
        'ConvertFrom-SimpleYaml.ps1', 'ConvertTo-RegFile.ps1', 'ConvertTo-WinTimeCsvSafe.ps1',
        'Disconnect-WinTimeAdminShare.ps1', 'Get-W32TimeDatabase.ps1', 'Get-WinTimeRegistryWorker.ps1',
        'Invoke-NtpQuery.ps1', 'Invoke-WinTimeHealthEvaluation.ps1', 'Invoke-WinTimeScan.ps1',
        'New-WinTimeHtmlReport.ps1', 'Resolve-W32TimeExpectation.ps1', 'Resolve-WinTimeTarget.ps1',
        'Write-WinTimeReportFile.ps1', 'Write-WinTimeSummary.ps1'
    )

    function Get-ScriptFunctionAst {
        param([string]$Path)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        if (@($errors).Count -gt 0) {
            throw ("'{0}' has parse errors: {1}" -f $Path, (@($errors | ForEach-Object { $_.Message }) -join '; '))
        }
        $functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
        return @($functions)[0]
    }
}

Describe 'WinTimeHealth module manifest' {

    It 'passes Test-ModuleManifest (tolerating only pending-FileList errors)' {
        $manifestErrors = @()
        $manifest = Test-ModuleManifest -Path $script:ManifestPath -ErrorAction SilentlyContinue -ErrorVariable manifestErrors -WarningAction SilentlyContinue
        $manifest | Should -Not -BeNullOrEmpty
        foreach ($manifestError in $manifestErrors) {
            # Only 'FileList entry ... Private/<known pending file>' errors are
            # acceptable mid-build; anything else is a real manifest defect.
            $message = $manifestError.Exception.Message
            $message | Should -Match 'FileList'
            $mentionsPending = $false
            foreach ($pending in $script:PrivateInventory) {
                if ($message.IndexOf($pending, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $mentionsPending = $true; break }
            }
            $mentionsPending | Should -BeTrue -Because ("only pending Private files may be missing, got: {0}" -f $message)
        }
    }

    It 'declares the agreed identity and export surface' {
        $manifest = Test-ModuleManifest -Path $script:ManifestPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $manifest.Version.ToString() | Should -Be '0.1.0'
        $manifest.PowerShellVersion.ToString() | Should -Be '5.1'
        @($manifest.ExportedFunctions.Keys) | Sort-Object | Should -Be (@($script:ExpectedFunctions) | Sort-Object)
        @($manifest.ExportedCmdlets.Keys).Count | Should -Be 0
        @($manifest.ExportedAliases.Keys).Count | Should -Be 0
    }

    It 'ships the database and format file in FileList' {
        $raw = Import-PowerShellDataFile -Path $script:ManifestPath
        $raw.FileList | Should -Contain 'Data/W32TimeKeys.yaml'
        $raw.FileList | Should -Contain 'Formats/WinTimeHealth.Format.ps1xml'
        $raw.PrivateData.PSData.Tags | Should -Contain 'W32Time'
    }
}

Describe 'WinTimeHealth module import' {

    It 'root module parses without errors' {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:PsmPath, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }

    It 'every module script parses without errors' {
        $scripts = @(Get-ChildItem -Path $script:ModuleRoot -Filter '*.ps1' -Recurse -File)
        $scripts.Count | Should -BeGreaterThan 0
        foreach ($script in $scripts) {
            $tokens = $null
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0 -Because ("{0} must parse" -f $script.FullName)
        }
    }

    It 'imports cross-platform and exports exactly the three public cmdlets' {
        $module = Import-Module -Name $script:ManifestPath -Force -PassThru -ErrorAction Stop
        try {
            @($module.ExportedFunctions.Keys).Count | Should -Be 3
            @($module.ExportedFunctions.Keys) | Sort-Object | Should -Be (@($script:ExpectedFunctions) | Sort-Object)
        } finally {
            Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Public cmdlet surface' {

    It '<_> declares [OutputType] and has comment-based help with examples' -ForEach @('Get-WinTimeConfig', 'Get-WinTimeHealth', 'Export-WinTimeConfigBaseline') {
        $path = Join-Path $script:PublicDir ($_ + '.ps1')
        Test-Path -LiteralPath $path | Should -BeTrue
        $functionAst = Get-ScriptFunctionAst -Path $path
        $functionAst | Should -Not -BeNullOrEmpty
        $functionAst.Name | Should -Be $_

        $outputTypes = @($functionAst.Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -match 'OutputType' })
        $outputTypes.Count | Should -BeGreaterThan 0 -Because 'DESIGN section 3 requires [OutputType()] on all cmdlets'

        $help = $functionAst.GetHelpContent()
        $help | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -BeNullOrEmpty
        @($help.Examples).Count | Should -BeGreaterOrEqual 1
    }

    It 'Get-WinTimeConfig help carries at least four realistic examples' {
        $functionAst = Get-ScriptFunctionAst -Path (Join-Path $script:PublicDir 'Get-WinTimeConfig.ps1')
        @($functionAst.GetHelpContent().Examples).Count | Should -BeGreaterOrEqual 4
    }

    It 'Get-WinTimeHealth check ValidateSet matches the DESIGN catalog exactly' {
        $functionAst = Get-ScriptFunctionAst -Path (Join-Path $script:PublicDir 'Get-WinTimeHealth.ps1')
        foreach ($parameterName in @('IncludedHealthChecks', 'ExcludedHealthChecks')) {
            $parameter = @($functionAst.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $parameterName })[0]
            $parameter | Should -Not -BeNullOrEmpty -Because ("-{0} must exist" -f $parameterName)
            $validateSet = @($parameter.Attributes | Where-Object { $_.TypeName.Name -match 'ValidateSet' })[0]
            $validateSet | Should -Not -BeNullOrEmpty -Because ("-{0} must carry a static ValidateSet" -f $parameterName)
            $values = @($validateSet.PositionalArguments | ForEach-Object { $_.Value })
            ($values | Sort-Object) | Should -Be ($script:CheckCatalog | Sort-Object)
        }
    }

    It 'Get-WinTimeConfig pipeline targeting binds Server/ComputerName/DnsHostName by property name' {
        $functionAst = Get-ScriptFunctionAst -Path (Join-Path $script:PublicDir 'Get-WinTimeConfig.ps1')
        $parameter = @($functionAst.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'IncludedDomainControllers' })[0]
        $parameter | Should -Not -BeNullOrEmpty
        $aliasAttribute = @($parameter.Attributes | Where-Object { $_.TypeName.Name -match '^Alias' })[0]
        $aliasAttribute | Should -Not -BeNullOrEmpty
        $aliases = @($aliasAttribute.PositionalArguments | ForEach-Object { $_.Value })
        ($aliases | Sort-Object) | Should -Be (@('ComputerName', 'DnsHostName', 'Server') | Sort-Object)
    }

    It 'Export-WinTimeConfigBaseline has mutually exclusive mandatory Named/All parameter sets' {
        $module = Import-Module -Name $script:ManifestPath -Force -PassThru -ErrorAction Stop
        try {
            $command = Get-Command -Name Export-WinTimeConfigBaseline -Module $module.Name
            $setNames = @($command.ParameterSets | ForEach-Object { $_.Name })
            $setNames | Should -Contain 'Named'
            $setNames | Should -Contain 'All'
            $command.Parameters['DomainControllers'].ParameterSets.Keys | Should -Be @('Named')
            $command.Parameters['ExportAllDCs'].ParameterSets.Keys | Should -Be @('All')
            $command.Parameters['DomainControllers'].ParameterSets['Named'].IsMandatory | Should -BeTrue
            $command.Parameters['ExportAllDCs'].ParameterSets['All'].IsMandatory | Should -BeTrue
            $command.Parameters['OutFile'].Attributes | Where-Object { ($_ -is [System.Management.Automation.ParameterAttribute]) -and $_.Mandatory } | Should -Not -BeNullOrEmpty
            $command.Parameters.ContainsKey('WhatIf') | Should -BeTrue -Because 'SupportsShouldProcess is part of the contract'
        } finally {
            Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe '5.1 syntax hygiene (DESIGN section 12)' {

    It 'contains no ternary or null-coalescing operator tokens (heuristic scan)' {
        $scripts = @(Get-ChildItem -Path $script:ModuleRoot -Include '*.ps1', '*.psm1' -Recurse -File |
                Where-Object { $_.FullName -ne $script:SelfTestPath })
        foreach ($script in $scripts) {
            $lineNumber = 0
            foreach ($line in [System.IO.File]::ReadAllLines($script.FullName)) {
                $lineNumber++
                $trimmed = $line.TrimStart()
                # Crude comment filter; the authoritative check is PSSA below.
                if ($trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) { continue }
                $line.Contains(' ?? ') | Should -BeFalse -Because ("null-coalescing at {0}:{1}" -f $script.FullName, $lineNumber)
                $line.Contains('??=') | Should -BeFalse -Because ("null-coalescing assignment at {0}:{1}" -f $script.FullName, $lineNumber)
                $line.Contains(') ? ') | Should -BeFalse -Because ("ternary at {0}:{1}" -f $script.FullName, $lineNumber)
            }
        }
    }

    It 'passes PSUseCompatibleSyntax for 5.1 and 7.4 (authoritative)' -Skip:(-not $script:HasScriptAnalyzer) {
        $settingsPath = Join-Path $script:ModuleRoot 'PSScriptAnalyzerSettings.psd1'
        # -IncludeRule restricts this invocation to PSUseCompatibleSyntax only.
        # Running the full default ruleset here (Path+Recurse, no -IncludeRule)
        # is unnecessary for this check and, in this PSScriptAnalyzer/.NET
        # combination, an unrelated default rule (PSAvoidReservedCharInCmdlet,
        # which dynamically resolves Export-ModuleMember via a throwaway
        # module/runspace) intermittently throws a NullReferenceException or
        # "more than one dynamic module" error - a PSScriptAnalyzer engine
        # flake unrelated to this module's code. Scoping to the one rule this
        # test is actually about keeps the check both authoritative and stable.
        $findings = @(Invoke-ScriptAnalyzer -Path $script:ModuleRoot -Recurse -Settings $settingsPath -IncludeRule 'PSUseCompatibleSyntax' -ErrorAction Stop)
        $findingText = @($findings | ForEach-Object { '{0}:{1} {2}' -f $_.ScriptName, $_.Line, $_.Message }) -join '; '
        $findings.Count | Should -Be 0 -Because $findingText
    }
}
