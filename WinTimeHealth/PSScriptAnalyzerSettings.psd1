# PSScriptAnalyzer settings for WinTimeHealth (DESIGN.md section 12).
# Default rules plus 5.1/7.4 syntax-compatibility checking. The single
# sanctioned Write-Host site (Write-WinTimeSummary) carries an inline
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute] with justification;
# PSAvoidUsingWriteHost is intentionally NOT excluded here.
@{
    IncludeDefaultRules = $true
    Rules               = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
