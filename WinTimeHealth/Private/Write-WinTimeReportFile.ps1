function Write-WinTimeReportFile {
    <#
    .SYNOPSIS
    Writes report text to disk as UTF-8 with BOM, honoring -Force overwrite
    semantics.

    .DESCRIPTION
    Single choke point for report file encoding (DESIGN section 10): content is
    written via [System.IO.File]::WriteAllText with UTF8Encoding($true) so
    Windows PowerShell 5.1 and PowerShell 7+ produce byte-identical files.

    When the target file already exists and -Force is not supplied, a
    terminating error is thrown with FullyQualifiedErrorId
    'FileExists,Write-WinTimeReportFile'.

    .PARAMETER Path
    Destination file path. Relative paths resolve against the caller's
    PowerShell location (provider path resolution), not the process working
    directory.

    .PARAMETER Content
    The text to write. An array of lines is joined with the platform newline;
    a single string is written as-is.

    .PARAMETER Force
    Overwrite an existing file.

    .OUTPUTS
    System.IO.FileInfo. The file that was written.

    .EXAMPLE
    Write-WinTimeReportFile -Path .\report.csv -Content $csvLines -Force
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [string[]]$Content,

        [switch]$Force
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $resolvedPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if ((Test-Path -LiteralPath $resolvedPath) -and (-not $Force)) {
        $message = [string]::Format($invariant, "File '{0}' already exists. Use -Force to overwrite.", $resolvedPath)
        $exception = [System.IO.IOException]::new($message)
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'FileExists',
            [System.Management.Automation.ErrorCategory]::ResourceExists,
            $resolvedPath)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    $text = $Content -join [System.Environment]::NewLine
    # UTF8Encoding($true) = BOM; identical bytes on Desktop and Core editions.
    $encoding = [System.Text.UTF8Encoding]::new($true)
    [System.IO.File]::WriteAllText($resolvedPath, $text, $encoding)

    Write-Verbose ([string]::Format($invariant, 'Write-WinTimeReportFile: wrote {0} character(s) to {1}.', $text.Length, $resolvedPath))
    return (Get-Item -LiteralPath $resolvedPath)
}
