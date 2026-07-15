function Disconnect-WinTimeAdminShare {
<#
.SYNOPSIS
Tears down an IPC$ SMB session previously established by
Connect-WinTimeAdminShare.

.DESCRIPTION
Cleanup half of the credential path (DESIGN section 7). Best-effort with
-ErrorAction SilentlyContinue semantics throughout: a missing mapping, a
missing cmdlet or an unreachable host never throws. Removes the SMB mapping
for \\<fqdn>\IPC$ and, when the WNetAddConnection2 fallback type was compiled
in this process, also calls WNetCancelConnection2. Only ever invoked by the
orchestrator for sessions THIS run established (tracked via the workers'
SessionEstablished output field), so pre-existing sessions are never touched.

.PARAMETER ComputerName
Canonical FQDN of the target whose IPC$ session should be disconnected.

.OUTPUTS
None.

.EXAMPLE
Disconnect-WinTimeAdminShare -ComputerName dc1.contoso.com
#>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    $remotePath = '\\' + $ComputerName + '\IPC$'

    if (Get-Command -Name Remove-SmbMapping -ErrorAction SilentlyContinue) {
        try {
            Remove-SmbMapping -RemotePath $remotePath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose ('Remove-SmbMapping for {0} failed: {1}' -f $remotePath, $_.Exception.Message)
        }
    }

    # Also cancel a WNet connection when the fallback type exists in-process.
    $nativeType = 'WinTimeHealth.NativeMethods' -as [type]
    if ($null -ne $nativeType) {
        try {
            $null = $nativeType::WNetCancelConnection2($remotePath, 0, $true)
        } catch {
            Write-Verbose ('WNetCancelConnection2 for {0} failed: {1}' -f $remotePath, $_.Exception.Message)
        }
    }
}
