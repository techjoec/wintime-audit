function Connect-WinTimeAdminShare {
<#
.SYNOPSIS
Establishes an IPC$ SMB session to a target under an alternate credential.

.DESCRIPTION
Credential path of DESIGN section 7. Pre-checks Get-SmbConnection for an
existing session to the same server: same user means reuse (never torn down -
it is not ours); a different user is a terminal 1219-style conflict (no
retry). Otherwise maps \\<fqdn>\IPC$ via New-SmbMapping (in-process, password
never on a command line) and falls back to a WNetAddConnection2 P/Invoke when
the IPC$ mapping is rejected (type compiled once per process).

NOTE: this function body is shipped BY TEXT into the scan worker
(Options.ConnectScript) and re-created there with [scriptblock]::Create, so
it must stay fully self-contained: no module state, no script-scoped
variables.

.PARAMETER ComputerName
Canonical FQDN of the target (the same string used for every other hop).

.PARAMETER Credential
The alternate credential to establish the session under.

.OUTPUTS
hashtable @{ Established = <bool: this call created a session>;
             Reused = <bool: an existing same-user session was reused> }

.EXAMPLE
Connect-WinTimeAdminShare -ComputerName dc1.contoso.com -Credential $cred
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    function ConvertTo-WinTimeAccountPart {
        # Normalizes 'DOMAIN\user', 'user@domain.tld' and 'user' to
        # @{ Domain; User }; the domain keeps only its first label so that
        # CONTOSO (NetBIOS) and contoso.com (DNS) compare equal.
        param([string]$Name)
        $domainPart = ''
        $userPart = [string]$Name
        $backslash = $userPart.IndexOf('\')
        $at = $userPart.IndexOf('@')
        if ($backslash -ge 0) {
            $domainPart = $userPart.Substring(0, $backslash)
            $userPart = $userPart.Substring($backslash + 1)
        } elseif ($at -gt 0) {
            $domainPart = $userPart.Substring($at + 1)
            $userPart = $userPart.Substring(0, $at)
        }
        $dot = $domainPart.IndexOf('.')
        if ($dot -gt 0) { $domainPart = $domainPart.Substring(0, $dot) }
        return @{ Domain = $domainPart; User = $userPart }
    }

    $wantedAccount = ConvertTo-WinTimeAccountPart -Name $Credential.UserName

    # Pre-check: an existing SMB session to this server?
    $existingConnections = @()
    if (Get-Command -Name Get-SmbConnection -ErrorAction SilentlyContinue) {
        $existingConnections = @(Get-SmbConnection -ServerName $ComputerName -ErrorAction SilentlyContinue)
    }
    if ($existingConnections.Count -gt 0) {
        $firstUser = ''
        foreach ($existingConnection in $existingConnections) {
            $connectionUser = [string]$existingConnection.UserName
            if ([string]::IsNullOrEmpty($firstUser)) { $firstUser = $connectionUser }
            $haveAccount = ConvertTo-WinTimeAccountPart -Name $connectionUser
            $userMatch = [string]::Equals($haveAccount.User, $wantedAccount.User, [System.StringComparison]::OrdinalIgnoreCase)
            $domainMatch = ([string]::IsNullOrEmpty($haveAccount.Domain) -or
                            [string]::IsNullOrEmpty($wantedAccount.Domain) -or
                            [string]::Equals($haveAccount.Domain, $wantedAccount.Domain, [System.StringComparison]::OrdinalIgnoreCase))
            if ($userMatch -and $domainMatch) {
                # Same user: reuse; never tear down a session we did not create.
                return @{ Established = $false; Reused = $true }
            }
        }
        throw ('1219 conflict: an existing SMB session to {0} is held by ''{1}'' - disconnect it (net use \\{0}\IPC$ /delete) or run without -Credential' -f $ComputerName, $firstUser)
    }

    $remotePath = '\\' + $ComputerName + '\IPC$'
    $plainPassword = $Credential.GetNetworkCredential().Password

    # Primary mechanism: in-box SMB mapping, in-process.
    $smbMappingError = 'New-SmbMapping cmdlet not available'
    if (Get-Command -Name New-SmbMapping -ErrorAction SilentlyContinue) {
        try {
            $null = New-SmbMapping -RemotePath $remotePath -UserName $Credential.UserName -Password $plainPassword -ErrorAction Stop
            return @{ Established = $true; Reused = $false }
        } catch {
            $smbMappingError = $_.Exception.Message
        }
    }

    # Fallback: WNetAddConnection2 P/Invoke. Compiled once per process; the
    # type-presence check is the "once" guard (no module/script state).
    if ($null -eq ('WinTimeHealth.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace WinTimeHealth
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class NetResource
    {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        public string lpLocalName;
        public string lpRemoteName;
        public string lpComment;
        public string lpProvider;
    }

    public static class NativeMethods
    {
        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        public static extern int WNetAddConnection2(NetResource lpNetResource, string lpPassword, string lpUserName, int dwFlags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        public static extern int WNetCancelConnection2(string lpName, int dwFlags, bool fForce);
    }
}
'@
    }

    $nativeType = 'WinTimeHealth.NativeMethods' -as [type]
    $resourceType = 'WinTimeHealth.NetResource' -as [type]
    if ($null -eq $nativeType -or $null -eq $resourceType) {
        throw ('cannot establish IPC$ session to {0}: New-SmbMapping failed ({1}) and the WNetAddConnection2 fallback is unavailable' -f $ComputerName, $smbMappingError)
    }

    $netResource = [System.Activator]::CreateInstance($resourceType)
    $netResource.dwType = 0  # RESOURCETYPE_ANY
    $netResource.lpRemoteName = $remotePath
    $returnCode = $nativeType::WNetAddConnection2($netResource, $plainPassword, $Credential.UserName, 0)
    if ($returnCode -eq 0) {
        return @{ Established = $true; Reused = $false }
    }
    if ($returnCode -eq 1219) {
        throw ('1219 conflict: disconnect the existing session to {0} or run without -Credential (WNetAddConnection2)' -f $ComputerName)
    }
    $win32Detail = New-Object System.ComponentModel.Win32Exception ($returnCode)
    # Rethrow as Win32Exception so the worker's classifier sees the native code.
    throw (New-Object System.ComponentModel.Win32Exception ($returnCode, ('cannot establish IPC$ session to {0}: New-SmbMapping failed ({1}); WNetAddConnection2 failed with code {2} ({3})' -f $ComputerName, $smbMappingError, $returnCode, $win32Detail.Message)))
}
