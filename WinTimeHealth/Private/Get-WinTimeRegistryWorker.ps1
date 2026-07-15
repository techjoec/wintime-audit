function Get-WinTimeErrorClass {
<#
.SYNOPSIS
Classifies an exception into a WinTimeHealth scan ErrorClass string.

.DESCRIPTION
Pure classification helper (unit-testable). Flattens the exception chain
(inner exceptions, AggregateException members, ErrorRecord payloads) and maps
it to one of: AccessDenied, AuthFailure, RemoteRegistryDisabled, Transport,
Unknown. The Timeout class is assigned by the worker envelope on attempt
expiry, never here. This function's body is embedded verbatim into the
self-contained worker scriptblock, so it must not reference any module state.

.PARAMETER Exception
The exception to classify.

.PARAMETER PreflightSucceeded
Whether the TCP/445 preflight succeeded for this attempt. An IOException from
the winreg open while port 445 answers maps to RemoteRegistryDisabled
(DESIGN section 7 step 4); without a live preflight it is plain Transport.

.OUTPUTS
[string] AccessDenied | AuthFailure | RemoteRegistryDisabled | Transport | Unknown
#>
    param(
        [System.Exception]$Exception,
        [bool]$PreflightSucceeded
    )

    if ($null -eq $Exception) { return 'Unknown' }

    # Flatten the exception chain into a bounded list.
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($Exception)
    $chain = New-Object System.Collections.ArrayList
    $guard = 0
    while ($queue.Count -gt 0 -and $guard -lt 32) {
        $guard++
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }
        $null = $chain.Add($current)
        if ($current -is [System.AggregateException]) {
            foreach ($member in $current.InnerExceptions) { $queue.Enqueue($member) }
        }
        if ($null -ne $current.InnerException) { $queue.Enqueue($current.InnerException) }
        if ($current -is [System.Management.Automation.IContainsErrorRecord]) {
            $record = $current.ErrorRecord
            if ($null -ne $record -and $null -ne $record.Exception -and -not [object]::ReferenceEquals($record.Exception, $current)) {
                $queue.Enqueue($record.Exception)
            }
        }
    }

    # Logon-class Win32 codes: 1326 bad credentials, 1331 account disabled,
    # 1907 password must change, 1219 conflicting session (DESIGN section 7 step 3).
    $authCodes = @(1219, 1326, 1331, 1907)
    $sawIoException = $false
    $sawTransportException = $false
    foreach ($candidate in $chain) {
        if ($candidate -is [System.Security.SecurityException]) { return 'AccessDenied' }
        if ($candidate -is [System.UnauthorizedAccessException]) { return 'AccessDenied' }
        # NB: SocketException derives from Win32Exception; its native codes are
        # 10000+ so they never collide with the logon codes checked here.
        if ($candidate -is [System.ComponentModel.Win32Exception]) {
            $nativeCode = ([System.ComponentModel.Win32Exception]$candidate).NativeErrorCode
            if ($authCodes -contains $nativeCode) { return 'AuthFailure' }
            if ($nativeCode -eq 5) { return 'AccessDenied' }
        }
        $message = [string]$candidate.Message
        foreach ($authCode in $authCodes) {
            if ($message -match ('(^|\D)' + $authCode + '(\D|$)')) { return 'AuthFailure' }
        }
        if ($message -match '(?i)user name or password|logon failure|password must be changed|account.{1,30}(disabled|locked)') { return 'AuthFailure' }
        if ($message -match '(?i)access.{1,4}denied') { return 'AccessDenied' }
        if ($candidate -is [System.Net.Sockets.SocketException]) { $sawTransportException = $true; continue }
        if ($candidate -is [System.TimeoutException]) { $sawTransportException = $true; continue }
        if ($candidate -is [System.IO.IOException]) { $sawIoException = $true; continue }
    }

    if ($sawIoException) {
        # Preflight OK + IOException on the winreg open: the named pipe is not
        # being served - RemoteRegistry deliberately disabled (trigger-start is
        # the modern default, so a dead pipe is a decision, not an accident).
        if ($PreflightSucceeded) { return 'RemoteRegistryDisabled' }
        return 'Transport'
    }
    if ($sawTransportException) { return 'Transport' }
    return 'Unknown'
}

function Get-WinTimeRegistryWorker {
<#
.SYNOPSIS
Returns the self-contained registry scan worker scriptblock.

.DESCRIPTION
Builds the worker described in DESIGN section 7 steps 1-5 as a fully
self-contained scriptblock: param($Target, $ReadSpec, $Options), no module
state, no Write-Progress/Write-Host. The Get-WinTimeErrorClass helper is
embedded by text so classification logic has a single source. The worker:

  1. TCP/445 preflight (2 s budget, fail fast, ErrorClass=Transport).
  2. On the credential path, invokes the connection scriptblock passed as
     TEXT in $Options.ConnectScript (recreated locally, so the worker keeps
     no runspace affinity) on a nested [powershell] instance with the same
     BeginInvoke + WaitOne(TimeoutSeconds) + abandon-on-timeout bound as
     step 3 (SMB session setup is native and uninterruptible too), and
     records SessionEstablished for orchestrator cleanup.
  3. Runs each registry read attempt on a nested [powershell] instance with
     BeginInvoke + WaitOne(TimeoutSeconds); abandons it on timeout (native
     winreg calls are uninterruptible - bounded thread leak, freed by the
     SMB client timeout). Never Thread.Abort; Stop is best-effort.
  4. Retries transport-class results only (Timeout/Transport) with
     1s/2s/4s... backoff; auth-class results are terminal on first
     occurrence. Preflight-ok + IOException maps to RemoteRegistryDisabled.
  5. Captures values as @{ Kind; Data } via GetValueKind +
     GetValue(DoNotExpandEnvironmentNames); DWORD normalized [uint32], QWORD
     [uint64]; Unknown/None kinds captured raw; missing subkey = empty
     hashtable; tree/value-name lookups OrdinalIgnoreCase.
  6. On the registry-scan path, also queries ServiceController('w32time',
     fqdn) for the live SCM status (svcctl rides the same 445 session);
     failures (including PlatformNotSupportedException on non-Windows) leave
     ScmStatus = $null rather than failing the scan.

.PARAMETER None
This factory takes no parameters.

.OUTPUTS
[scriptblock] worker returning @{ ComputerName; Success; Attempts; Error;
ErrorClass; DurationMs; Tree; SessionEstablished; ScmStatus }.
#>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()

    $classifyBody = ${function:Get-WinTimeErrorClass}.ToString()
    $classifyFunction = 'function Get-WinTimeErrorClass {' + [System.Environment]::NewLine + $classifyBody + [System.Environment]::NewLine + '}'

    $template = @'
param($Target, $ReadSpec, $Options)

# Self-contained W32Time registry scan worker (DESIGN section 7).
# Runs inside a thread job: no module state, no host/progress output.
$ErrorActionPreference = 'Stop'

#<<CLASSIFY>>#

# --- input normalization (all inputs are treated read-only) ---
$computerName = ''
if ($Target -is [string]) {
    $computerName = $Target
} elseif ($null -ne $Target) {
    $computerName = [string]$Target.ComputerName
}

$timeoutSeconds = 30
$retryCount = 3
$credential = $null
$connectScript = $null
if ($Options -is [hashtable]) {
    if ($Options.ContainsKey('TimeoutSeconds') -and $null -ne $Options['TimeoutSeconds']) { $timeoutSeconds = [int]$Options['TimeoutSeconds'] }
    if ($Options.ContainsKey('RetryCount') -and $null -ne $Options['RetryCount']) { $retryCount = [int]$Options['RetryCount'] }
    if ($Options.ContainsKey('Credential') -and $null -ne $Options['Credential']) { $credential = $Options['Credential'] }
    if ($null -ne $credential -and $Options.ContainsKey('ConnectScript') -and $null -ne $Options['ConnectScript']) {
        # Recreated from text: no affinity to the orchestrator's runspace.
        $connectScript = [scriptblock]::Create([string]$Options['ConnectScript'])
    }
}

$readPaths = @()
foreach ($entry in @($ReadSpec)) {
    if ($null -eq $entry) { continue }
    $entryPath = $null
    $entryRecursive = $false
    if ($entry -is [hashtable]) {
        if ($entry.ContainsKey('Path')) { $entryPath = [string]$entry['Path'] }
        if ($entry.ContainsKey('Recursive')) { $entryRecursive = [bool]$entry['Recursive'] }
    } else {
        $pathProperty = $entry.PSObject.Properties['Path']
        if ($null -ne $pathProperty) { $entryPath = [string]$pathProperty.Value }
        $recursiveProperty = $entry.PSObject.Properties['Recursive']
        if ($null -ne $recursiveProperty) { $entryRecursive = [bool]$recursiveProperty.Value }
    }
    if (-not [string]::IsNullOrEmpty($entryPath)) {
        $readPaths += , @{ Path = $entryPath; Recursive = $entryRecursive }
    }
}

# Registry read body: executed on a nested [powershell] instance per attempt.
# Only its text is used (AddScript), so there is no runspace affinity.
$innerScript = {
    param($ComputerName, $Paths)
    $ErrorActionPreference = 'Stop'
    $tree = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
    try {
        foreach ($spec in $Paths) {
            $stack = New-Object System.Collections.Stack
            $stack.Push([string]$spec.Path)
            while ($stack.Count -gt 0) {
                $currentPath = [string]$stack.Pop()
                $key = $base.OpenSubKey($currentPath, $false)
                if ($null -eq $key) {
                    # Missing subkey => empty hashtable (absence is data).
                    if (-not $tree.ContainsKey($currentPath)) {
                        $tree[$currentPath] = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
                    }
                    continue
                }
                try {
                    $values = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($valueName in $key.GetValueNames()) {
                        $kind = 'Unknown'
                        try { $kind = $key.GetValueKind($valueName).ToString() } catch { $kind = 'Unknown' }
                        $data = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        if ($kind -eq 'DWord' -and $null -ne $data) {
                            # Single choke point: DWORD normalized unsigned.
                            # NB: the hex literal 0xFFFFFFFF parses as Int32 -1
                            # in PowerShell, so a '-band 0xFFFFFFFF' mask is a
                            # no-op and the [uint32] cast below would throw for
                            # any DWORD with the high bit set (e.g. the
                            # near-universal CompatibilityFlags=0x80000000).
                            # Reinterpret the bit pattern via BitConverter
                            # instead, mirroring the QWORD branch below.
                            $data = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$data), 0)
                        } elseif ($kind -eq 'QWord' -and $null -ne $data) {
                            $data = [System.BitConverter]::ToUInt64([System.BitConverter]::GetBytes([long]$data), 0)
                        }
                        $values[$valueName] = @{ Kind = $kind; Data = $data }
                    }
                    $tree[$currentPath] = $values
                    if ([bool]$spec.Recursive) {
                        foreach ($subKeyName in $key.GetSubKeyNames()) {
                            $stack.Push(($currentPath + '\' + $subKeyName))
                        }
                    }
                } finally {
                    $key.Close()
                }
            }
        }
    } finally {
        $base.Close()
    }

    # Live SCM state (DESIGN section 8: "Service Status queried via
    # ServiceController('w32time', fqdn) inside the worker - svcctl rides the
    # same 445 session"). A failure here (including
    # PlatformNotSupportedException on non-Windows hosts, or the service not
    # existing at all) must not fail the registry scan: leave ScmStatus
    # $null and let the caller report it as unavailable.
    $scmStatus = $null
    $serviceController = $null
    try {
        $serviceController = New-Object System.ServiceProcess.ServiceController('w32time', $ComputerName)
        $scmStatus = $serviceController.Status.ToString()
    } catch {
        $scmStatus = $null
    } finally {
        if ($null -ne $serviceController) { try { $serviceController.Close() } catch { } }
    }

    @{ Tree = $tree; ScmStatus = $scmStatus }
}

$result = @{
    ComputerName       = $computerName
    Success            = $false
    Attempts           = 0
    Error              = $null
    ErrorClass         = $null
    DurationMs         = 0
    Tree               = $null
    ScmStatus          = $null
    SessionEstablished = $false
}
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if ([string]::IsNullOrEmpty($computerName)) {
    $result.Error = 'no ComputerName supplied to worker'
    $result.ErrorClass = 'Unknown'
    $result.DurationMs = [int]$stopwatch.ElapsedMilliseconds
    return $result
}

$maxAttempts = 1 + $retryCount
$lastError = $null
$lastClass = $null
$sessionReady = $false
$attempt = 0

while ($attempt -lt $maxAttempts) {
    $attempt++
    $result.Attempts = $attempt
    if ($attempt -gt 1) {
        # Backoff between transport-class retries: 1s, 2s, 4s, ...
        Start-Sleep -Seconds ([int][System.Math]::Pow(2, $attempt - 2))
    }

    # Step 1: TCP/445 preflight, 2 s budget - fail fast on a dead transport.
    $preflightOk = $false
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $connectTask = $tcpClient.ConnectAsync($computerName, 445)
            if (-not $connectTask.Wait(2000)) {
                throw (New-Object System.TimeoutException(('TCP 445 preflight to {0} timed out after 2000 ms' -f $computerName)))
            }
            $preflightOk = $true
        } finally {
            $tcpClient.Dispose()
        }
    } catch {
        $lastClass = 'Transport'
        $lastError = ('TCP 445 unreachable on {0}: {1}' -f $computerName, $_.Exception.Message)
        continue
    }

    # Step 2 (credential path): establish the IPC$ session under the
    # alternate credential before the winreg hop. Auth-class failures are
    # terminal on first occurrence - retrying sprays lockouts. Runs on a
    # nested [powershell] instance with the same BeginInvoke + WaitOne +
    # abandon-on-timeout pattern as the winreg read below: SMB session setup
    # (New-SmbMapping / WNetAddConnection2) is native and uninterruptible and
    # must not be allowed to block this worker's own ThreadJob thread past
    # the per-attempt timeout budget.
    if ($null -ne $connectScript -and -not $sessionReady) {
        $nestedConnectPs = $null
        $connectAbandoned = $false
        try {
            $nestedConnectPs = [powershell]::Create()
            $null = $nestedConnectPs.AddScript($connectScript.ToString()).AddParameter('ComputerName', $computerName).AddParameter('Credential', $credential)
            $connectAsyncResult = $nestedConnectPs.BeginInvoke()
            if (-not $connectAsyncResult.AsyncWaitHandle.WaitOne($timeoutSeconds * 1000)) {
                # Abandon on timeout: SMB session setup is uninterruptible;
                # the SMB client timeout eventually frees the leaked thread.
                $connectAbandoned = $true
                $lastClass = 'Timeout'
                $lastError = ('IPC$ session establishment to {0} exceeded {1}s (attempt {2}) - abandoned' -f $computerName, $timeoutSeconds, $attempt)
                try { $null = $nestedConnectPs.BeginStop($null, $null) } catch { $lastClass = 'Timeout' }
                continue
            }
            $connectOutput = $nestedConnectPs.EndInvoke($connectAsyncResult)
            $connection = $null
            foreach ($item in $connectOutput) { $connection = $item }
            $sessionReady = $true
            $established = $false
            if ($connection -is [hashtable]) {
                if ($connection.ContainsKey('Established')) { $established = [bool]$connection['Established'] }
            } elseif ($null -ne $connection) {
                $establishedProperty = $connection.PSObject.Properties['Established']
                if ($null -ne $establishedProperty) { $established = [bool]$establishedProperty.Value }
            }
            $result.SessionEstablished = $established
        } catch {
            # PreflightSucceeded is deliberately $false here: an IOException
            # during session setup is transport trouble, not a winreg signal.
            $lastClass = Get-WinTimeErrorClass -Exception $_.Exception -PreflightSucceeded $false
            $lastError = ('IPC$ session to {0} failed: {1}' -f $computerName, $_.Exception.Message)
            if ($lastClass -eq 'Transport' -or $lastClass -eq 'Timeout') { continue }
            break
        } finally {
            if ($null -ne $nestedConnectPs -and -not $connectAbandoned) {
                try { $nestedConnectPs.Dispose() } catch { $nestedConnectPs = $null }
            }
        }
    }

    # Steps 2-5: registry read on a nested PowerShell with a hard budget.
    $nestedPs = $null
    $abandoned = $false
    try {
        $nestedPs = [powershell]::Create()
        $null = $nestedPs.AddScript($innerScript.ToString()).AddArgument($computerName).AddArgument($readPaths)
        $asyncResult = $nestedPs.BeginInvoke()
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($timeoutSeconds * 1000)) {
            # Abandon on timeout: winreg calls are uninterruptible; the SMB
            # client timeout (~60 s) eventually frees the leaked thread.
            $abandoned = $true
            $lastClass = 'Timeout'
            $lastError = ('registry read on {0} exceeded {1}s (attempt {2}) - abandoned' -f $computerName, $timeoutSeconds, $attempt)
            try { $null = $nestedPs.BeginStop($null, $null) } catch { $lastClass = 'Timeout' }
            continue
        }
        $output = $nestedPs.EndInvoke($asyncResult)
        $innerResult = $null
        foreach ($item in $output) { if ($item -is [hashtable]) { $innerResult = $item } }
        $tree = $null
        if ($null -ne $innerResult -and $innerResult.ContainsKey('Tree')) { $tree = $innerResult['Tree'] }
        if ($null -ne $tree) {
            $result.Tree = $tree
            if ($innerResult.ContainsKey('ScmStatus')) { $result.ScmStatus = $innerResult['ScmStatus'] }
            $result.Success = $true
            $result.Error = $null
            $result.ErrorClass = $null
            break
        }
        $lastClass = 'Unknown'
        $lastError = ('registry read on {0} returned no tree' -f $computerName)
        break
    } catch {
        $lastClass = Get-WinTimeErrorClass -Exception $_.Exception -PreflightSucceeded $preflightOk
        if ($lastClass -eq 'RemoteRegistryDisabled') {
            $lastError = ('winreg pipe unavailable - RemoteRegistry likely Disabled on {0}' -f $computerName)
        } else {
            $lastError = ('registry read on {0} failed: {1}' -f $computerName, $_.Exception.Message)
        }
        if ($lastClass -eq 'Transport' -or $lastClass -eq 'Timeout') { continue }
        break
    } finally {
        if ($null -ne $nestedPs -and -not $abandoned) {
            try { $nestedPs.Dispose() } catch { $nestedPs = $null }
        }
    }
}

if (-not $result.Success) {
    if ($null -eq $lastClass) { $lastClass = 'Unknown' }
    if ($null -eq $lastError) { $lastError = ('scan of {0} failed for an unknown reason' -f $computerName) }
    $result.Error = $lastError
    $result.ErrorClass = $lastClass
}
$result.DurationMs = [int]$stopwatch.ElapsedMilliseconds
$result
'@

    $workerText = $template.Replace('#<<CLASSIFY>>#', $classifyFunction)
    return [scriptblock]::Create($workerText)
}
