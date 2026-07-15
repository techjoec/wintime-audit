function Get-WinTimeScanCeilingSeconds {
<#
.SYNOPSIS
Computes the per-job watchdog ceiling for a scan worker.

.DESCRIPTION
Pure math helper (unit-testable), per DESIGN section 7 step 6:
TimeoutSeconds x attempts + backoff sum + 15 s grace, where attempts is
1 + RetryCount and the backoff sequence is 1s/2s/4s/... between attempts.

.PARAMETER TimeoutSeconds
Per-attempt registry read budget.

.PARAMETER RetryCount
Number of transport-class retries (attempts = 1 + RetryCount).

.OUTPUTS
[int] ceiling in seconds.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'the trailing noun carries the unit (seconds), per module convention')]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$RetryCount
    )

    $attempts = 1 + $RetryCount
    $backoffSum = 0
    for ($i = 0; $i -lt $RetryCount; $i++) {
        $backoffSum += [int][System.Math]::Pow(2, $i)
    }
    return [int]($TimeoutSeconds * $attempts + $backoffSum + 15)
}

function Invoke-WinTimeScan {
<#
.SYNOPSIS
Fans the registry scan worker out across targets with Start-ThreadJob and
accounts for every target.

.DESCRIPTION
Scan orchestrator (DESIGN section 7). Resolves the worker scriptblock ONCE
via Get-WinTimeRegistryWorker before dispatch (job scriptblocks never reach
back into module state), dispatches up to ThrottleLimit concurrent thread
jobs, owns the single Write-Progress bar (ok/failed/retrying/remaining +
elapsed seconds), enforces the per-job ceiling
(TimeoutSeconds x attempts + backoff + 15 s grace) with Wait-Job -Timeout
bookkeeping and Stop-Job, and guarantees that EVERY target appears in the
output even when the watchdog fires. Five or more consecutive AuthFailure
results stop dispatching and raise a terminating error (credential lockout
guard). On the credential path the workers report SessionEstablished; the
orchestrator tracks those sessions and disconnects them - and only them - in
a finally block that also runs on Ctrl+C.

.PARAMETER Targets
Target objects from Resolve-WinTimeTarget (ComputerName/Domain are used).

.PARAMETER ReadSpec
Array of @{ Path = <HKLM-relative key path>; Recursive = <bool> } entries.

.PARAMETER Credential
Optional alternate credential; enables the IPC$ session path in the worker.

.PARAMETER ThrottleLimit
Maximum concurrent thread jobs (default 32).

.PARAMETER RetryCount
Transport-class retries per target (default 3).

.PARAMETER TimeoutSeconds
Per-attempt registry read budget in seconds (default 30, best-effort).

.PARAMETER Activity
Text for the Write-Progress activity line.

.PARAMETER RunId
Run correlation GUID stamped on every ScanStatus record; defaults to a new
GUID (callers pass their per-invocation RunId).

.OUTPUTS
hashtable @{ Results = <hashtable fqdn -> worker result hashtable>;
             Statuses = <WinTime.ScanStatus[]> }
ScanStatus.OsBuild is left 0 here and filled post-hoc by callers.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Justification = 'DESIGN section 5 mandates OrdinalIgnoreCase path semantics; literal hashtables use the current culture')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Targets,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$ReadSpec,

        [System.Management.Automation.PSCredential]$Credential,

        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 32,

        [ValidateRange(0, 10)]
        [int]$RetryCount = 3,

        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 30,

        [string]$Activity = 'WinTimeHealth scan',

        [guid]$RunId = [guid]::NewGuid()
    )

    function Get-WinTimeTargetName {
        # Canonical FQDN of a target object (string targets tolerated).
        param($TargetObject)
        if ($TargetObject -is [string]) { return $TargetObject }
        if ($null -ne $TargetObject) {
            $nameProperty = $TargetObject.PSObject.Properties['ComputerName']
            if ($null -ne $nameProperty) { return [string]$nameProperty.Value }
        }
        return ''
    }

    function ConvertTo-WinTimeScanStatus {
        # Builds one WinTime.ScanStatus record from a worker result hashtable.
        param($TargetObject, [hashtable]$WorkerResult, [string]$RunIdText)
        $server = Get-WinTimeTargetName -TargetObject $TargetObject
        $domain = ''
        if ($null -ne $TargetObject -and $TargetObject -isnot [string]) {
            $domainProperty = $TargetObject.PSObject.Properties['Domain']
            if ($null -ne $domainProperty) { $domain = [string]$domainProperty.Value }
        }
        $success = $false
        if ($WorkerResult.ContainsKey('Success')) { $success = [bool]$WorkerResult['Success'] }
        $attempts = 0
        if ($WorkerResult.ContainsKey('Attempts') -and $null -ne $WorkerResult['Attempts']) { $attempts = [int]$WorkerResult['Attempts'] }
        $lastError = $null
        if ($WorkerResult.ContainsKey('Error')) { $lastError = $WorkerResult['Error'] }
        $errorClass = $null
        if ($WorkerResult.ContainsKey('ErrorClass')) { $errorClass = $WorkerResult['ErrorClass'] }
        $durationMs = 0
        if ($WorkerResult.ContainsKey('DurationMs') -and $null -ne $WorkerResult['DurationMs']) { $durationMs = [int]$WorkerResult['DurationMs'] }
        return [pscustomobject]@{
            PSTypeName = 'WinTime.ScanStatus'
            Server     = $server
            Domain     = $domain
            Success    = $success
            Attempts   = $attempts
            LastError  = $lastError
            ErrorClass = $errorClass
            DurationMs = $durationMs
            OsBuild    = 0   # filled post-hoc by callers
            RunId      = $RunIdText
            Timestamp  = [System.DateTime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        }
    }

    if (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
        throw 'Start-ThreadJob is not available. On Windows PowerShell 5.1 run: Install-Module ThreadJob -Scope CurrentUser'
    }

    $results = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    $statuses = New-Object System.Collections.Generic.List[object]
    $runIdText = $RunId.ToString()

    if ($null -eq $Targets -or $Targets.Count -eq 0) {
        return @{ Results = $results; Statuses = @() }
    }

    # Resolve worker + connection scriptblocks BEFORE dispatch: job
    # scriptblocks must never reference module functions.
    $worker = Get-WinTimeRegistryWorker
    $connectText = $null
    if ($null -ne $Credential) {
        $connectCommand = Get-Command -Name Connect-WinTimeAdminShare -CommandType Function -ErrorAction SilentlyContinue
        if ($null -eq $connectCommand) {
            throw 'Connect-WinTimeAdminShare is not loaded; the -Credential scan path requires it.'
        }
        $connectText = $connectCommand.ScriptBlock.ToString()
    }

    $ceilingSeconds = Get-WinTimeScanCeilingSeconds -TimeoutSeconds $TimeoutSeconds -RetryCount $RetryCount
    Write-Verbose ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
        'Invoke-WinTimeScan: {0} target(s), throttle {1}, per-attempt timeout {2}s, retries {3}, per-job ceiling {4}s',
        $Targets.Count, $ThrottleLimit, $TimeoutSeconds, $RetryCount, $ceilingSeconds))

    $pending = New-Object System.Collections.Queue
    foreach ($target in $Targets) { $pending.Enqueue($target) }
    $running = @{}   # job InstanceId -> @{ Job; Target; Deadline; Dispatched }
    $sessionsToClean = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    $totalCount = $Targets.Count
    $okCount = 0
    $failedCount = 0
    $consecutiveAuthFailures = 0
    $authAborted = $false
    $overall = [System.Diagnostics.Stopwatch]::StartNew()
    $progressId = 1

    try {
        while ((($pending.Count -gt 0) -and -not $authAborted) -or ($running.Count -gt 0)) {

            # --- dispatch up to the throttle (stops on auth abort) ---
            while ($pending.Count -gt 0 -and $running.Count -lt $ThrottleLimit -and -not $authAborted) {
                $target = $pending.Dequeue()
                $options = @{ TimeoutSeconds = $TimeoutSeconds; RetryCount = $RetryCount }
                if ($null -ne $Credential) {
                    $options['Credential'] = $Credential
                    $options['ConnectScript'] = $connectText
                }
                # Clone the spec per job so workers can treat inputs read-only.
                $spec = @()
                foreach ($specEntry in @($ReadSpec)) {
                    if ($specEntry -is [hashtable]) { $spec += , $specEntry.Clone() } else { $spec += , $specEntry }
                }
                $job = Start-ThreadJob -ScriptBlock $worker -ArgumentList @($target, $spec, $options) -ThrottleLimit $ThrottleLimit
                $running[$job.InstanceId] = @{
                    Job        = $job
                    Target     = $target
                    Deadline   = (Get-Date).AddSeconds($ceilingSeconds)
                    Dispatched = (Get-Date)
                }
            }

            # --- brief wait for any state change (Wait-Job bookkeeping) ---
            $activeJobs = @()
            foreach ($runningEntry in $running.Values) { $activeJobs += $runningEntry['Job'] }
            if ($activeJobs.Count -gt 0) {
                $null = Wait-Job -Job $activeJobs -Any -Timeout 1 -ErrorAction SilentlyContinue
            }

            # --- harvest finished jobs and fire the watchdog ---
            foreach ($instanceId in @($running.Keys)) {
                $entry = $running[$instanceId]
                $job = $entry['Job']
                $target = $entry['Target']
                $fqdn = Get-WinTimeTargetName -TargetObject $target
                if ([string]::IsNullOrEmpty($fqdn)) { $fqdn = ('unknown-target-{0}' -f $instanceId) }
                $workerResult = $null

                if ($job.State -eq 'Completed' -or $job.State -eq 'Failed' -or $job.State -eq 'Stopped') {
                    $jobErrors = $null
                    $jobOutput = @(Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErrors)
                    foreach ($item in $jobOutput) { if ($item -is [hashtable]) { $workerResult = $item } }
                    if ($null -eq $workerResult) {
                        # Job died without producing a result: still accounted.
                        $reason = ''
                        if ($null -ne $job.JobStateInfo -and $null -ne $job.JobStateInfo.Reason) {
                            $reason = [string]$job.JobStateInfo.Reason.Message
                        } elseif ($null -ne $jobErrors -and $jobErrors.Count -gt 0) {
                            $reason = [string]$jobErrors[0]
                        }
                        $workerResult = @{
                            ComputerName       = $fqdn
                            Success            = $false
                            Attempts           = 0
                            Error              = ('scan job produced no result: {0}' -f $reason)
                            ErrorClass         = 'Unknown'
                            DurationMs         = [int]((Get-Date) - $entry['Dispatched']).TotalMilliseconds
                            Tree               = $null
                            # Session state unknown on the credential path:
                            # default to $false (never disconnect). The worker
                            # only sets SessionEstablished=$true after it has
                            # confirmed *this* call created the session (never
                            # for a reused same-user session); if the job died
                            # or was abandoned before reporting a result we
                            # cannot know whether it created, reused, or never
                            # reached a session at all, so treating it as
                            # "established" here would risk tearing down a
                            # session this run did not create (or one it
                            # created but hasn't finished using).
                            SessionEstablished = $false
                        }
                    }
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    $running.Remove($instanceId)
                } elseif ((Get-Date) -gt $entry['Deadline']) {
                    # Per-job ceiling exceeded: stop the job as bookkeeping and
                    # account the target as Timeout (totals must always add up).
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    $running.Remove($instanceId)
                    $workerResult = @{
                        ComputerName       = $fqdn
                        Success            = $false
                        Attempts           = (1 + $RetryCount)
                        Error              = ('scan exceeded the per-target ceiling of {0}s - stopped by watchdog' -f $ceilingSeconds)
                        ErrorClass         = 'Timeout'
                        DurationMs         = [int]((Get-Date) - $entry['Dispatched']).TotalMilliseconds
                        Tree               = $null
                        # See the "job produced no result" branch above: the
                        # session outcome for this abandoned job is unknown,
                        # so default to $false rather than risk disconnecting
                        # a session this run did not establish.
                        SessionEstablished = $false
                    }
                }

                if ($null -ne $workerResult) {
                    $results[$fqdn] = $workerResult
                    if ($null -ne $Credential -and $workerResult.ContainsKey('SessionEstablished') -and [bool]$workerResult['SessionEstablished']) {
                        $sessionsToClean[$fqdn] = $true
                    }
                    $statuses.Add((ConvertTo-WinTimeScanStatus -TargetObject $target -WorkerResult $workerResult -RunIdText $runIdText))
                    $resultSuccess = $false
                    if ($workerResult.ContainsKey('Success')) { $resultSuccess = [bool]$workerResult['Success'] }
                    if ($resultSuccess) {
                        $okCount++
                        $consecutiveAuthFailures = 0
                    } else {
                        $failedCount++
                        $resultClass = $null
                        if ($workerResult.ContainsKey('ErrorClass')) { $resultClass = $workerResult['ErrorClass'] }
                        if ($resultClass -eq 'AuthFailure') {
                            $consecutiveAuthFailures++
                            if ($consecutiveAuthFailures -ge 5) { $authAborted = $true }
                        } else {
                            $consecutiveAuthFailures = 0
                        }
                    }
                }
            }

            # --- the single progress bar ---
            $completedCount = $okCount + $failedCount
            $retryingCount = 0
            foreach ($runningEntry in $running.Values) {
                # Approximation: a job past its first attempt budget is retrying.
                if (((Get-Date) - $runningEntry['Dispatched']).TotalSeconds -gt ($TimeoutSeconds + 2)) { $retryingCount++ }
            }
            $remainingCount = $pending.Count + $running.Count
            $percentComplete = 0
            if ($totalCount -gt 0) { $percentComplete = [int](100 * $completedCount / $totalCount) }
            if ($percentComplete -gt 100) { $percentComplete = 100 }
            $progressStatus = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
                'ok {0}  failed {1}  retrying {2}  remaining {3}  elapsed {4}s',
                $okCount, $failedCount, $retryingCount, $remainingCount, [int]$overall.Elapsed.TotalSeconds)
            Write-Progress -Id $progressId -Activity $Activity -Status $progressStatus -PercentComplete $percentComplete
        }

        if ($authAborted) {
            # Account for every undispatched target, then abort before lockout.
            while ($pending.Count -gt 0) {
                $target = $pending.Dequeue()
                $fqdn = Get-WinTimeTargetName -TargetObject $target
                if ([string]::IsNullOrEmpty($fqdn)) { $fqdn = ('unknown-target-{0}' -f $pending.Count) }
                $workerResult = @{
                    ComputerName       = $fqdn
                    Success            = $false
                    Attempts           = 0
                    Error              = 'not attempted - run aborted after 5 consecutive credential failures'
                    ErrorClass         = 'AuthFailure'
                    DurationMs         = 0
                    Tree               = $null
                    SessionEstablished = $false
                }
                $results[$fqdn] = $workerResult
                $statuses.Add((ConvertTo-WinTimeScanStatus -TargetObject $target -WorkerResult $workerResult -RunIdText $runIdText))
                $failedCount++
            }
            $abortMessage = 'credential appears invalid - aborting before lockout (5 consecutive AuthFailure results)'
            $abortException = New-Object System.InvalidOperationException ($abortMessage)
            $abortRecord = New-Object System.Management.Automation.ErrorRecord (
                $abortException, 'AuthFailureAbort', [System.Management.Automation.ErrorCategory]::AuthenticationError, $statuses.ToArray())
            $PSCmdlet.ThrowTerminatingError($abortRecord)
        }

        return @{ Results = $results; Statuses = $statuses.ToArray() }
    } finally {
        # Runs on normal exit, terminating error and Ctrl+C alike.
        foreach ($instanceId in @($running.Keys)) {
            $entry = $running[$instanceId]
            Stop-Job -Job $entry['Job'] -ErrorAction SilentlyContinue
            Remove-Job -Job $entry['Job'] -Force -ErrorAction SilentlyContinue
        }
        # Tear down only the sessions THIS run established.
        if ($null -ne $Credential) {
            foreach ($sessionHost in @($sessionsToClean.Keys)) {
                try {
                    Disconnect-WinTimeAdminShare -ComputerName $sessionHost
                } catch {
                    Write-Verbose ('session cleanup for {0} failed: {1}' -f $sessionHost, $_.Exception.Message)
                }
            }
        }
        Write-Progress -Id $progressId -Activity $Activity -Completed
    }
}
