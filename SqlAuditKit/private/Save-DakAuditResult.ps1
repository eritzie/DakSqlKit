function Save-DakAuditResult {
    <#
    .SYNOPSIS
        Persists audit result objects to the AuditKit repository tables.
    .DESCRIPTION
        Called by Invoke-DakAuditSuite when -Repository is specified. Initializes the
        target schema on first use (creates tables if absent), writes one AuditRun
        header row, then inserts all result rows into AuditResult.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Repository,

        [Parameter()]
        [string]$Database = "DBAOps",

        [Parameter()]
        [string]$Schema = "audit",

        [Parameter()]
        [PSCredential]$SqlCredential
    )

    begin {
        $ErrorActionPreference = "Stop"

        $connSplat = @{ SqlInstance = $Repository; Database = $Database }
        if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }

        $splatInit = @{
            SqlInstance   = $Repository
            Database      = $Database
            Schema        = $Schema
            ErrorAction   = "Stop"
        }
        if ($SqlCredential) { $splatInit.SqlCredential = $SqlCredential }
        Initialize-DakRepository @splatInit

        $runId      = [System.Guid]::NewGuid()
        $runDate    = Get-Date
        $count      = 0
        $passCount  = 0
        $failCount  = 0
        $warnCount  = 0
        $manuCount  = 0
        $sqlInstances = @()
        $frameworks   = @()
    }

    process {
        $resultSql = @"
INSERT INTO [$Schema].AuditResult
    (RunId, RunDate, ComputerName, SqlInstance, Framework, CheckId,
     CheckName, Category, AssessmentType, Priority, Status, Compliant,
     CurrentValue, ExpectedValue, Remediation, Reference)
VALUES
    (@RunId, @RunDate, @ComputerName, @SqlInstance, @Framework, @CheckId,
     @CheckName, @Category, @AssessmentType, @Priority, @Status, @Compliant,
     @CurrentValue, @ExpectedValue, @Remediation, @Reference);
"@
        foreach ($r in $InputObject) {
            try {
                $splatResult = @{
                    Query         = $resultSql
                    EnableException = $true
                    SqlParameters = @{
                        RunId          = $runId
                        RunDate        = $runDate
                        ComputerName   = $r.ComputerName   ?? ""
                        SqlInstance    = $r.SqlInstance    ?? ""
                        Framework      = $r.Framework      ?? ""
                        CheckId        = $r.CheckId        ?? ""
                        CheckName      = $r.CheckName      ?? ""
                        Category       = $r.Category       ?? [DBNull]::Value
                        AssessmentType = $r.AssessmentType ?? [DBNull]::Value
                        Priority       = $r.Priority       ?? [DBNull]::Value
                        Status         = $r.Status         ?? ""
                        Compliant      = if ($null -eq $r.Compliant) { [DBNull]::Value } else { [int]$r.Compliant }
                        CurrentValue   = $r.CurrentValue   ?? [DBNull]::Value
                        ExpectedValue  = $r.ExpectedValue  ?? [DBNull]::Value
                        Remediation    = $r.Remediation    ?? [DBNull]::Value
                        Reference      = $r.Reference      ?? [DBNull]::Value
                    }
                }
                Invoke-DbaQuery @connSplat @splatResult
            } catch {
                Write-Warning "Failed to persist result $($r.CheckId) for $($r.SqlInstance): $($_.Exception.Message)"
            }

            $count++
            if ($r.Status -eq "Pass")    { $passCount++ }
            elseif ($r.Status -eq "Fail")    { $failCount++ }
            elseif ($r.Status -eq "Warning") { $warnCount++ }
            elseif ($r.Status -eq "Manual")  { $manuCount++ }

            $inst = $r.SqlInstance ?? ""
            if ($inst -and $inst -notin $sqlInstances) { $sqlInstances += $inst }

            $fw = $r.Framework ?? ""
            if ($fw -and $fw -notin $frameworks) { $frameworks += $fw }
        }
    }

    end {
        if ($count -eq 0) { return }

        $sqlInstanceStr = $sqlInstances -join ", "
        $frameworkStr   = $frameworks   -join ", "
        $runBy          = "$env:USERDOMAIN\$env:USERNAME"

        # ── AuditRun header ───────────────────────────────────────────────────
        $runSql = @"
INSERT INTO [$Schema].AuditRun
    (RunId, RunDate, RunBy, SqlInstances, Frameworks, TotalChecks, PassCount, FailCount, WarnCount, ManuCount)
VALUES
    (@RunId, @RunDate, @RunBy, @SqlInstances, @Frameworks, @TotalChecks, @PassCount, @FailCount, @WarnCount, @ManuCount);
"@
        try {
            $splatRun = @{
                Query         = $runSql
                EnableException = $true
                SqlParameters = @{
                    RunId        = $runId
                    RunDate      = $runDate
                    RunBy        = $runBy
                    SqlInstances = $sqlInstanceStr
                    Frameworks   = $frameworkStr
                    TotalChecks  = $count
                    PassCount    = $passCount
                    FailCount    = $failCount
                    WarnCount    = $warnCount
                    ManuCount    = $manuCount
                }
            }
            Invoke-DbaQuery @connSplat @splatRun
        } catch {
            Write-Warning "Failed to write AuditRun record: $($_.Exception.Message)"
        }

        Write-Host "Done — RunId: $runId" -ForegroundColor Green
        Write-Verbose "Saved $count results to [$Repository].[$Database].[$Schema] — RunId $runId"
    }
}
