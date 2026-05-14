function Invoke-DakAuditSuite {
    <#
    .SYNOPSIS
        Runs one or more security audit frameworks against SQL Server instances.

    .DESCRIPTION
        Orchestrates the DakSqlKit framework check functions against one or more
        SQL Server instances. Returns pipeline-friendly PSCustomObjects (type
        DakSqlKit.AuditResult) for consumption with Format-Table, Export-Csv,
        Export-Excel (ImportExcel), ConvertTo-Json, Out-GridView, etc.

        When -Repository is specified, results are persisted to the AuditKit tracking
        database on that instance. The database and schema are created automatically
        on first use — no pre-requisite script required.

        Supported frameworks and implementation status:
            CIS   — CIS Microsoft SQL Server 2025 Benchmark v1.0.0  (full — 48 checks)
            SOX   — Sarbanes-Oxley IT general controls               (pending)
            STIG  — DISA SQL Server STIG                             (pending)
            PCI   — PCI-DSS v4.0                                     (pending)
            SOC2  — SOC 2 Trust Service Criteria                     (pending)

    .PARAMETER SqlInstance
        One or more SQL Server instances to audit. Accepts pipeline input by value
        and by property name (compatible with Get-DbaRegisteredServer output).

    .PARAMETER SqlCredential
        SQL Server authentication credential for the audited instance(s).
        Omit for Windows authentication.

    .PARAMETER Framework
        One or more frameworks to run: CIS, SOX, STIG, PCI, SOC2, or All.
        Default: All (runs every implemented framework).

    .PARAMETER FailedOnly
        Return only checks with Status of Fail or Warning.

    .PARAMETER Repository
        SQL Server instance hosting the AuditKit persistence database.
        The database and schema are created automatically if they do not exist.
        Specify a different instance here than -SqlInstance to use a centralized
        audit repository.

    .PARAMETER RepositoryDatabase
        Name of the AuditKit persistence database. Default: AuditKit.

    .PARAMETER RepositoryCredential
        SQL Server authentication credential for the repository instance.
        Omit for Windows authentication (most common when Repository is on your
        own network and the audited instances are remote).

    .EXAMPLE
        Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS

    .EXAMPLE
        Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        # Pipe multiple instances from Central Management Server
        Get-DbaRegisteredServer -Group Production | Invoke-DakAuditSuite -Framework CIS

    .EXAMPLE
        # Persist to a centralized audit repository on a separate instance
        Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS -Repository SQLAUDIT01

    .EXAMPLE
        # Persist and also consume results locally
        $results = Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS -Repository SQLAUDIT01
        $results | Where-Object Status -eq 'Fail' | Select-Object CheckId, Priority, Remediation
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("CIS", "SOX", "STIG", "PCI", "SOC2", "All")]
        [string[]]$Framework = "All",

        [Parameter()]
        [switch]$FailedOnly,

        [Parameter()]
        [string]$Repository,

        [Parameter()]
        [string]$RepositoryDatabase = "DBAOps",

        [Parameter()]
        [string]$RepositorySchema = "audit",

        [Parameter()]
        [PSCredential]$RepositoryCredential
    )

    begin {
        $ErrorActionPreference = "Stop"
        $runAll         = $Framework -contains "All"
        $allResults     = @()
        $notImplemented = @()
        $credSplat      = @{}
        if ($SqlCredential) { $credSplat.SqlCredential = $SqlCredential }
    }

    process {
        foreach ($instance in $SqlInstance) {
            Write-Verbose "[$instance] Starting audit — frameworks: $($Framework -join ", ")"

            if ($runAll -or $Framework -contains "CIS") {
                Write-Verbose "[$instance] Running CIS checks"
                if ($Repository) {
                    # Write-Host status lines stream in real-time; collect objects for persistence
                    $cisResults = Test-DakCISBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $cisResults) { $allResults += $r }
                } else {
                    # Stream objects to the pipeline; suppress Write-Host for clean output
                    Test-DakCISBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            foreach ($fw in @("SOX", "STIG", "PCI", "SOC2")) {
                if ($runAll -or $Framework -contains $fw) {
                    if ($fw -notin $notImplemented) {
                        Write-Warning "$fw checks are not yet implemented. Skipping."
                        $notImplemented += $fw
                    }
                }
            }
        }
    }

    end {
        if ($Repository -and $allResults.Count -gt 0) {
            $repoSplat = @{
                Repository = $Repository
                Database   = $RepositoryDatabase
                Schema     = $RepositorySchema
            }
            if ($RepositoryCredential) { $repoSplat.SqlCredential = $RepositoryCredential }

            # One AuditRun record per audited instance for clean trend queries
            $allResults | Group-Object SqlInstance | ForEach-Object {
                $grp = $_.Group
                Write-Host "Saving $($grp.Count) results for $($_.Name) to [$Repository].[$RepositoryDatabase].[$RepositorySchema]..." -ForegroundColor Cyan
                try {
                    $grp | Save-DakAuditResult @repoSplat
                } catch {
                    Write-Warning "Failed to save results for $($_.Name): $($_.Exception.Message)"
                }
            }
        }
    }
}
