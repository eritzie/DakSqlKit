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

        When -RepositoryDatabase is specified without -Repository, results are persisted
        to that database on each audited instance itself (local persistence).

        Supported frameworks and implementation status:
            CIS      — CIS Microsoft SQL Server 2025 Benchmark v1.0.0  (full — 48 checks)
            DbConfig — Instance/DB configuration health and security    (full — 92 checks)
            SOX      — Sarbanes-Oxley ITGC (AC/CM/OP/BA/LS/AL)           (full — 40 checks)
            STIG     — DISA SQL Server 2022 STIG V1R4/V1R3               (full — 52 checks)
            PCI      — PCI DSS v4.0.1                                    (full — 34 checks)
            SOC2     — SOC 2 TSC CC1/CC4–CC9 (database-relevant)          (full — 31 checks)

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
        Name of the AuditKit persistence database. Default: DBAOps.
        When specified without -Repository, results are saved to this database on
        each audited instance (local persistence mode).

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
        # Persist to the audited instance itself (local persistence)
        Invoke-DakAuditSuite -SqlInstance SQL-DEV-01 -Framework CIS -RepositoryDatabase DBAOps

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
        [ValidateSet("CIS", "SOX", "STIG", "PCI", "SOC2", "DbConfig", "All")]
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
        $credSplat      = @{}
        if ($SqlCredential) { $credSplat.SqlCredential = $SqlCredential }
        # Local persistence: -RepositoryDatabase supplied without -Repository → save to each audited instance
        $useLocalRepo = $PSBoundParameters.ContainsKey('RepositoryDatabase') -and -not $PSBoundParameters.ContainsKey('Repository')
        $saveResults  = $Repository -or $useLocalRepo
    }

    process {
        foreach ($instance in $SqlInstance) {
            Write-Verbose "[$instance] Starting audit — frameworks: $($Framework -join ", ")"

            if ($runAll -or $Framework -contains "CIS") {
                Write-Verbose "[$instance] Running CIS checks"
                if ($saveResults) {
                    $cisResults = Test-DakCISBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $cisResults) { $allResults += $r }
                } else {
                    Test-DakCISBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            if ($runAll -or $Framework -contains "DbConfig") {
                Write-Verbose "[$instance] Running DbConfig checks"
                if ($saveResults) {
                    $dbcResults = Test-DakDbConfig -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $dbcResults) { $allResults += $r }
                } else {
                    Test-DakDbConfig -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            if ($runAll -or $Framework -contains "SOX") {
                Write-Verbose "[$instance] Running SOX checks"
                if ($saveResults) {
                    $soxResults = Test-DakSOXBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $soxResults) { $allResults += $r }
                } else {
                    Test-DakSOXBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            if ($runAll -or $Framework -contains "PCI") {
                Write-Verbose "[$instance] Running PCI checks"
                if ($saveResults) {
                    $pciResults = Test-DakPCIBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $pciResults) { $allResults += $r }
                } else {
                    Test-DakPCIBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            if ($runAll -or $Framework -contains "SOC2") {
                Write-Verbose "[$instance] Running SOC 2 checks"
                if ($saveResults) {
                    $soc2Results = Test-DakSOC2Benchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $soc2Results) { $allResults += $r }
                } else {
                    Test-DakSOC2Benchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }

            if ($runAll -or $Framework -contains "STIG") {
                Write-Verbose "[$instance] Running STIG checks"
                if ($saveResults) {
                    $stigResults = Test-DakSTIGBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly
                    foreach ($r in $stigResults) { $allResults += $r }
                } else {
                    Test-DakSTIGBenchmark -SqlInstance $instance @credSplat -FailedOnly:$FailedOnly -Quiet
                }
            }
        }
    }

    end {
        if ($saveResults -and $allResults.Count -gt 0) {
            # One AuditRun record per audited instance for clean trend queries.
            # Local persistence mode: each group saves to its own SqlInstance.
            $allResults | Group-Object SqlInstance | ForEach-Object {
                $grp        = $_.Group
                $repoTarget = if ($Repository) { $Repository } else { $_.Name }
                $repoSplat  = @{
                    Repository = $repoTarget
                    Database   = $RepositoryDatabase
                    Schema     = $RepositorySchema
                }
                if ($RepositoryCredential) { $repoSplat.SqlCredential = $RepositoryCredential }
                Write-Host "Saving $($grp.Count) results for $($_.Name) to [$repoTarget].[$RepositoryDatabase].[$RepositorySchema]..." -ForegroundColor Cyan
                try {
                    $grp | Save-DakAuditResult @repoSplat
                } catch {
                    Write-Warning "Failed to save results for $($_.Name): $($_.Exception.Message)"
                }
            }
        }
    }
}
