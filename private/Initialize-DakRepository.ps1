function Initialize-DakRepository {
    <#
    .SYNOPSIS
        Ensures the AuditKit schema and tables exist in the target database.
    .DESCRIPTION
        Called by Save-DakAuditResult. Creates the repository database via New-DbaDatabase
        if it does not exist, then creates the target schema and tables (AuditRun,
        AuditResult) and two reporting views if they are missing. Safe to call repeatedly —
        all DDL uses IF NOT EXISTS guards and adds missing columns for in-place upgrades.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SqlInstance,

        [Parameter()]
        [string]$Database = "DbAuditKit",

        [Parameter()]
        [string]$Schema = "audit",

        [Parameter()]
        [PSCredential]$SqlCredential
    )

    $ErrorActionPreference = "Stop"

    $connSplat = @{ SqlInstance = $SqlInstance }
    if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }

    $dbSplat = @{ SqlInstance = $SqlInstance; Database = $Database }
    if ($SqlCredential) { $dbSplat.SqlCredential = $SqlCredential }

    # ── Create database if absent ─────────────────────────────────────────────
    if (-not (Get-DbaDatabase @connSplat -Database $Database -ErrorAction SilentlyContinue)) {
        Write-Verbose "Creating repository database [$Database] on $SqlInstance"
        $null = New-DbaDatabase @connSplat -Name $Database
    }

    # ── Schema + tables ───────────────────────────────────────────────────────
    Write-Verbose "Provisioning schema and tables in [$SqlInstance].[$Database]"
    $tableSql = @"
SET NOCOUNT ON;

IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'$Schema')
    EXEC('CREATE SCHEMA [$Schema]');

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = N'AuditRun' AND schema_id = SCHEMA_ID('$Schema'))
BEGIN
    CREATE TABLE [$Schema].AuditRun (
        RunId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_AuditRun PRIMARY KEY DEFAULT NEWID(),
        RunDate      DATETIME2(0)     NOT NULL DEFAULT SYSDATETIME(),
        RunBy        NVARCHAR(255)    NOT NULL,
        SqlInstances NVARCHAR(MAX)    NOT NULL,
        Frameworks   NVARCHAR(255)    NULL,
        Platform     NVARCHAR(100)    NULL,
        Version      NVARCHAR(50)     NULL,
        TotalChecks  INT              NULL,
        PassCount    INT              NULL,
        FailCount    INT              NULL,
        WarnCount    INT              NULL,
        ManuCount    INT              NULL
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = N'AuditResult' AND schema_id = SCHEMA_ID('$Schema'))
BEGIN
    CREATE TABLE [$Schema].AuditResult (
        ResultId       INT              NOT NULL IDENTITY(1,1) CONSTRAINT PK_AuditResult PRIMARY KEY,
        RunId          UNIQUEIDENTIFIER NOT NULL,
        RunDate        DATETIME2(0)     NOT NULL,
        ComputerName   NVARCHAR(255)    NOT NULL,
        SqlInstance    NVARCHAR(255)    NOT NULL,
        Framework      NVARCHAR(20)     NOT NULL,
        CheckId        NVARCHAR(20)     NOT NULL,
        CheckName      NVARCHAR(255)    NOT NULL,
        Category       NVARCHAR(100)    NULL,
        AssessmentType NVARCHAR(20)     NULL,
        Priority       NVARCHAR(20)     NULL,
        Status         NVARCHAR(20)     NOT NULL,
        Compliant      BIT              NULL,
        CurrentValue   NVARCHAR(MAX)    NULL,
        ExpectedValue  NVARCHAR(MAX)    NULL,
        Remediation    NVARCHAR(MAX)    NULL,
        Reference      NVARCHAR(255)    NULL
    );
END;

-- Column migration: add columns introduced after initial release
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('[$Schema].AuditResult') AND name = N'AssessmentType')
    ALTER TABLE [$Schema].AuditResult ADD AssessmentType NVARCHAR(20) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('[$Schema].AuditResult') AND name = N'Priority')
    ALTER TABLE [$Schema].AuditResult ADD Priority NVARCHAR(20) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('[$Schema].AuditRun') AND name = N'Platform')
    ALTER TABLE [$Schema].AuditRun ADD Platform NVARCHAR(100) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('[$Schema].AuditRun') AND name = N'Version')
    ALTER TABLE [$Schema].AuditRun ADD Version NVARCHAR(50) NULL;
"@

    Invoke-DbaQuery @dbSplat -Query $tableSql -EnableException

    # ── Views (drop + recreate so definition stays current) ───────────────────
    $dropViews = @"
IF OBJECT_ID('[$Schema].vw_LatestRunResults', 'V') IS NOT NULL DROP VIEW [$Schema].vw_LatestRunResults;
IF OBJECT_ID('[$Schema].vw_FailureTrend',     'V') IS NOT NULL DROP VIEW [$Schema].vw_FailureTrend;
"@
    Invoke-DbaQuery @dbSplat -Query $dropViews -EnableException

    $createLatest = @"
CREATE VIEW [$Schema].vw_LatestRunResults AS
/*  Most recent result per check per instance. Use for current-state dashboards. */
WITH ranked AS (
    SELECT *,
           ROW_NUMBER() OVER (
               PARTITION BY SqlInstance, Framework, CheckId
               ORDER BY RunDate DESC
           ) AS rn
    FROM [$Schema].AuditResult
)
SELECT ResultId, RunId, RunDate, ComputerName, SqlInstance,
       Framework, CheckId, CheckName, Category, AssessmentType,
       Priority, Status, Compliant, CurrentValue, ExpectedValue,
       Remediation, Reference
FROM   ranked
WHERE  rn = 1;
"@
    Invoke-DbaQuery @dbSplat -Query $createLatest -EnableException

    $createTrend = @"
CREATE VIEW [$Schema].vw_FailureTrend AS
/*  Failure counts per instance per run date. Use for trend tracking. */
SELECT  SqlInstance,
        Framework,
        CAST(RunDate AS DATE)                                   AS RunDay,
        COUNT(CASE WHEN Status = 'Fail'    THEN 1 END)         AS FailCount,
        COUNT(CASE WHEN Status = 'Warning' THEN 1 END)         AS WarnCount,
        COUNT(CASE WHEN Status = 'Manual'  THEN 1 END)         AS ManuCount,
        COUNT(*)                                                AS TotalChecks
FROM    [$Schema].AuditResult
GROUP BY SqlInstance, Framework, CAST(RunDate AS DATE);
"@
    Invoke-DbaQuery @dbSplat -Query $createTrend -EnableException
    Write-Verbose "Schema ready in [$SqlInstance].[$Database].[$Schema]"
}
