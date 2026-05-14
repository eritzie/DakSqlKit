/*
    Create-AuditDatabase.sql
    Reference DDL for the AuditKit persistence tables.

    You do NOT need to run this manually — Invoke-DakAuditSuite -Repository creates
    the schema and tables automatically on first use via Initialize-DakRepository.

    Run this script if you prefer to pre-provision the objects yourself, e.g. to
    review the schema before the first audit run or to create them under a different
    schema name.

    Defaults:  database = DBAOps,  schema = audit
*/

USE [DBAOps];
GO

IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'audit')
    EXEC('CREATE SCHEMA [audit]');
GO

-- ── audit.AuditRun ────────────────────────────────────────────────────────────
-- One row per Invoke-DakAuditSuite call per audited instance.
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = N'AuditRun' AND schema_id = SCHEMA_ID('audit'))
BEGIN
    CREATE TABLE audit.AuditRun (
        RunId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_AuditRun PRIMARY KEY DEFAULT NEWID(),
        RunDate      DATETIME2(0)     NOT NULL DEFAULT SYSDATETIME(),
        RunBy        NVARCHAR(255)    NOT NULL,
        SqlInstances NVARCHAR(MAX)    NOT NULL,   -- comma-separated; typically one instance per row
        Frameworks   NVARCHAR(255)    NULL,
        TotalChecks  INT              NULL,
        PassCount    INT              NULL,
        FailCount    INT              NULL,
        WarnCount    INT              NULL,
        ManuCount    INT              NULL
    );
    PRINT 'Table audit.AuditRun created.';
END
ELSE
    PRINT 'Table audit.AuditRun already exists — skipping.';
GO

-- ── audit.AuditResult ─────────────────────────────────────────────────────────
-- One row per check per instance per run.
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = N'AuditResult' AND schema_id = SCHEMA_ID('audit'))
BEGIN
    CREATE TABLE audit.AuditResult (
        ResultId       INT              NOT NULL IDENTITY(1,1) CONSTRAINT PK_AuditResult PRIMARY KEY,
        RunId          UNIQUEIDENTIFIER NOT NULL,
        RunDate        DATETIME2(0)     NOT NULL,
        ComputerName   NVARCHAR(255)    NOT NULL,
        SqlInstance    NVARCHAR(255)    NOT NULL,
        Framework      NVARCHAR(20)     NOT NULL,   -- CIS | SOX | STIG | PCI | SOC2
        CheckId        NVARCHAR(20)     NOT NULL,
        CheckName      NVARCHAR(255)    NOT NULL,
        Category       NVARCHAR(100)    NULL,
        AssessmentType NVARCHAR(20)     NULL,        -- Automated | Manual
        Priority       NVARCHAR(20)     NULL,        -- Critical | High | Medium | Low | Info
        Status         NVARCHAR(20)     NOT NULL,    -- Pass | Fail | Warning | Manual | Data | Skip | Error
        Compliant      BIT              NULL,
        CurrentValue   NVARCHAR(MAX)    NULL,
        ExpectedValue  NVARCHAR(MAX)    NULL,
        Remediation    NVARCHAR(MAX)    NULL,
        Reference      NVARCHAR(255)    NULL
    );
    PRINT 'Table audit.AuditResult created.';
END
ELSE
    PRINT 'Table audit.AuditResult already exists — skipping.';
GO

-- ── Views ─────────────────────────────────────────────────────────────────────
IF OBJECT_ID('audit.vw_LatestRunResults', 'V') IS NOT NULL DROP VIEW audit.vw_LatestRunResults;
GO

CREATE VIEW audit.vw_LatestRunResults AS
/*  Most recent result per check per instance. Use for current-state dashboards. */
WITH ranked AS (
    SELECT *,
           ROW_NUMBER() OVER (
               PARTITION BY SqlInstance, Framework, CheckId
               ORDER BY RunDate DESC
           ) AS rn
    FROM audit.AuditResult
)
SELECT ResultId, RunId, RunDate, ComputerName, SqlInstance,
       Framework, CheckId, CheckName, Category, AssessmentType,
       Priority, Status, Compliant, CurrentValue, ExpectedValue,
       Remediation, Reference
FROM   ranked
WHERE  rn = 1;
GO

IF OBJECT_ID('audit.vw_FailureTrend', 'V') IS NOT NULL DROP VIEW audit.vw_FailureTrend;
GO

CREATE VIEW audit.vw_FailureTrend AS
/*  Failure counts per instance per run date. Use for trend tracking. */
SELECT  SqlInstance,
        Framework,
        CAST(RunDate AS DATE)                           AS RunDay,
        COUNT(CASE WHEN Status = 'Fail'    THEN 1 END) AS FailCount,
        COUNT(CASE WHEN Status = 'Warning' THEN 1 END) AS WarnCount,
        COUNT(CASE WHEN Status = 'Manual'  THEN 1 END) AS ManuCount,
        COUNT(*)                                        AS TotalChecks
FROM    audit.AuditResult
GROUP BY SqlInstance, Framework, CAST(RunDate AS DATE);
GO

PRINT 'AuditKit schema creation complete.';
