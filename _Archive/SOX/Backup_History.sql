/*
    Backup_History.sql
    Scope: Server
    Purpose: Report recent database backup history and backup job schedules
             to verify backups are running as expected.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Returns two result sets:
      1. Most recent backup per database per type (from msdb.dbo.backupset).
      2. Agent job schedules — last run and next run for backup jobs.
    - Backup history captures backups regardless of how they were initiated.
    - Defaults to last 30 days. Adjust @DaysBack as needed.
    - Databases with no recent backup will appear with NULL backup columns.
    - Job schedules query filters to Ola Hallengren's backup jobs by default.
      Adjust the WHERE clause if using a different backup solution.
    
    Dependencies:
    - Backup job schedules query assumes Ola Hallengren's Maintenance Solution.
      https://ola.hallengren.com
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Backup_History.sql';
PRINT '============================================';
PRINT ' ';

-- ── Adjust lookback window here ──
DECLARE @DaysBack int = 30;

-- ── Most recent backup per database per type ──
SELECT
    @@SERVERNAME AS [ServerName],
    d.[name] AS [Database],
    d.[state_desc] AS [DatabaseState],
    d.[recovery_model_desc] AS [RecoveryModel],
    b.[type] AS [BackupType],
    CASE b.[type]
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Log'
        ELSE b.[type]
    END AS [BackupTypeDesc],
    b.[backup_start_date] AS [LastBackupStart],
    b.[backup_finish_date] AS [LastBackupFinish],
    DATEDIFF(SECOND, b.[backup_start_date], b.[backup_finish_date]) AS [DurationSeconds],
    CAST(b.[backup_size] / 1048576.0 AS decimal(12,2)) AS [BackupSizeMB],
    CAST(b.[compressed_backup_size] / 1048576.0 AS decimal(12,2)) AS [CompressedSizeMB],
    b.[server_name] AS [BackupServer],
    b.[user_name] AS [BackupRunBy]
FROM sys.databases d
LEFT JOIN (
    SELECT 
        [database_name], [type], [backup_start_date], [backup_finish_date],
        [backup_size], [compressed_backup_size], [server_name], [user_name],
        ROW_NUMBER() OVER (
            PARTITION BY [database_name], [type] 
            ORDER BY [backup_finish_date] DESC
        ) AS rn
    FROM msdb.dbo.backupset
    WHERE [backup_finish_date] >= DATEADD(DAY, -@DaysBack, GETDATE())
) b ON d.[name] = b.[database_name] AND b.rn = 1
WHERE d.[source_database_id] IS NULL  -- Skip snapshots
ORDER BY d.[name], b.[type];

-- ── Backup Job Schedules ─────────────────────────────────────
-- Shows last run and next scheduled run for backup-related agent jobs.
-- Assumes Ola Hallengren's Maintenance Solution job naming convention.
-- Adjust the WHERE clause if using a different backup solution.
-- The wrapper's Invoke-DbaQuery will return this as a second result 
-- set. If running in SSMS, you'll see two grids.

SELECT
    @@SERVERNAME AS [ServerName],
    job.[name] AS [JobName],
    msdb.dbo.agent_datetime(MAX(hist.[run_date]), MAX(hist.[run_time])) AS [LastRunDate],
    msdb.dbo.agent_datetime(MAX(sched.[next_run_date]), MAX(sched.[next_run_time])) AS [NextRunDate]
FROM msdb.dbo.sysjobs job
INNER JOIN msdb.dbo.sysjobhistory hist ON job.[job_id] = hist.[job_id]
INNER JOIN msdb.dbo.sysjobschedules sched ON job.[job_id] = sched.[job_id]
WHERE job.[name] LIKE 'DatabaseBackup%'
GROUP BY job.[name]
ORDER BY job.[name];