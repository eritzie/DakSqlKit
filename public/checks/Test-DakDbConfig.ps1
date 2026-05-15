function Test-DakDbConfig {
    <#
    .SYNOPSIS
        Tests SQL Server instances for configuration health and security settings.

    .DESCRIPTION
        Checks instance memory/CPU/OS configuration, database-level settings, file and
        autogrowth configuration, security settings, storage layout, database health,
        and SQL Agent alerting. Returns one result object per check per instance
        (type: DakSqlKit.AuditResult).

        Sections:
            1  — Instance Memory/CPU/OS Configuration    (15 checks: DC-1.1–1.15)
            2  — Database Settings                       (9 checks:  DC-2.1–2.9)
            3  — File and Autogrowth Settings            (4 checks:  DC-3.1–3.4)
            4  — Security Configuration                  (29 checks: DC-4.1–4.29)
            5  — Storage Layout                          (4 checks:  DC-5.1–5.4)
            6  — Database Health                         (8 checks:  DC-6.1–6.8)
            7  — SQL Agent / Alerting                    (10 checks: DC-7.1–7.10)
            8  — High Availability / HADR                (7 checks:  DC-8.1–8.7)
            9  — Log Shipping                            (4 checks:  DC-9.1–9.4)
            10 — Operational Governance                  (2 checks:  DC-10.1–10.2)

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        Sections to run: 1–10, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

    .PARAMETER Quiet
        Suppress Write-Host progress output. Use when calling from Invoke-DakAuditSuite.

    .EXAMPLE
        Test-DakDbConfig -SqlInstance 'SQL-DEV-01'

    .EXAMPLE
        Test-DakDbConfig -SqlInstance 'SQL-DEV-01' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Test-DakDbConfig -SqlInstance 'SQL-DEV-01' -Section 3, 4
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "All")]
        [string[]]$Section = "All",

        [Parameter()]
        [switch]$FailedOnly,

        [Parameter()]
        [switch]$Quiet
    )

    begin {
        $ErrorActionPreference = "Stop"

        if (-not (Get-Module -ListAvailable -Name dbatools)) {
            throw "dbatools module is required. Install with: Install-Module dbatools"
        }

        $runAll        = $Section -contains "All"
        $runDate       = Get-Date
        $runBy         = "$env:USERDOMAIN\$env:USERNAME"
        $privDataCache = @{}   # keyed by computer name; Get-DbaPrivilege once per host

        function ShouldRun ([string]$s) { $runAll -or $Section -contains $s }

        $priority = @{
            "DC-1.1" = "High"    # Unlimited memory causes OS paging under load
            "DC-1.2" = "Medium"  # Unthrottled parallelism degrades OLTP concurrency
            "DC-1.3" = "Medium"  # Default cost threshold of 5 too aggressive for modern hardware
            "DC-1.4" = "Low"     # Backup compression reduces storage and I/O overhead
            "DC-1.5" = "Low"     # Ad hoc plan caching prevents plan cache bloat
            "DC-1.6" = "High"    # No IFI means zero-initialization blocks threads during data file growth
            "DC-1.7" = "Medium"  # No LPIM means buffer pool can be paged out under memory pressure
            "DC-1.8" = "Medium"  # Balanced power plan throttles CPU; High Performance is SQL Server best practice
            "DC-1.9" = "Low"     # Default 6 log files may not retain enough history for incident review
            "DC-2.1" = "High"    # Auto-shrink causes fragmentation and I/O storms
            "DC-2.2" = "Medium"  # Auto-close drops connection pool; performance hit on reconnect
            "DC-2.3" = "High"    # CHECKSUM detects storage corruption; TornPage misses silent corruption
            "DC-2.4" = "Medium"  # Old compat level blocks optimizer improvements
            "DC-2.5" = "Medium"  # Missing auto-create stats leads to poor query plans
            "DC-2.6" = "Medium"  # Stale stats leads to poor query plans
            "DC-3.1" = "Medium"  # Single TempDB file causes allocation contention on multi-core
            "DC-3.2" = "Medium"  # Unequal TempDB files defeat proportional fill; contention returns
            "DC-3.3" = "High"    # Percent autogrowth can trigger multi-GB growth events and VLF explosion
            "DC-3.4" = "Medium"  # Data/log on system drive risks OS stability if drive fills
            "DC-4.1" = "High"    # Enabled SA login is a direct brute-force target
            "DC-4.2" = "Medium"  # Renamed SA is harder to target; defense in depth
            "DC-4.3" = "High"    # TRUSTWORTHY enables dangerous cross-DB ownership chaining
            "DC-4.4" = "Medium"  # Guest CONNECT allows any authenticated login to query the database
            "DC-4.5" = "Medium"  # Orphaned users hold permissions but cannot authenticate
            "DC-4.6" = "Low"     # Excess public server permissions broaden attack surface
            "DC-1.10"= "High"    # Unpatched instances are exposed to known CVEs; end-of-support builds have no fixes
            "DC-1.11"= "High"    # SQL Server running as SYSTEM gives the engine full OS control; use a dedicated service account
            "DC-4.7" = "High"    # Mixed Mode auth exposes SQL logins to brute-force; Windows-only is more secure
            "DC-4.8" = "Medium"  # Missing SPNs force NTLM fallback; breaks Kerberos delegation and double-hop
            "DC-4.9" = "High"    # xp_cmdshell enables OS command execution directly from SQL; highest attack surface
            "DC-4.10"= "Medium"  # CLR enables .NET code execution in SQL; unnecessary attack surface if not used
            "DC-4.11"= "Medium"  # Ole Automation allows COM object instantiation from SQL; unnecessary surface area
            "DC-4.12"= "Medium"  # Ad Hoc Distributed Queries enables OPENROWSET/OPENDATASOURCE without restrictions
            "DC-4.13"= "Medium"  # Cross-DB ownership chaining allows implicit privilege escalation across database boundaries
            "DC-4.14"= "Low"     # Database Mail XPs expose external email infrastructure from SQL context; disable if not used
            "DC-4.15"= "Low"     # Remote access is a deprecated protocol; disable to reduce exposure from legacy RPC connections
            "DC-4.16"= "Low"     # Startup procedures execute at engine start with elevated context; unnecessary ones are a risk
            "DC-4.17"= "High"    # SQL logins in sysadmin bypass all authorization controls; Windows groups preferred
            "DC-4.18"= "Medium"  # Databases owned by SA SID grant elevated context if the owner is impersonated
            "DC-4.19"= "High"    # Linked server SQL auth stores credentials in sys.linked_logins; prefer Windows auth
            "DC-4.20"= "High"    # SQL logins without CHECK_POLICY bypass Windows password complexity and expiration requirements
            "DC-4.21"= "Medium"  # No login failure auditing means brute-force attempts go undetected in the SQL Server error log
            "DC-4.22"= "Medium"  # Priority boost can starve the OS and cause instability; not supported and not recommended
            "DC-4.23"= "Medium"  # Lightweight pooling (fiber mode) is deprecated and unsupported in SQL Server 2019+
            "DC-4.24"= "High"    # Expired or missing TLS certificate causes connection failures and leaves data in transit unprotected
            "DC-4.25"= "High"    # Without force encryption clients may connect unencrypted regardless of server certificate configuration
            "DC-5.1" = "High"    # 4KB allocation unit wastes I/O on SQL Server 8KB pages; 64KB is standard
            "DC-5.2" = "High"    # Data/log on same volume risks data loss if volume fills; also I/O contention
            "DC-5.3" = "Medium"  # TempDB on shared volume competes with user DB I/O under load
            "DC-5.4" = "High"    # Low disk space on SQL volumes risks instance crashes and data loss from log-full conditions
            "DC-6.1" = "High"    # VLF count >1000 causes slow recovery, slow log backup, and slow DB attach
            "DC-6.2" = "High"    # CHECKDB not run in >30 days means undetected corruption may be unrecoverable
            "DC-6.3" = "High"    # Full backup older than 7 days violates typical RPO; data loss window too wide
            "DC-6.4" = "High"    # FULL recovery without frequent log backups leaves large RPO gap between full backups
            "DC-6.5" = "High"    # SUSPECT/EMERGENCY databases indicate unrecoverable errors; require immediate DBA attention
            "DC-7.1" = "High"    # Agent stopped means all scheduled jobs and alerts are silently not executing
            "DC-7.2" = "Medium"  # Severity 17-25 alerts missing means critical engine errors go unnoticed
            "DC-7.3" = "Medium"  # Error 825 (I/O soft error) is an early warning of disk failure
            "DC-7.4" = "Medium"  # No enabled operator means alerts fire but no one receives notification
            "DC-7.5" = "Medium"  # Alert with no notification configured fires but takes no action
            "DC-7.6" = "Medium"  # system_health XE session captures deadlocks, memory errors, and connectivity failures; stopping it eliminates key diagnostic data
            "DC-1.12"= "High"    # Memory dump files indicate SQL Server crashes or internal assertions — each one warrants investigation
            "DC-2.7" = "Medium"  # Collation mismatch causes implicit conversions, sort order inconsistencies, and join collation conflict errors
            "DC-6.6" = "Critical"# Suspect pages indicate unresolved I/O errors, bad checksums, or torn pages — potential data loss
            "DC-6.7" = "High"    # Identity columns near their data type maximum will cause INSERT failures when the type overflows
            "DC-7.7" = "High"    # Failed jobs may indicate missed backups, maintenance failures, or ETL errors that compound over time
            "DC-7.8" = "Medium"  # Jobs significantly exceeding normal run time may indicate blocking, resource contention, or runaway processes
            "DC-7.9" = "Low"     # Ola Hallengren's solution is the de facto standard for backup, integrity check, and index/statistics maintenance
            "DC-8.1" = "High"     # Documents standalone state; no AG protection on this instance
            "DC-8.2" = "High"     # Database mirroring is deprecated (SQL 2012) and removed (SQL 2022)
            "DC-8.3" = "Critical" # Disconnected replicas cannot receive log and will diverge from primary
            "DC-8.4" = "High"     # Unsynchronized replicas increase data loss exposure on failover
            "DC-8.5" = "Medium"   # Manual-only failover requires DBA intervention during an outage
            "DC-8.6" = "High"     # High lag on synchronous replicas blocks primary commits; high async lag raises RPO
            "DC-8.7" = "Medium"   # Without a listener, clients must be reconfigured manually after every failover
            "DC-9.1" = "Info"     # Detection only — documents whether log shipping is in use on this instance
            "DC-9.2" = "High"     # Backup outside threshold means secondary is falling behind the primary
            "DC-9.3" = "High"     # Restore outside threshold means the configured RPO is being exceeded
            "DC-9.4" = "High"     # Log shipping errors indicate jobs failing or latency building undetected
            "DC-1.13"= "Low"     # SQL Browser required for named instance port discovery; not running prevents client connections
            "DC-1.14"= "Critical"# Version approaching or past end-of-support receives no security patches
            "DC-1.15"= "Medium"  # Non-rotating service account credentials increase exposure window on compromise
            "DC-2.8" = "Medium"  # Query Store provides query plan history and regression detection without additional tooling
            "DC-2.9" = "Medium"  # Contained database authentication bypasses instance-level login controls and policy enforcement
            "DC-4.26"= "Info"    # Documents TDE status; encryption requirement depends on data classification and compliance mandate
            "DC-4.27"= "High"    # Without SQL Server Audit there is no tamper-evident record of privileged operations or schema changes
            "DC-4.28"= "Medium"  # Undocumented global trace flags alter engine behavior for all connections and are unsupported
            "DC-4.29"= "High"    # Unrestricted inbound access to SQL port exposes the instance to brute-force and CVE exploitation
            "DC-6.8" = "High"    # Untested backups provide false assurance; the first real recovery attempt should not be the first test
            "DC-7.10"= "Medium"  # Database Mail required for SQL Agent operator notifications; without it alert notifications are silently discarded
            "DC-10.1"= "High"    # An untested or undocumented DR runbook provides false assurance about recovery capability
            "DC-10.2"= "Medium"  # Without an application connectivity map, login changes and database moves carry unknown blast radius
        }

        $sql = @{
            "DC-1.1" = "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'max server memory (MB)';"
            "DC-1.2" = "-- Automated via Test-DbaMaxDop. T-SQL: SELECT [value_in_use] FROM [sys].[configurations] WHERE [name] = 'max degree of parallelism';"
            "DC-1.3" = "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'cost threshold for parallelism';"
            "DC-1.4" = "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'backup compression default';"
            "DC-1.5" = "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'optimize for ad hoc workloads';"
            "DC-1.6" = "-- Automated via Get-DbaPrivilege -ComputerName. Grant 'Perform volume maintenance tasks' to the SQL Server service account in secpol.msc."
            "DC-1.7" = "-- Automated via Get-DbaPrivilege -ComputerName. Grant 'Lock pages in memory' to the SQL Server service account in secpol.msc."
            "DC-1.8" = "-- Automated via Test-DbaPowerPlan -ComputerName. CMD: powercfg /query SCHEME_MIN."
            "DC-1.9" = "-- Automated via Get-DbaErrorLogConfig. EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs';"
            "DC-2.1" = "SELECT [name] FROM [sys].[databases] WHERE [is_auto_shrink_on] = 1 AND [database_id] > 4;"
            "DC-2.2" = "SELECT [name] FROM [sys].[databases] WHERE [is_auto_close_on] = 1 AND [database_id] > 4;"
            "DC-2.3" = "SELECT [name], [page_verify_option_desc] FROM [sys].[databases] WHERE [page_verify_option_desc] <> 'CHECKSUM' AND [database_id] > 4;"
            "DC-2.4" = "SELECT [d].[name], [d].[compatibility_level] FROM [sys].[databases] [d] CROSS JOIN (SELECT [compatibility_level] FROM [sys].[databases] WHERE [name] = 'master') [m] WHERE [d].[database_id] > 4 AND [d].[compatibility_level] < [m].[compatibility_level] - 10;"
            "DC-2.5" = "SELECT [name] FROM [sys].[databases] WHERE [is_auto_create_stats_on] = 0 AND [database_id] > 4;"
            "DC-2.6" = "SELECT [name] FROM [sys].[databases] WHERE [is_auto_update_stats_on] = 0 AND [database_id] > 4;"
            "DC-3.1" = "-- Automated via Get-DbaDbFile (tempdb ROWS count) + Get-DbaComputerSystem (CPU count). T-SQL: SELECT COUNT(*) FROM [tempdb].[sys].[database_files] WHERE [type] = 0;"
            "DC-3.2" = "SELECT [name], [size], [growth], [is_percent_growth] FROM [tempdb].[sys].[database_files] WHERE [type] = 0 ORDER BY [name];"
            "DC-3.3" = "SELECT DB_NAME([mf].[database_id]) AS [DatabaseName], [mf].[name], [mf].[growth], [mf].[is_percent_growth] FROM [sys].[master_files] [mf] WHERE [mf].[database_id] > 4 AND [mf].[is_percent_growth] = 1;"
            "DC-3.4" = "-- Automated via Get-DbaDefaultPath. EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'DefaultData';"
            "DC-4.1" = "SELECT [name], [is_disabled] FROM [sys].[server_principals] WHERE [sid] = 0x01;"
            "DC-4.2" = "SELECT [name] FROM [sys].[server_principals] WHERE [sid] = 0x01;"
            "DC-4.3" = "SELECT [name] FROM [sys].[databases] WHERE [is_trustworthy_on] = 1 AND [name] <> 'msdb' AND [database_id] > 4;"
            "DC-4.4" = "-- Run per user database: SELECT [permission_name] FROM [sys].[database_permissions] WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest') AND [permission_name] = 'CONNECT';"
            "DC-4.5" = "-- Automated via Get-DbaDbOrphanUser. T-SQL: SELECT [dp].[name] FROM [sys].[database_principals] [dp] LEFT JOIN [sys].[server_principals] [sp] ON [dp].[sid] = [sp].[sid] WHERE [dp].[type] IN ('S','U','G') AND [sp].[sid] IS NULL AND [dp].[principal_id] > 4;"
            "DC-4.6" = "SELECT [permission_name], [state_desc], [class_desc] FROM [sys].[server_permissions] WHERE [grantee_principal_id] = SUSER_SID(N'public') AND [state_desc] LIKE 'GRANT%' AND NOT ([permission_name] = 'VIEW ANY DATABASE' AND [class_desc] = 'SERVER') AND NOT ([permission_name] = 'CONNECT' AND [class_desc] = 'ENDPOINT' AND [major_id] IN (2,3,4,5));"
            "DC-1.10"= "-- Automated via Test-DbaBuild. Web: https://sqlserverupdates.com to find the latest CU for each major version."
            "DC-1.11"= "-- Automated via Get-DbaService -ComputerName -Type Engine. Check StartName against SYSTEM/LocalSystem."
            "DC-4.7" = "-- Automated via Get-DbaInstanceProperty -InstanceProperty LoginMode. SMO ServerLoginMode: 1 = Integrated (Windows-only), 2 = Mixed. T-SQL: SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS INT) AS [WindowsAuthOnly];"
            "DC-4.8" = "-- Automated via Test-DbaSpn -ComputerName. CMD: setspn -L <service-account> to view all registered SPNs."
            "DC-4.9" = "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'xp_cmdshell';"
            "DC-4.10"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'clr enabled';"
            "DC-4.11"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'Ole Automation Procedures';"
            "DC-4.12"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'Ad Hoc Distributed Queries';"
            "DC-4.13"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'cross db ownership chaining';"
            "DC-4.14"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'Database Mail XPs';"
            "DC-4.15"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'remote access';"
            "DC-4.16"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'scan for startup procs';"
            "DC-4.17"= "SELECT [sp].[name], [sp].[type_desc] FROM [sys].[server_role_members] [srm] JOIN [sys].[server_principals] [sp] ON [srm].[member_principal_id] = [sp].[principal_id] JOIN [sys].[server_principals] [r] ON [srm].[role_principal_id] = [r].[principal_id] WHERE [r].[name] = 'sysadmin' AND [sp].[type] = 'S' AND [sp].[sid] <> 0x01;"
            "DC-4.18"= "SELECT [name] FROM [sys].[databases] WHERE [owner_sid] = 0x01 AND [database_id] > 4;"
            "DC-4.19"= "SELECT [ls].[name] AS [LinkedServer], [ll].[remote_name] FROM [sys].[linked_logins] [ll] JOIN [sys].[servers] [ls] ON [ll].[server_id] = [ls].[server_id] WHERE [ll].[remote_name] IS NOT NULL AND [ll].[uses_self_credential] = 0;"
            "DC-4.20"= "SELECT [name], [is_policy_checked], [is_expiration_checked] FROM [sys].[sql_logins] WHERE [is_policy_checked] = 0 AND [sid] <> 0x01 AND [is_disabled] = 0;"
            "DC-4.21"= "-- Registry via xp_instance_regread: HKLM\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\AuditLevel. 0=None, 1=Success, 2=Failure, 3=All"
            "DC-4.22"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'priority boost';"
            "DC-4.23"= "SELECT [name], [value_in_use] AS [RunningValue] FROM [sys].[configurations] WHERE [name] = 'lightweight pooling';"
            "DC-4.24"= "-- Automated via Get-DbaNetworkCertificate -ComputerName. Certificate stored in Windows cert store (LocalMachine\My); thumbprint in SQL Server registry."
            "DC-4.25"= "-- Automated via Get-DbaForceNetworkEncryption. Registry: HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance>\MSSQLServer\SuperSocketNetLib\ForceEncryption."
            "DC-5.4" ="-- Automated via Get-DbaDiskSpace -ComputerName. SQL volumes identified from database file paths in sys.master_files."
            "DC-5.1" = "-- Automated via Test-DbaDiskAllocation -ComputerName. CMD: fsutil fsinfo ntfsinfo <drive>: | findstr 'Bytes Per Cluster'."
            "DC-5.2" = "SELECT [mf].[name], [mf].[physical_name], [mf].[type_desc] FROM [sys].[master_files] [mf] WHERE [mf].[database_id] > 4 ORDER BY [mf].[database_id], [mf].[type_desc];"
            "DC-5.3" = "SELECT [mf].[name], [mf].[physical_name], [mf].[type_desc] FROM [sys].[master_files] [mf] WHERE [mf].[database_id] = DB_ID(N'tempdb') OR [mf].[database_id] > 4 ORDER BY [mf].[database_id], [mf].[type_desc];"
            "DC-6.1" = "-- Automated via Measure-DbaDbVirtualLogFile. T-SQL: DBCC LOGINFO;"
            "DC-6.2" = "-- Automated via Get-DbaLastGoodCheckDb. T-SQL: DBCC DBINFO() WITH TABLERESULTS; (find dbi_dbccLastKnownGood)"
            "DC-6.3" = "SELECT [database_name], MAX([backup_finish_date]) AS [LastFullBackup] FROM [msdb].[dbo].[backupset] WHERE [type] = 'D' GROUP BY [database_name];"
            "DC-6.4" = "-- Automated via Get-DbaLastBackup. T-SQL: SELECT [database_name], MAX([backup_finish_date]) FROM [msdb].[dbo].[backupset] WHERE [type] = 'L' GROUP BY [database_name];"
            "DC-6.5" = "SELECT [name], [state_desc] FROM [sys].[databases] WHERE [state_desc] NOT IN ('ONLINE', 'OFFLINE') AND [is_in_standby] = 0;"
            "DC-7.1" = "-- Automated via Get-DbaService -ComputerName -Type Agent. CMD: sc query SQLSERVERAGENT."
            "DC-7.2" = "SELECT [name], [severity], [enabled] FROM [msdb].[dbo].[sysalerts] WHERE [severity] BETWEEN 17 AND 25 AND [enabled] = 1;"
            "DC-7.3" = "SELECT [name], [message_id], [enabled] FROM [msdb].[dbo].[sysalerts] WHERE [message_id] = 825 AND [enabled] = 1;"
            "DC-7.4" = "SELECT [name], [enabled] FROM [msdb].[dbo].[sysoperators] WHERE [enabled] = 1;"
            "DC-7.5" = "SELECT [a].[name] FROM [msdb].[dbo].[sysalerts] [a] WHERE [a].[enabled] = 1 AND NOT EXISTS (SELECT 1 FROM [msdb].[dbo].[sysnotifications] [n] WHERE [n].[alert_id] = [a].[id]) ORDER BY [a].[name];"
            "DC-7.6" = "-- Automated via Get-DbaXESession. T-SQL: SELECT [name], [state_desc], [startup_state_desc] FROM [sys].[dm_xe_sessions] WHERE [name] = 'system_health';"
            "DC-1.12"= "-- Automated via Get-DbaDump (sys.dm_server_memory_dumps). Files are in the SQL Server LOG directory with .mdmp extension."
            "DC-2.7" = "-- Automated via Test-DbaDbCollation. T-SQL: SELECT [name], [collation_name] FROM [sys].[databases] WHERE [collation_name] <> CAST(SERVERPROPERTY('Collation') AS nvarchar(128)) AND [database_id] > 4;"
            "DC-6.6" = "SELECT DB_NAME([database_id]) AS [DatabaseName], [file_id], [page_id], [event_type], [error_count], [last_update_date] FROM [msdb].[dbo].[suspect_pages] WHERE [event_type] IN (1, 2, 3);"
            "DC-6.7" = "-- Automated via Test-DbaIdentityUsage. T-SQL per table: SELECT IDENT_CURRENT('<table>'), IDENT_SEED('<table>'), IDENT_INCR('<table>')."
            "DC-7.7" = "SELECT [j].[name], [jh].[run_date], [jh].[run_time], [jh].[message] FROM [msdb].[dbo].[sysjobhistory] [jh] JOIN [msdb].[dbo].[sysjobs] [j] ON [j].[job_id] = [jh].[job_id] WHERE [jh].[run_status] = 0 AND [jh].[step_id] = 0 ORDER BY [jh].[run_date] DESC, [jh].[run_time] DESC;"
            "DC-7.8" = "SELECT [j].[name], [a].[start_execution_date], DATEDIFF(MINUTE, [a].[start_execution_date], GETDATE()) AS [RunMinutes] FROM [msdb].[dbo].[sysjobactivity] [a] JOIN [msdb].[dbo].[sysjobs] [j] ON [j].[job_id] = [a].[job_id] WHERE [a].[start_execution_date] IS NOT NULL AND [a].[stop_execution_date] IS NULL AND [a].[run_requested_date] IS NOT NULL ORDER BY [RunMinutes] DESC;"
            "DC-7.9" = "-- Automated via Get-DbaDbStoredProcedure. Check for DatabaseBackup, DatabaseIntegrityCheck, IndexOptimize, CommandExecute in master. Install: Install-DbaMaintenanceSolution."
            "DC-8.1" = "SELECT SERVERPROPERTY('IsHadrEnabled') AS [IsHadrEnabled];"
            "DC-8.2" = "SELECT [name], [mirroring_state_desc], [mirroring_partner_name] FROM [sys].[databases] WHERE [mirroring_state_desc] IS NOT NULL AND [database_id] > 4;"
            "DC-8.3" = "SELECT [ar].[replica_server_name], [rs].[connected_state_desc] FROM [sys].[dm_hadr_availability_replica_states] [rs] JOIN [sys].[availability_replicas] [ar] ON [ar].[replica_id] = [rs].[replica_id];"
            "DC-8.4" = "SELECT [ar].[replica_server_name], [rs].[synchronization_health_desc] FROM [sys].[dm_hadr_availability_replica_states] [rs] JOIN [sys].[availability_replicas] [ar] ON [ar].[replica_id] = [rs].[replica_id];"
            "DC-8.5" = "SELECT [ar].[replica_server_name], [ar].[failover_mode_desc], [ar].[availability_mode_desc] FROM [sys].[availability_replicas] [ar] JOIN [sys].[availability_groups] [ag] ON [ag].[group_id] = [ar].[group_id];"
            "DC-8.6" = "SELECT [ars].[replica_server_name], [drs].[database_name], [drs].[secondary_lag_seconds] FROM [sys].[dm_hadr_database_replica_states] [drs] JOIN [sys].[availability_replicas] [ars] ON [ars].[replica_id] = [drs].[replica_id] WHERE [drs].[is_local] = 0 ORDER BY [drs].[secondary_lag_seconds] DESC;"
            "DC-8.7" = "SELECT [ag].[name] AS [AGName], [l].[dns_name], [l].[port] FROM [sys].[availability_group_listeners] [l] JOIN [sys].[availability_groups] [ag] ON [ag].[group_id] = [l].[group_id];"
            "DC-9.1" = "SELECT [primary_database] AS [Database], 'Primary' AS [Role] FROM [msdb].[dbo].[log_shipping_primary_databases] UNION ALL SELECT [secondary_database], 'Secondary' FROM [msdb].[dbo].[log_shipping_secondary_databases];"
            "DC-9.2" = "-- Automated via Test-DbaDbLogShipStatus. T-SQL: SELECT [primary_database], [last_backup_date], [backup_threshold] FROM [msdb].[dbo].[log_shipping_monitor_primary];"
            "DC-9.3" = "-- Automated via Test-DbaDbLogShipStatus. T-SQL: SELECT [secondary_database], [last_restored_date], [restore_threshold] FROM [msdb].[dbo].[log_shipping_monitor_secondary];"
            "DC-9.4" = "-- Automated via Get-DbaDbLogShipError. T-SQL: SELECT [database_name], [agent_type], [action], [message] FROM [msdb].[dbo].[log_shipping_monitor_error_detail] ORDER BY [log_time] DESC;"
            "DC-1.13"= "-- Automated via Get-DbaService -ComputerName -Type Browser. CMD: sc query SQLBrowser"
            "DC-1.14"= "-- Automated via Test-DbaBuild (SupportedUntil property). Reference: https://learn.microsoft.com/lifecycle/products/?products=sql-server"
            "DC-1.15"= "-- Manual review. Get-DbaService -ComputerName '<host>' -Type Engine,Agent | Select-Object DisplayName, StartName. MSA accounts end with '$'."
            "DC-2.8" = "-- Automated via Get-DbaDbQueryStoreOption. T-SQL per DB: SELECT [actual_state_desc], [readonly_reason] FROM [sys].[database_query_store_options];"
            "DC-2.9" = "SELECT [name], [containment_desc] FROM [sys].[databases] WHERE [database_id] > 4 AND [containment_desc] <> N'NONE'; SELECT [name], [value_in_use] FROM [sys].[configurations] WHERE [name] = 'contained database authentication';"
            "DC-4.26"= "SELECT [d].[name], CASE WHEN [de].[database_id] IS NOT NULL THEN 'Enabled' ELSE 'Disabled' END AS [TDE_Status], [de].[encryption_state_desc] FROM [sys].[databases] [d] LEFT JOIN [sys].[dm_database_encryption_keys] [de] ON [de].[database_id] = [d].[database_id] WHERE [d].[database_id] > 4;"
            "DC-4.27"= "-- Automated via Get-DbaInstanceAudit. T-SQL: SELECT [name], [type_desc], [on_failure_desc], [is_state_enabled] FROM [sys].[server_audits];"
            "DC-4.28"= "-- Automated via Get-DbaTraceFlag. T-SQL: DBCC TRACESTATUS(-1) WITH NO_INFOMSGS; (returns active global trace flags)"
            "DC-4.29"= "-- Manual review. Check Windows Firewall Advanced Security or network ACLs. Default SQL port: 1433. Named instance port: SELECT [local_tcp_port] FROM [sys].[dm_exec_connections] WHERE [session_id] = @@SPID;"
            "DC-6.8" = "-- Manual review. Test-DbaLastBackup validates backup files. Get-DbaDbRestoreHistory shows recent restore history but does not confirm a full validation test."
            "DC-7.10"= "-- Automated via Get-DbaDbMailProfile / Get-DbaDbMailAccount. T-SQL: SELECT [profile_id], [name] FROM [msdb].[dbo].[sysmail_profile]; SELECT [account_id], [name] FROM [msdb].[dbo].[sysmail_account];"
            "DC-10.1"= "-- Manual review. No automated check possible. Confirm runbook location, last test date, and coverage of failover/restore procedures."
            "DC-10.2"= "-- Manual review. Context: SELECT DISTINCT [program_name], [login_name], DB_NAME([database_id]) AS [Database] FROM [sys].[dm_exec_sessions] WHERE [is_user_process] = 1 AND [program_name] <> '' ORDER BY [program_name];"
        }
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) { Write-Host "DbConfig — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] DbConfig checks — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "DbConfig"
                RunDate      = $runDate
                RunBy        = $runBy
            }

            $emit = {
                param ([PSCustomObject]$r)
                $color = switch ($r.Status) {
                    "Pass"    { "Green"    }
                    "Fail"    { "Red"      }
                    "Warning" { "Yellow"   }
                    "Skip"    { "DarkGray" }
                    "Manual"  { "Cyan"     }
                    default   { "Gray"     }
                }
                if (-not $Quiet) { Write-Host ("  [{0,-6}] {1,-52} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Manual", "Error") { $r }
            }

            # ── Pre-fetch: sp_configure values (§1, §4) ─────────────────────
            $spCfg = @{}
            try {
                Get-DbaSpConfigure @connSplat | ForEach-Object { $spCfg[$_.DisplayName] = $_ }
            } catch { Write-Warning "[$instance] Pre-fetch Get-DbaSpConfigure failed: $($_.Exception.Message)" }

            # ── Pre-fetch: database objects (§2, §3, §4, §5, §6) ─────────────
            $allDbObjects    = @()
            $userDbs         = @()
            $userDbNames     = @()
            $instCompatLevel = 0
            try {
                $allDbObjects    = @(Get-DbaDatabase @connSplat)
                $userDbs         = @($allDbObjects | Where-Object { $_.ID -gt 4 -and $_.IsAccessible })
                $userDbNames     = @($userDbs | Select-Object -ExpandProperty Name)
                $masterDb        = $allDbObjects | Where-Object { $_.Name -eq 'master' } | Select-Object -First 1
                $instCompatLevel = if ($masterDb) { [int]$masterDb.CompatibilityLevel } else { 0 }
            } catch { Write-Warning "[$instance] Pre-fetch Get-DbaDatabase failed: $($_.Exception.Message)" }

            # ── Pre-fetch: database files (§3, §5) ───────────────────────────
            $dbFiles        = @()
            $dbFilesFetched = $false
            try {
                $dbFiles        = @(Get-DbaDbFile @connSplat)
                $dbFilesFetched = $true
            } catch { Write-Warning "[$instance] Pre-fetch Get-DbaDbFile failed: $($_.Exception.Message)" }

            # ── §1 Instance Memory/CPU/OS Configuration ─────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Instance Config"

                # DC-1.1 Max Server Memory
                try {
                    $mem         = $spCfg["max server memory (MB)"]
                    $isUnlimited = $mem.RunningValue -eq 2147483647
                    $splatCheck  = @{
                        CheckId        = "DC-1.1"
                        CheckName      = "Max Server Memory Configured"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.1"]
                        Status         = if (-not $isUnlimited) { "Pass" } else { "Fail" }
                        CurrentValue   = "$($mem.RunningValue) MB"
                        ExpectedValue  = "< 2147483647 (not default unlimited)"
                        Remediation    = "Leave 10-15% for OS: EXEC sp_configure 'max server memory (MB)', <target>; RECONFIGURE;"
                        Reference      = "SQL Server Memory Best Practices — unlimited setting allows buffer pool to crowd out OS and SSAS"
                        SqlQuery       = $sql["DC-1.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.1: $($_.Exception.Message)" }

                # DC-1.2 MAXDOP
                try {
                    $maxdop     = Test-DbaMaxDop @connSplat
                    $splatCheck = @{
                        CheckId        = "DC-1.2"
                        CheckName      = "MAXDOP Configured"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.2"]
                        Status         = if ($maxdop.Compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = $maxdop.CurrentMaxDop.ToString()
                        ExpectedValue  = $maxdop.RecommendedMaxDop.ToString()
                        Remediation    = "EXEC sp_configure 'max degree of parallelism', $($maxdop.RecommendedMaxDop); RECONFIGURE;"
                        Reference      = "SQL Server MAXDOP Best Practices — cap at logical CPU count or 8 per NUMA node"
                        SqlQuery       = $sql["DC-1.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.2: $($_.Exception.Message)" }

                # DC-1.3 Cost Threshold for Parallelism
                try {
                    $ctp        = $spCfg["cost threshold for parallelism"]
                    $splatCheck = @{
                        CheckId        = "DC-1.3"
                        CheckName      = "Cost Threshold for Parallelism"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.3"]
                        Status         = if ($ctp.RunningValue -ge 25) { "Pass" } else { "Fail" }
                        CurrentValue   = $ctp.RunningValue.ToString()
                        ExpectedValue  = ">= 25"
                        Remediation    = "EXEC sp_configure 'cost threshold for parallelism', 50; RECONFIGURE;"
                        Reference      = "SQL Server Parallelism Best Practices — default of 5 triggers parallel plans on trivial queries"
                        SqlQuery       = $sql["DC-1.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.3: $($_.Exception.Message)" }

                # DC-1.4 Backup Compression Default
                try {
                    $bc         = $spCfg["backup compression default"]
                    $splatCheck = @{
                        CheckId        = "DC-1.4"
                        CheckName      = "Backup Compression Enabled"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.4"]
                        Status         = if ($bc.RunningValue -eq 1) { "Pass" } else { "Fail" }
                        CurrentValue   = $bc.RunningValue.ToString()
                        ExpectedValue  = "1"
                        Remediation    = "EXEC sp_configure 'backup compression default', 1; RECONFIGURE;"
                        Reference      = "SQL Server Backup Best Practices — compression reduces backup size and I/O at negligible CPU cost"
                        SqlQuery       = $sql["DC-1.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.4: $($_.Exception.Message)" }

                # DC-1.5 Optimize for Ad Hoc Workloads
                try {
                    $adhoc      = $spCfg["optimize for ad hoc workloads"]
                    $splatCheck = @{
                        CheckId        = "DC-1.5"
                        CheckName      = "Optimize for Ad Hoc Workloads"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.5"]
                        Status         = if ($adhoc.RunningValue -eq 1) { "Pass" } else { "Fail" }
                        CurrentValue   = $adhoc.RunningValue.ToString()
                        ExpectedValue  = "1"
                        Remediation    = "EXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE;"
                        Reference      = "SQL Server Plan Cache Best Practices — prevents single-use plan cache bloat on ad hoc workloads"
                        SqlQuery       = $sql["DC-1.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.5: $($_.Exception.Message)" }

                # OS privilege data for DC-1.6 and DC-1.7 — cached per host so named
                # instances sharing the same computer don't open a second WinRM session
                $privData    = $null
                $privFetched = $false
                if ($privDataCache.ContainsKey($computerName)) {
                    $privData    = $privDataCache[$computerName]
                    $privFetched = $true
                } else {
                    try {
                        $privData    = Get-DbaPrivilege -ComputerName $computerName -EnableException
                        $privFetched = $true
                        $privDataCache[$computerName] = $privData
                    } catch { Write-Warning "[$instance] Get-DbaPrivilege failed — DC-1.6/DC-1.7 skipped: $($_.Exception.Message)" }
                }

                # DC-1.6 Instant File Initialization
                try {
                    if (-not $privFetched) { throw "Get-DbaPrivilege did not succeed" }
                    $splatCheck = @{
                        CheckId        = "DC-1.6"
                        CheckName      = "Instant File Initialization Enabled"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.6"]
                        Status         = if ($privData.InstantFileInitialization) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($privData.InstantFileInitialization) { "Enabled" } else { "Disabled" }
                        ExpectedValue  = "Enabled"
                        Remediation    = "Grant 'Perform volume maintenance tasks' to the SQL Server service account in secpol.msc, then restart SQL Server."
                        Reference      = "SQL Server IFI Best Practices — without IFI, SQL Server zero-initializes data file growth, blocking all activity during the event"
                        SqlQuery       = $sql["DC-1.6"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.6: $($_.Exception.Message)" }

                # DC-1.7 Lock Pages in Memory
                try {
                    if (-not $privFetched) { throw "Get-DbaPrivilege did not succeed" }
                    $splatCheck = @{
                        CheckId        = "DC-1.7"
                        CheckName      = "Lock Pages in Memory Enabled"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.7"]
                        Status         = if ($privData.LockPagesInMemory) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($privData.LockPagesInMemory) { "Enabled" } else { "Disabled" }
                        ExpectedValue  = "Enabled"
                        Remediation    = "Grant 'Lock pages in memory' to the SQL Server service account in secpol.msc, then restart SQL Server."
                        Reference      = "SQL Server LPIM Best Practices — without LPIM, Windows can page out the buffer pool under memory pressure"
                        SqlQuery       = $sql["DC-1.7"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.7: $($_.Exception.Message)" }

                # DC-1.8 Power Plan
                try {
                    $powerPlan  = Test-DbaPowerPlan -ComputerName $computerName -EnableException
                    $splatCheck = @{
                        CheckId        = "DC-1.8"
                        CheckName      = "Power Plan Set to High Performance"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.8"]
                        Status         = if ($powerPlan.IsBestPractice) { "Pass" } else { "Warning" }
                        CurrentValue   = $powerPlan.ActivePowerPlan
                        ExpectedValue  = $powerPlan.RecommendedPowerPlan
                        Remediation    = "powercfg /setactive SCHEME_MIN   (or set 'High Performance' in Control Panel > Power Options)"
                        Reference      = "SQL Server Power Plan Best Practices — Balanced plan CPU throttling causes query latency spikes"
                        SqlQuery       = $sql["DC-1.8"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.8: $($_.Exception.Message)" }

                # DC-1.9 Error Log File Count
                try {
                    $errLogCfg  = Get-DbaErrorLogConfig @connSplat
                    $logCount   = [int]$errLogCfg.LogCount
                    $splatCheck = @{
                        CheckId        = "DC-1.9"
                        CheckName      = "Error Log File Count >= 12"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.9"]
                        Status         = if ($logCount -ge 12) { "Pass" } else { "Warning" }
                        CurrentValue   = $logCount.ToString()
                        ExpectedValue  = ">= 12"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 12;"
                        Reference      = "SQL Server Error Log Best Practices — default of 6 may not retain enough history to diagnose incidents"
                        SqlQuery       = $sql["DC-1.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.9: $($_.Exception.Message)" }

                # DC-1.10 SQL Server Build / Patch Level
                try {
                    $build      = Test-DbaBuild @connSplat -Latest -EnableException
                    $outOfSupport = $null -ne $build.SupportedUntil -and $build.SupportedUntil -lt (Get-Date)
                    $cuLabel    = if ($build.CULevel) { "$($build.SPLevel) $($build.CULevel)" } else { $build.SPLevel }
                    $status110  = if ($outOfSupport) { "Fail" } elseif (-not $build.Compliant) { "Warning" } else { "Pass" }
                    $untilStr   = if ($build.SupportedUntil) { $build.SupportedUntil.ToString("yyyy-MM-dd") } else { "unknown" }
                    $splatCheck = @{
                        CheckId        = "DC-1.10"
                        CheckName      = "SQL Server Build Current"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.10"]
                        Status         = $status110
                        CurrentValue   = "$($build.NameLevel) — $cuLabel (build $($build.BuildLevel))"
                        ExpectedValue  = "Latest CU for this major version; supported until $untilStr"
                        Remediation    = "Apply the latest Cumulative Update from https://sqlserverupdates.com"
                        Reference      = "SQL Server Build Best Practices — CUs contain critical fixes and security patches; end-of-support builds receive no further fixes"
                        SqlQuery       = $sql["DC-1.10"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.10: $($_.Exception.Message)" }

                # DC-1.11 SQL Server Service Account Not SYSTEM/LocalSystem
                try {
                    $sqlSvcs    = @(Get-DbaService -ComputerName $computerName -Type Engine -EnableException)
                    $badSvcs    = @($sqlSvcs | Where-Object { $_.StartName -in @('NT AUTHORITY\SYSTEM', 'LocalSystem', '.\SYSTEM', 'SYSTEM') })
                    $warnSvcs   = @($sqlSvcs | Where-Object { $_.StartName -in @('NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE') })
                    $status111  = if ($badSvcs) { "Fail" } elseif ($warnSvcs) { "Warning" } else { "Pass" }
                    $svcDetail  = $sqlSvcs | ForEach-Object { "$($_.DisplayName): $($_.StartName)" }
                    $splatCheck = @{
                        CheckId        = "DC-1.11"
                        CheckName      = "SQL Server Service Account Not SYSTEM"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.11"]
                        Status         = $status111
                        CurrentValue   = if ($svcDetail) { $svcDetail -join "; " } else { "No SQL engine service found" }
                        ExpectedValue  = "Dedicated low-privilege service account (managed service account or domain account)"
                        Remediation    = "Use SQL Server Configuration Manager to change the service account to a dedicated MSA or domain account with minimum required privileges."
                        Reference      = "SQL Server Security Best Practices — SYSTEM/LocalSystem grants SQL Server full OS access; use a dedicated account to limit blast radius on compromise"
                        SqlQuery       = $sql["DC-1.11"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.11: $($_.Exception.Message)" }

                # DC-1.12 No Recent Memory Dumps
                try {
                    $dumps      = @(Get-DbaDump @connSplat)
                    $recent     = @($dumps | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) })
                    $splatCheck = @{
                        CheckId        = "DC-1.12"
                        CheckName      = "No Recent Memory Dumps"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.12"]
                        Status         = if ($recent) { "Fail" } else { "Pass" }
                        CurrentValue   = if ($recent) {
                            ($recent | ForEach-Object { "$($_.FileName) ($($_.CreationTime.ToString('yyyy-MM-dd')))" }) -join "; "
                        } else { "No memory dumps in last 30 days" }
                        ExpectedValue  = "No memory dump files written in last 30 days"
                        Remediation    = "Review SQL Server error log and Windows Application event log around each dump time. Common causes: memory pressure, access violations, scheduler health issues."
                        Reference      = "SQL Server Diagnostics Best Practices — each memory dump indicates a crash or internal assertion; investigate before the next occurrence"
                        SqlQuery       = $sql["DC-1.12"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.12: $($_.Exception.Message)" }

                # DC-1.13 SQL Browser Service State
                try {
                    $isNamedInstance = $instance -match "\\"
                    $browserSvcs     = @(Get-DbaService -ComputerName $computerName -Type Browser -EnableException -WarningAction SilentlyContinue)
                    $browserSvc      = $browserSvcs | Select-Object -First 1
                    $browserRunning  = $browserSvc -and $browserSvc.State -eq 'Running'
                    $status113       = if (-not $isNamedInstance) {
                        "Pass"
                    } elseif ($browserRunning) {
                        "Pass"
                    } else {
                        "Warning"
                    }
                    $current113 = if ($browserSvc) {
                        "State: $($browserSvc.State) | StartMode: $($browserSvc.StartMode)"
                    } else { "SQL Browser service not found on $computerName" }
                    $splatCheck = @{
                        CheckId        = "DC-1.13"
                        CheckName      = "SQL Browser Service State"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.13"]
                        Status         = $status113
                        CurrentValue   = $current113
                        ExpectedValue  = if ($isNamedInstance) { "Running (required for named instance port resolution)" } else { "N/A — default instance uses fixed port 1433" }
                        Remediation    = "SQL Server Configuration Manager > SQL Server Services > SQL Server Browser > Start. Set startup type to Automatic."
                        Reference      = "SQL Server Network Configuration — SQL Browser translates instance names to dynamic TCP ports; named instances require it unless clients connect using an explicit port"
                        SqlQuery       = $sql["DC-1.13"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.13: $($_.Exception.Message)" }

                # DC-1.14 SQL Server Version Within Support Lifecycle
                try {
                    $buildEol   = Test-DbaBuild @connSplat -Latest -EnableException
                    $eolDate    = $buildEol.SupportedUntil
                    $daysLeft   = if ($eolDate) { [int]($eolDate - (Get-Date)).TotalDays } else { $null }
                    $status114  = if ($null -eq $daysLeft) {
                        "Manual"
                    } elseif ($daysLeft -lt 0) {
                        "Fail"
                    } elseif ($daysLeft -le 180) {
                        "Warning"
                    } else {
                        "Pass"
                    }
                    $current114 = if ($eolDate) {
                        "$($buildEol.NameLevel) — support ends $($eolDate.ToString('yyyy-MM-dd')) ($daysLeft days)"
                    } else {
                        "$($buildEol.NameLevel) — support end date not available"
                    }
                    $splatCheck = @{
                        CheckId        = "DC-1.14"
                        CheckName      = "SQL Server Version Within Support Lifecycle"
                        Category       = "Instance Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-1.14"]
                        Status         = $status114
                        CurrentValue   = $current114
                        ExpectedValue  = "Major version in mainstream or extended support with > 180 days remaining"
                        Remediation    = "Plan upgrade to a supported major version before end-of-support date. Microsoft Extended Security Updates (ESU) may be available for a limited period after EOL."
                        Reference      = "Microsoft SQL Server Lifecycle — end-of-support versions receive no security patches; any new CVE is permanently unmitigated without upgrading"
                        SqlQuery       = $sql["DC-1.14"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.14: $($_.Exception.Message)" }

                # DC-1.15 Service Account Uses MSA or Rotation Is Documented
                try {
                    $allSvcs     = @(Get-DbaService -ComputerName $computerName -Type Engine, Agent -EnableException -WarningAction SilentlyContinue)
                    $svcDetail   = $allSvcs | ForEach-Object { "$($_.DisplayName): $($_.StartName)" }
                    $splatCheck  = @{
                        CheckId        = "DC-1.15"
                        CheckName      = "Service Account Uses MSA or Rotation Documented"
                        Category       = "Instance Config"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-1.15"]
                        Status         = "Manual"
                        CurrentValue   = if ($svcDetail) { $svcDetail -join "; " } else { "Unable to retrieve service account info" }
                        ExpectedValue  = "Managed Service Account (MSA/gMSA) with automatic password rotation, or a documented manual rotation schedule"
                        Remediation    = "Convert to a Group Managed Service Account (gMSA) for automatic password rotation. If using a domain account, document a rotation procedure and schedule in your runbook."
                        Reference      = "SQL Server Security Best Practices — static service account passwords increase the exposure window after a credential compromise; gMSA eliminates the manual rotation requirement"
                        SqlQuery       = $sql["DC-1.15"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-1.15: $($_.Exception.Message)" }
            }

            # ── §2 Database Settings ────────────────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Database Settings"

                # DC-2.1 Auto-Shrink
                try {
                    $shrinkDbs  = @($userDbs | Where-Object { $_.AutoShrink } | Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "DC-2.1"
                        CheckName      = "Auto-Shrink Disabled"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.1"]
                        Status         = if (-not $shrinkDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($shrinkDbs) { $shrinkDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (AUTO_SHRINK = OFF on all user databases)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_SHRINK OFF;"
                        Reference      = "SQL Server Database Best Practices — auto-shrink causes index fragmentation and unpredictable I/O"
                        SqlQuery       = $sql["DC-2.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.1: $($_.Exception.Message)" }

                # DC-2.2 Auto-Close
                try {
                    $closeDbs   = @($userDbs | Where-Object { $_.AutoClose } | Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "DC-2.2"
                        CheckName      = "Auto-Close Disabled"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.2"]
                        Status         = if (-not $closeDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($closeDbs) { $closeDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (AUTO_CLOSE = OFF on all user databases)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_CLOSE OFF;"
                        Reference      = "SQL Server Database Best Practices — auto-close drops connection pool and worker threads on idle"
                        SqlQuery       = $sql["DC-2.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.2: $($_.Exception.Message)" }

                # DC-2.3 Page Verify CHECKSUM
                try {
                    $badPv      = @($userDbs |
                        Where-Object { $_.PageVerify.ToString() -ne 'Checksum' } |
                        ForEach-Object { "$($_.Name) ($($_.PageVerify))" })
                    $splatCheck = @{
                        CheckId        = "DC-2.3"
                        CheckName      = "Page Verify Set to CHECKSUM"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.3"]
                        Status         = if (-not $badPv) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($badPv) { $badPv -join "; " } else { "All CHECKSUM" }
                        ExpectedValue  = "CHECKSUM on all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "SQL Server Database Best Practices — CHECKSUM detects silent storage corruption that TORN_PAGE misses"
                        SqlQuery       = $sql["DC-2.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.3: $($_.Exception.Message)" }

                # DC-2.4 Compatibility Level
                try {
                    $badCompat  = @($userDbs |
                        Where-Object { [int]$_.CompatibilityLevel -lt ($instCompatLevel - 10) } |
                        ForEach-Object { "$($_.Name) (level $([int]$_.CompatibilityLevel), instance $instCompatLevel)" })
                    $splatCheck = @{
                        CheckId        = "DC-2.4"
                        CheckName      = "Compatibility Level Current"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.4"]
                        Status         = if (-not $badCompat) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($badCompat) { $badCompat -join "; " } else { "All within one version of instance" }
                        ExpectedValue  = "Within 10 compatibility levels of instance level ($instCompatLevel)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET COMPATIBILITY_LEVEL = <level>; -- Test workloads thoroughly before changing."
                        Reference      = "SQL Server Compatibility Level — old levels prevent cardinality estimator and optimizer improvements"
                        SqlQuery       = $sql["DC-2.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.4: $($_.Exception.Message)" }

                # DC-2.5 Auto-Create Statistics
                try {
                    $noAcsDbs   = @($userDbs | Where-Object { -not $_.AutoCreateStatisticsEnabled } | Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "DC-2.5"
                        CheckName      = "Auto-Create Statistics Enabled"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.5"]
                        Status         = if (-not $noAcsDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($noAcsDbs) { $noAcsDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (AUTO_CREATE_STATISTICS = ON on all user databases)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_CREATE_STATISTICS ON;"
                        Reference      = "SQL Server Statistics Best Practices — optimizer requires statistics to build efficient plans"
                        SqlQuery       = $sql["DC-2.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.5: $($_.Exception.Message)" }

                # DC-2.6 Auto-Update Statistics
                try {
                    $noAusDbs   = @($userDbs | Where-Object { -not $_.AutoUpdateStatisticsEnabled } | Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "DC-2.6"
                        CheckName      = "Auto-Update Statistics Enabled"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.6"]
                        Status         = if (-not $noAusDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($noAusDbs) { $noAusDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (AUTO_UPDATE_STATISTICS = ON on all user databases)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_UPDATE_STATISTICS ON;"
                        Reference      = "SQL Server Statistics Best Practices — stale statistics lead to suboptimal query plans"
                        SqlQuery       = $sql["DC-2.6"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.6: $($_.Exception.Message)" }

                # DC-2.7 Database Collation Matches Instance Collation
                try {
                    $collAll      = @(Test-DbaDbCollation @connSplat | Where-Object { $_.Database -in $userDbNames })
                    $collCheck    = @($collAll | Where-Object { -not $_.Match })
                    $instColl     = if ($collAll) { $collAll[0].InstanceCollation } else { "unknown" }
                    $splatCheck   = @{
                        CheckId        = "DC-2.7"
                        CheckName      = "Database Collation Matches Instance"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.7"]
                        Status         = if (-not $collCheck) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($collCheck) {
                            ($collCheck | ForEach-Object { "$($_.Database): $($_.DatabaseCollation)" }) -join "; "
                        } else { "All user databases match instance collation ($instColl)" }
                        ExpectedValue  = "All user databases use instance collation ($instColl)"
                        Remediation    = "Collation changes require rebuilding the database or adding COLLATE clauses to queries. Confirm whether the mismatch is intentional before changing."
                        Reference      = "SQL Server Collation Best Practices — mismatched collations cause implicit conversions and 'Cannot resolve the collation conflict' errors on cross-database joins"
                        SqlQuery       = $sql["DC-2.7"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.7: $($_.Exception.Message)" }

                # DC-2.8 Query Store Enabled
                try {
                    $eligibleDbs = @($userDbs | Where-Object { [int]$_.CompatibilityLevel -ge 130 })
                    if ($eligibleDbs.Count -eq 0) {
                        $splatCheck = @{
                            CheckId        = "DC-2.8"
                            CheckName      = "Query Store Enabled"
                            Category       = "Database Settings"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-2.8"]
                            Status         = "Skip"
                            CurrentValue   = "No user databases at compatibility level >= 130 (SQL 2016+)"
                            ExpectedValue  = "Query Store enabled on all user databases at compatibility level >= 130"
                            Remediation    = "N/A"
                            Reference      = "SQL Server Query Store — requires compatibility level 130+; provides query plan history, regressed query detection, and forced plan support"
                            SqlQuery       = $sql["DC-2.8"]
                        }
                    } else {
                        $splatQsOpt  = @{ SqlInstance = $instance }
                        if ($SqlCredential) { $splatQsOpt.SqlCredential = $SqlCredential }
                        $qsOptions   = @(Get-DbaDbQueryStoreOption @splatQsOpt |
                            Where-Object { $_.Database -in ($eligibleDbs | Select-Object -ExpandProperty Name) })
                        $qsOff       = @($qsOptions | Where-Object { $_.ActualState -in @('Off', 'Error') })
                        $splatCheck  = @{
                            CheckId        = "DC-2.8"
                            CheckName      = "Query Store Enabled"
                            Category       = "Database Settings"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-2.8"]
                            Status         = if (-not $qsOff) { "Pass" } else { "Warning" }
                            CurrentValue   = if ($qsOff) {
                                ($qsOff | ForEach-Object { "$($_.Database): $($_.ActualState)" }) -join "; "
                            } else { "Query Store enabled on all $($eligibleDbs.Count) eligible database(s)" }
                            ExpectedValue  = "Query Store in READ_WRITE state on all user databases at compatibility level >= 130"
                            Remediation    = "ALTER DATABASE [<dbname>] SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE);"
                            Reference      = "SQL Server Query Store Best Practices — Query Store enables plan forcing, regressed query identification, and wait statistics history without external tools"
                            SqlQuery       = $sql["DC-2.8"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.8: $($_.Exception.Message)" }

                # DC-2.9 Contained Database Authentication
                try {
                    $containedDbs  = @($userDbs | Where-Object { $_.ContainmentType.ToString() -ne 'None' })
                    $containedCfg  = $spCfg["contained database authentication"]
                    $authEnabled   = $containedCfg -and $containedCfg.RunningValue -eq 1
                    $status29      = if ($containedDbs.Count -eq 0 -and -not $authEnabled) { "Pass" } else { "Warning" }
                    $detail29      = "Contained DB auth setting: $(if ($authEnabled) { 'Enabled' } else { 'Disabled' })"
                    if ($containedDbs) { $detail29 += "; Contained databases: $($containedDbs.Name -join ', ')" }
                    $splatCheck    = @{
                        CheckId        = "DC-2.9"
                        CheckName      = "Contained Database Authentication"
                        Category       = "Database Settings"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-2.9"]
                        Status         = $status29
                        CurrentValue   = $detail29
                        ExpectedValue  = "Contained database authentication disabled and no databases using partial containment, unless explicitly required"
                        Remediation    = "If not needed: EXEC sp_configure 'contained database authentication', 0; RECONFIGURE; ALTER DATABASE [<db>] SET CONTAINMENT = NONE;"
                        Reference      = "SQL Server Contained Databases — contained database users authenticate directly to the database, bypassing instance-level login controls and Windows password policy enforcement"
                        SqlQuery       = $sql["DC-2.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-2.9: $($_.Exception.Message)" }
            }

            # ── §3 File & Growth Settings ───────────────────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 File & Growth"

                # DC-3.1 TempDB Data File Count
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $sysInfo      = Get-DbaComputerSystem -ComputerName $computerName -EnableException
                    $logicalCpu   = [math]::Min([int]$sysInfo.NumberLogicalProcessors, 8)
                    $tmpDataFiles = @($dbFiles | Where-Object { $_.Database -eq 'tempdb' -and $_.TypeDescription -eq 'ROWS' })
                    $fileCount    = $tmpDataFiles.Count
                    $splatCheck   = @{
                        CheckId        = "DC-3.1"
                        CheckName      = "TempDB Data File Count"
                        Category       = "File & Growth"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-3.1"]
                        Status         = if ($fileCount -ge $logicalCpu) { "Pass" } else { "Warning" }
                        CurrentValue   = "$fileCount data file(s)"
                        ExpectedValue  = "$logicalCpu (min(logical CPUs, 8))"
                        Remediation    = "ALTER DATABASE [tempdb] ADD FILE (NAME = N'tempdev<n>', FILENAME = N'<path>\tempdev<n>.ndf', SIZE = <size>MB, FILEGROWTH = 512MB);"
                        Reference      = "SQL Server TempDB Best Practices — one data file per logical CPU (max 8) reduces GAM/SGAM contention"
                        SqlQuery       = $sql["DC-3.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-3.1: $($_.Exception.Message)" }

                # DC-3.2 TempDB Data Files Equal Size
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $tmpFiles  = @($dbFiles | Where-Object { $_.Database -eq 'tempdb' -and $_.TypeDescription -eq 'ROWS' })
                    $sizesMB   = @($tmpFiles | ForEach-Object { [math]::Round($_.Size.Megabytes) } | Sort-Object -Unique)
                    $hasPct    = ($tmpFiles | Where-Object { $_.GrowthType -eq 'Percent' }).Count -gt 0
                    $unequal   = $sizesMB.Count -gt 1 -or $hasPct
                    $detail    = $tmpFiles | ForEach-Object {
                        $g = if ($_.GrowthType -eq 'Percent') { "$($_.Growth)%" } else { "$($_.Growth)" }
                        "$($_.LogicalName): $([math]::Round($_.Size.Megabytes))MB grow=$g"
                    }
                    $splatCheck = @{
                        CheckId        = "DC-3.2"
                        CheckName      = "TempDB Data Files Equal Size"
                        Category       = "File & Growth"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-3.2"]
                        Status         = if (-not $unequal) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($detail) { $detail -join "; " } else { "No tempdb data files found" }
                        ExpectedValue  = "All data files same initial size with fixed-MB growth"
                        Remediation    = "Resize via DBCC SHRINKFILE then: ALTER DATABASE [tempdb] MODIFY FILE (NAME = N'<name>', SIZE = <size>MB, FILEGROWTH = 512MB);"
                        Reference      = "SQL Server TempDB Best Practices — equal file sizes ensure proportional fill distributes I/O evenly"
                        SqlQuery       = $sql["DC-3.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-3.2: $($_.Exception.Message)" }

                # DC-3.3 No Percent-Based Autogrowth
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $pctFiles   = @($dbFiles | Where-Object { $_.Database -in $userDbNames -and $_.GrowthType -eq 'Percent' })
                    $pctDetail  = $pctFiles | ForEach-Object { "$($_.Database).$($_.LogicalName) ($($_.Growth)%)" }
                    $splatCheck = @{
                        CheckId        = "DC-3.3"
                        CheckName      = "No Percent-Based Autogrowth"
                        Category       = "File & Growth"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-3.3"]
                        Status         = if (-not $pctFiles) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($pctDetail) { $pctDetail -join "; " } else { "None" }
                        ExpectedValue  = "None (all user database files use fixed-MB autogrowth)"
                        Remediation    = "ALTER DATABASE [<dbname>] MODIFY FILE (NAME = N'<logicalname>', FILEGROWTH = 512MB);"
                        Reference      = "SQL Server File Best Practices — percent growth on large files can trigger multi-GB events and excessive VLF counts"
                        SqlQuery       = $sql["DC-3.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-3.3: $($_.Exception.Message)" }

                # DC-3.4 Default Paths Not on System Drive
                try {
                    $paths      = Get-DbaDefaultPath @connSplat
                    $sysDrive   = $env:SystemDrive
                    $badPaths   = @()
                    if ($paths.Data   -like "$sysDrive*") { $badPaths += "Data: $($paths.Data)"     }
                    if ($paths.Log    -like "$sysDrive*") { $badPaths += "Log: $($paths.Log)"       }
                    if ($paths.Backup -like "$sysDrive*") { $badPaths += "Backup: $($paths.Backup)" }
                    $splatCheck = @{
                        CheckId        = "DC-3.4"
                        CheckName      = "Default Paths Not on System Drive"
                        Category       = "File & Growth"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-3.4"]
                        Status         = if (-not $badPaths) { "Pass" } else { "Warning" }
                        CurrentValue   = "Data=$($paths.Data) | Log=$($paths.Log) | Backup=$($paths.Backup)"
                        ExpectedValue  = "Data, Log, and Backup paths not on $sysDrive"
                        Remediation    = "Relocate files to dedicated drive. Update defaults: SSMS > Server Properties > Database Settings."
                        Reference      = "SQL Server Storage Best Practices — system drive contention risks OS stability if the drive fills"
                        SqlQuery       = $sql["DC-3.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-3.4: $($_.Exception.Message)" }
            }

            # ── §4 Security Configuration ───────────────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Security Config"

                # Pre-fetch SA login by SID (0x01) — shared by DC-4.1 and DC-4.2; works even if SA has been renamed
                $saLogin   = $null
                $saFetched = $false
                try {
                    $saLogin   = Get-DbaLogin @connSplat |
                        Where-Object { $_.Sid.Length -eq 1 -and $_.Sid[0] -eq 1 } |
                        Select-Object -First 1
                    $saFetched = $true
                } catch { Write-Warning "[$instance] Get-DbaLogin (SA SID pre-fetch) failed — DC-4.1/DC-4.2 skipped: $($_.Exception.Message)" }

                # DC-4.1 SA Login Disabled
                try {
                    if (-not $saFetched) { throw "SA login data not available — Get-DbaLogin pre-fetch failed" }
                    $saName41   = if ($saLogin) { $saLogin.Name } else { "sa" }
                    $splatCheck = @{
                        CheckId        = "DC-4.1"
                        CheckName      = "SA Login Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.1"]
                        Status         = if ($null -eq $saLogin) { "Manual" } elseif ($saLogin.IsDisabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $saLogin) { "No login with SA SID (0x01) found" } elseif ($saLogin.IsDisabled) { "Disabled (name: $saName41)" } else { "Enabled (name: $saName41)" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "ALTER LOGIN [$saName41] DISABLE;"
                        Reference      = "SQL Server Security Best Practices — SA is a known brute-force target; disable when not required"
                        SqlQuery       = $sql["DC-4.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.1: $($_.Exception.Message)" }

                # DC-4.2 SA Login Renamed
                try {
                    if (-not $saFetched) { throw "SA login data not available — Get-DbaLogin pre-fetch failed" }
                    $saName42   = if ($saLogin) { $saLogin.Name } else { $null }
                    $splatCheck = @{
                        CheckId        = "DC-4.2"
                        CheckName      = "SA Login Renamed"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.2"]
                        Status         = if ($null -eq $saLogin) { "Manual" } elseif ($saName42 -ne "sa") { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $saLogin) { "No login with SA SID (0x01) found" } else { $saName42 }
                        ExpectedValue  = "Not 'sa'"
                        Remediation    = "ALTER LOGIN [sa] WITH NAME = [<newname>];"
                        Reference      = "SQL Server Security Best Practices — renaming the SA SID raises the bar for targeted credential attacks"
                        SqlQuery       = $sql["DC-4.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.2: $($_.Exception.Message)" }

                # DC-4.3 Trustworthy Bit Off (uses pre-fetched $userDbs)
                try {
                    $trustDbs   = @($userDbs | Where-Object { $_.Trustworthy } | Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "DC-4.3"
                        CheckName      = "Trustworthy Bit Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.3"]
                        Status         = if (-not $trustDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($trustDbs) { $trustDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (TRUSTWORTHY = OFF on all user databases)"
                        Remediation    = "ALTER DATABASE [<dbname>] SET TRUSTWORTHY OFF;"
                        Reference      = "SQL Server Security Best Practices — TRUSTWORTHY enables cross-DB ownership chaining and elevated CLR permissions"
                        SqlQuery       = $sql["DC-4.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.3: $($_.Exception.Message)" }

                # DC-4.4 Guest User CONNECT — no dbatools equivalent; checked per user database
                try {
                    $guestQuery = "SELECT [permission_name] FROM [sys].[database_permissions] WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest') AND [permission_name] = 'CONNECT';"
                    $guestDbs   = @()
                    foreach ($db in $userDbNames) {
                        $splatQ = @{
                            SqlInstance = $instance
                            Database    = $db
                            Query       = $guestQuery
                        }
                        if ($SqlCredential) { $splatQ.SqlCredential = $SqlCredential }
                        if (Invoke-DbaQuery @splatQ) { $guestDbs += $db }
                    }
                    $splatCheck = @{
                        CheckId        = "DC-4.4"
                        CheckName      = "Guest User CONNECT Revoked"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.4"]
                        Status         = if (-not $guestDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($guestDbs) { $guestDbs -join ", " } else { "None" }
                        ExpectedValue  = "None (guest CONNECT revoked in all user databases)"
                        Remediation    = "USE [<dbname>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "SQL Server Security Best Practices — guest CONNECT allows any authenticated login database access without an explicit mapping"
                        SqlQuery       = $sql["DC-4.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.4: $($_.Exception.Message)" }

                # DC-4.5 Orphaned Database Users
                try {
                    $orphans    = @(Get-DbaDbOrphanUser @connSplat)
                    $orphanList = $orphans | ForEach-Object { "$($_.DatabaseName)\$($_.UserName)" }
                    $splatCheck = @{
                        CheckId        = "DC-4.5"
                        CheckName      = "No Orphaned Database Users"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.5"]
                        Status         = if (-not $orphanList) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($orphanList) { $orphanList -join "; " } else { "None" }
                        ExpectedValue  = "None (no orphaned users in any user database)"
                        Remediation    = "DROP USER [<username>]; -- Or remap: ALTER USER [<username>] WITH LOGIN = [<login>];"
                        Reference      = "SQL Server Security Best Practices — orphaned users hold permissions but cannot authenticate; remove after login deletion"
                        SqlQuery       = $sql["DC-4.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.5: $($_.Exception.Message)" }

                # DC-4.6 Public Role Server Permissions
                # Get-DbaPermission -IncludeServerLevel exists but its output property names for class/state
                # differ enough from sys.server_permissions that the default-exclusion filter is cleaner in SQL
                try {
                    $pubPerms   = Invoke-DbaQuery @connSplat -Query $sql["DC-4.6"]
                    $permList   = $pubPerms | ForEach-Object { "$($_.permission_name) ($($_.state_desc)) on $($_.class_desc)" }
                    $splatCheck = @{
                        CheckId        = "DC-4.6"
                        CheckName      = "Public Role Server Permissions"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.6"]
                        Status         = if (-not $permList) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($permList) { $permList -join "; " } else { "None" }
                        ExpectedValue  = "None (no non-standard permissions granted to public)"
                        Remediation    = "REVOKE <permission> FROM [public]; -- Review each permission before revoking."
                        Reference      = "SQL Server Security Best Practices — public role permissions apply to every login on the instance"
                        SqlQuery       = $sql["DC-4.6"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.6: $($_.Exception.Message)" }

                # DC-4.7 SQL Server Authentication Mode
                try {
                    $loginModeProp = Get-DbaInstanceProperty @connSplat -InstanceProperty LoginMode
                    # SMO ServerLoginMode: 1 = Integrated (Windows-only), 2 = Mixed
                    $loginMode  = ($loginModeProp | Select-Object -First 1).Value
                    $winOnly    = [int]$loginMode -eq 1
                    $splatCheck = @{
                        CheckId        = "DC-4.7"
                        CheckName      = "Authentication Mode Windows-Only"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.7"]
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Authentication" } else { "Mixed Mode (SQL + Windows)" }
                        ExpectedValue  = "Windows Authentication only"
                        Remediation    = "SSMS > Server Properties > Security > Server authentication = Windows Authentication mode. Restart SQL Server service."
                        Reference      = "CIS SQL Server Benchmark 3.1 — SQL logins are vulnerable to brute force; Windows-only auth forces Kerberos/NTLM"
                        SqlQuery       = $sql["DC-4.7"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.7: $($_.Exception.Message)" }

                # DC-4.8 SQL Server SPNs Registered
                try {
                    $spnTest    = @(Test-DbaSpn -ComputerName $computerName -EnableException)
                    $missingSpn = @($spnTest | Where-Object { -not $_.IsSet })
                    $spnDetail  = $missingSpn | Select-Object -ExpandProperty RequiredSPN
                    $splatCheck = @{
                        CheckId        = "DC-4.8"
                        CheckName      = "SQL Server SPNs Registered"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.8"]
                        Status         = if (-not $missingSpn) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($spnDetail) { "Missing: $($spnDetail -join '; ')" } else { "All required SPNs registered" }
                        ExpectedValue  = "All MSSQLSvc SPNs registered for this instance"
                        Remediation    = "Set-DbaSpn -ComputerName $computerName  (requires Active Directory write permission or submit to AD team)"
                        Reference      = "SQL Server Kerberos Best Practices — missing SPNs force NTLM fallback; breaks delegation and linked-server double-hop scenarios"
                        SqlQuery       = $sql["DC-4.8"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.8: $($_.Exception.Message)" }

                # DC-4.9 xp_cmdshell Disabled
                try {
                    $xpcmd      = $spCfg["xp_cmdshell"]
                    if ($null -eq $xpcmd) { throw "sp_configure key 'xp_cmdshell' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.9"
                        CheckName      = "xp_cmdshell Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.9"]
                        Status         = if ($xpcmd.RunningValue -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$($xpcmd.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
                        Reference      = "CIS SQL Server Benchmark 2.15 — xp_cmdshell provides direct OS command execution from SQL; disable unless explicitly required"
                        SqlQuery       = $sql["DC-4.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.9: $($_.Exception.Message)" }

                # DC-4.10 CLR Enabled = 0
                try {
                    $clr        = $spCfg["clr enabled"]
                    if ($null -eq $clr) { throw "sp_configure key 'clr enabled' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.10"
                        CheckName      = "CLR Integration Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.10"]
                        Status         = if ($clr.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($clr.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'clr enabled', 0; RECONFIGURE; -- Verify no CLR assemblies are in use first."
                        Reference      = "CIS SQL Server Benchmark 2.2 — CLR integration enables arbitrary .NET code execution inside SQL Server; disable if not required"
                        SqlQuery       = $sql["DC-4.10"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.10: $($_.Exception.Message)" }

                # DC-4.11 Ole Automation Procedures Disabled
                try {
                    $oleAuto    = $spCfg["Ole Automation Procedures"]
                    if ($null -eq $oleAuto) { throw "sp_configure key 'Ole Automation Procedures' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.11"
                        CheckName      = "Ole Automation Procedures Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.11"]
                        Status         = if ($oleAuto.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($oleAuto.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE; -- Verify no sp_OA* calls are in use first."
                        Reference      = "CIS SQL Server Benchmark 2.5 — Ole Automation allows COM object instantiation from T-SQL; unnecessary attack surface in most environments"
                        SqlQuery       = $sql["DC-4.11"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.11: $($_.Exception.Message)" }

                # DC-4.12 Ad Hoc Distributed Queries Disabled
                try {
                    $adhocDQ    = $spCfg["Ad Hoc Distributed Queries"]
                    if ($null -eq $adhocDQ) { throw "sp_configure key 'Ad Hoc Distributed Queries' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.12"
                        CheckName      = "Ad Hoc Distributed Queries Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.12"]
                        Status         = if ($adhocDQ.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($adhocDQ.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE; -- Verify no OPENROWSET/OPENDATASOURCE usage first."
                        Reference      = "CIS SQL Server Benchmark 2.1 — Ad Hoc Distributed Queries enables OPENROWSET/OPENDATASOURCE without linked server permissions; disable if not required"
                        SqlQuery       = $sql["DC-4.12"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.12: $($_.Exception.Message)" }

                # DC-4.13 Cross DB Ownership Chaining Disabled
                try {
                    $crossDbChain = $spCfg["cross db ownership chaining"]
                    if ($null -eq $crossDbChain) { throw "sp_configure key 'cross db ownership chaining' not found" }
                    $splatCheck   = @{
                        CheckId        = "DC-4.13"
                        CheckName      = "Cross DB Ownership Chaining Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.13"]
                        Status         = if ($crossDbChain.RunningValue -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$($crossDbChain.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;"
                        Reference      = "CIS SQL Server Benchmark 2.3 — cross-DB ownership chaining allows implicit privilege escalation across database boundaries"
                        SqlQuery       = $sql["DC-4.13"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.13: $($_.Exception.Message)" }

                # DC-4.14 Database Mail XPs Disabled
                try {
                    $dbMailXps  = $spCfg["Database Mail XPs"]
                    if ($null -eq $dbMailXps) { throw "sp_configure key 'Database Mail XPs' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.14"
                        CheckName      = "Database Mail XPs Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.14"]
                        Status         = if ($dbMailXps.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($dbMailXps.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE; -- Verify Database Mail is not in use first."
                        Reference      = "CIS SQL Server Benchmark 2.4 — Database Mail XPs expose external email infrastructure from SQL context; disable if not sending mail from SQL"
                        SqlQuery       = $sql["DC-4.14"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.14: $($_.Exception.Message)" }

                # DC-4.15 Remote Access Disabled
                try {
                    $remAccess  = $spCfg["remote access"]
                    if ($null -eq $remAccess) { throw "sp_configure key 'remote access' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.15"
                        CheckName      = "Remote Access Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.15"]
                        Status         = if ($remAccess.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($remAccess.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'remote access', 0; RECONFIGURE WITH OVERRIDE;"
                        Reference      = "CIS SQL Server Benchmark 2.7 — remote access is a deprecated feature; disable to reduce exposure from legacy RPC connections"
                        SqlQuery       = $sql["DC-4.15"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.15: $($_.Exception.Message)" }

                # DC-4.16 Scan for Startup Procs Disabled
                try {
                    $startupProcs = $spCfg["scan for startup procs"]
                    if ($null -eq $startupProcs) { throw "sp_configure key 'scan for startup procs' not found" }
                    $splatCheck   = @{
                        CheckId        = "DC-4.16"
                        CheckName      = "Scan for Startup Procs Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.16"]
                        Status         = if ($startupProcs.RunningValue -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = "$($startupProcs.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE; -- Verify no startup procedures are required first."
                        Reference      = "CIS SQL Server Benchmark 2.9 — startup procs execute automatically with elevated context on engine start; unnecessary ones expand the attack surface"
                        SqlQuery       = $sql["DC-4.16"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.16: $($_.Exception.Message)" }

                # DC-4.17 Sysadmin Role — No SQL Logins
                # No dbatools cmdlet returns login type alongside role membership in one call — using Invoke-DbaQuery
                try {
                    $sysadminSql    = @"
SELECT [sp].[name], [sp].[type_desc]
FROM   [sys].[server_role_members] [srm]
JOIN   [sys].[server_principals]   [sp] ON [srm].[member_principal_id] = [sp].[principal_id]
JOIN   [sys].[server_principals]   [r]  ON [srm].[role_principal_id]   = [r].[principal_id]
WHERE  [r].[name]  = 'sysadmin'
AND    [sp].[type] = 'S'
AND    [sp].[sid] <> 0x01;
"@
                    $splatSysAdminQ = @{
                        SqlInstance = $instance
                        Query       = $sysadminSql
                    }
                    if ($SqlCredential) { $splatSysAdminQ.SqlCredential = $SqlCredential }
                    $sqlSysAdmins   = @(Invoke-DbaQuery @splatSysAdminQ)
                    $sqlAdminNames  = $sqlSysAdmins | Select-Object -ExpandProperty name
                    $splatCheck     = @{
                        CheckId        = "DC-4.17"
                        CheckName      = "Sysadmin Role — No SQL Logins"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.17"]
                        Status         = if (-not $sqlSysAdmins) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($sqlAdminNames) { $sqlAdminNames -join ", " } else { "None" }
                        ExpectedValue  = "No SQL Server logins (type = SQL_LOGIN) in the sysadmin role"
                        Remediation    = "ALTER SERVER ROLE [sysadmin] DROP MEMBER [<login>]; -- Replace with least-privilege Windows group where possible."
                        Reference      = "CIS SQL Server Benchmark 3.2 — SQL logins in sysadmin bypass all authorization; prefer Windows-authenticated accounts which benefit from AD controls"
                        SqlQuery       = $sql["DC-4.17"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.17: $($_.Exception.Message)" }

                # DC-4.18 No User Databases Owned by SA SID
                # Checking by owner_sid = 0x01 to catch renamed sa accounts
                try {
                    $saOwnedSql    = "SELECT [name] FROM [sys].[databases] WHERE [owner_sid] = 0x01 AND [database_id] > 4;"
                    $splatSaOwnedQ = @{
                        SqlInstance = $instance
                        Query       = $saOwnedSql
                    }
                    if ($SqlCredential) { $splatSaOwnedQ.SqlCredential = $SqlCredential }
                    $saOwnedDbs    = @(Invoke-DbaQuery @splatSaOwnedQ)
                    $saOwnedNames  = $saOwnedDbs | Select-Object -ExpandProperty name
                    $splatCheck    = @{
                        CheckId        = "DC-4.18"
                        CheckName      = "No User Databases Owned by SA"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.18"]
                        Status         = if (-not $saOwnedDbs) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($saOwnedNames) { $saOwnedNames -join ", " } else { "None" }
                        ExpectedValue  = "No user databases owned by the SA SID (0x01)"
                        Remediation    = "ALTER AUTHORIZATION ON DATABASE::[<dbname>] TO [<service_account_or_dba_login>];"
                        Reference      = "SQL Server Security Best Practices — SA-owned databases grant elevated execution context when code runs as the database owner; assign to a low-privilege account"
                        SqlQuery       = $sql["DC-4.18"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.18: $($_.Exception.Message)" }

                # DC-4.19 No Linked Servers Using SQL Auth
                # No dbatools cmdlet for linked server login security configuration — using Invoke-DbaQuery
                try {
                    $linkedSql    = @"
SELECT [ls].[name] AS [LinkedServer], [ll].[remote_name]
FROM   [sys].[linked_logins]  [ll]
JOIN   [sys].[servers]        [ls] ON [ll].[server_id] = [ls].[server_id]
WHERE  [ll].[remote_name] IS NOT NULL
AND    [ll].[uses_self_credential] = 0;
"@
                    $splatLinkedQ = @{
                        SqlInstance = $instance
                        Query       = $linkedSql
                    }
                    if ($SqlCredential) { $splatLinkedQ.SqlCredential = $SqlCredential }
                    $sqlAuthLinks = @(Invoke-DbaQuery @splatLinkedQ)
                    $linkDetail   = $sqlAuthLinks | ForEach-Object { "$($_.LinkedServer) (login: $($_.remote_name))" }
                    $splatCheck   = @{
                        CheckId        = "DC-4.19"
                        CheckName      = "No Linked Servers Using SQL Auth"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.19"]
                        Status         = if (-not $sqlAuthLinks) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($linkDetail) { $linkDetail -join "; " } else { "None" }
                        ExpectedValue  = "No linked servers with stored SQL Server credentials (use Windows auth or no mapping)"
                        Remediation    = "Reconfigure linked server to use Windows auth: EXEC sp_addlinkedsrvlogin @rmtsrvname = N'<server>', @useself = 'TRUE';"
                        Reference      = "SQL Server Security Best Practices — stored SQL credentials in sys.linked_logins are readable by sysadmin members and persist indefinitely"
                        SqlQuery       = $sql["DC-4.19"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.19: $($_.Exception.Message)" }

                # DC-4.20 SQL Login Password Policy Enforced
                # No dbatools cmdlet filters SQL logins by SID while checking password policy — using Invoke-DbaQuery
                try {
                    $pwdPolicySql    = @"
SELECT [name], [is_policy_checked], [is_expiration_checked]
FROM   [sys].[sql_logins]
WHERE  [is_policy_checked] = 0
AND    [sid] <> 0x01
AND    [is_disabled] = 0;
"@
                    $splatPwdPolicyQ = @{
                        SqlInstance = $instance
                        Query       = $pwdPolicySql
                    }
                    if ($SqlCredential) { $splatPwdPolicyQ.SqlCredential = $SqlCredential }
                    $noPolicyLogins  = @(Invoke-DbaQuery @splatPwdPolicyQ)
                    $noPolicyNames   = $noPolicyLogins | Select-Object -ExpandProperty name
                    $splatCheck      = @{
                        CheckId        = "DC-4.20"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.20"]
                        Status         = if (-not $noPolicyLogins) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($noPolicyNames) { $noPolicyNames -join ", " } else { "None" }
                        ExpectedValue  = "CHECK_POLICY = ON for all enabled SQL Server logins"
                        Remediation    = "ALTER LOGIN [<login>] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;"
                        Reference      = "CIS SQL Server Benchmark 3.3 — logins without CHECK_POLICY bypass Windows password complexity and expiration controls"
                        SqlQuery       = $sql["DC-4.20"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.20: $($_.Exception.Message)" }

                # DC-4.21 Login Auditing Configured
                # SERVERPROPERTY('AuditLevel') is undocumented and returns NULL — read from instance registry key instead
                try {
                    $auditRegSql     = @"
DECLARE @AuditLevel INT;
EXEC xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer',
    N'AuditLevel',
    @AuditLevel OUTPUT;
SELECT ISNULL(@AuditLevel, 0) AS [AuditLevel];
"@
                    $splatAuditLevelQ = @{
                        SqlInstance = $instance
                        Query       = $auditRegSql
                    }
                    if ($SqlCredential) { $splatAuditLevelQ.SqlCredential = $SqlCredential }
                    $auditRow    = Invoke-DbaQuery @splatAuditLevelQ
                    $auditLevel  = [int]$auditRow.AuditLevel
                    $auditLabel  = switch ($auditLevel) {
                        0       { "None (no auditing)" }
                        1       { "Success logins only" }
                        2       { "Failed logins only" }
                        3       { "All logins (success and failure)" }
                        default { "$auditLevel" }
                    }
                    $status421  = if ($auditLevel -eq 0) { "Fail" } elseif ($auditLevel -eq 1) { "Warning" } else { "Pass" }
                    $splatCheck = @{
                        CheckId        = "DC-4.21"
                        CheckName      = "Login Auditing Configured"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.21"]
                        Status         = $status421
                        CurrentValue   = $auditLabel
                        ExpectedValue  = "Failed logins (2) or All logins (3)"
                        Remediation    = "SSMS > Server Properties > Security > Login auditing = 'Both failed and successful logins'. Restart SQL Server service."
                        Reference      = "CIS SQL Server Benchmark 3.4 — failed login auditing is the minimum needed to detect brute-force attempts and unauthorized access"
                        SqlQuery       = $sql["DC-4.21"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.21: $($_.Exception.Message)" }

                # DC-4.22 Priority Boost Disabled
                try {
                    $prioBoost  = $spCfg["priority boost"]
                    if ($null -eq $prioBoost) { throw "sp_configure key 'priority boost' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.22"
                        CheckName      = "Priority Boost Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.22"]
                        Status         = if ($prioBoost.RunningValue -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$($prioBoost.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'priority boost', 0; RECONFIGURE;"
                        Reference      = "CIS SQL Server Benchmark 2.6 — raising SQL Server to high OS priority can starve other processes and cause system instability; not recommended by Microsoft"
                        SqlQuery       = $sql["DC-4.22"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.22: $($_.Exception.Message)" }

                # DC-4.23 Lightweight Pooling Disabled
                try {
                    $lwPooling  = $spCfg["lightweight pooling"]
                    if ($null -eq $lwPooling) { throw "sp_configure key 'lightweight pooling' not found" }
                    $splatCheck = @{
                        CheckId        = "DC-4.23"
                        CheckName      = "Lightweight Pooling Disabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.23"]
                        Status         = if ($lwPooling.RunningValue -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$($lwPooling.RunningValue)"
                        ExpectedValue  = "0 (disabled)"
                        Remediation    = "EXEC sp_configure 'lightweight pooling', 0; RECONFIGURE;"
                        Reference      = "CIS SQL Server Benchmark 2.8 — fiber mode (lightweight pooling) is deprecated; unsupported in SQL Server 2019+ and incompatible with several features"
                        SqlQuery       = $sql["DC-4.23"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.23: $($_.Exception.Message)" }

                # DC-4.24 TLS Certificate Configured and Not Expiring
                try {
                    $tlsCert = Get-DbaNetworkCertificate -ComputerName $instance -EnableException | Select-Object -First 1
                    if ($null -eq $tlsCert -or $null -eq $tlsCert.Thumbprint -or $tlsCert.Thumbprint -eq '') {
                        $status424  = "Fail"
                        $current424 = "No TLS certificate configured — SQL Server is using an auto-generated self-signed certificate"
                        $exp424     = "A valid certificate configured in SQL Server Configuration Manager"
                    } else {
                        $daysLeft   = [math]::Round(($tlsCert.NotAfter - (Get-Date)).TotalDays)
                        $status424  = if ($daysLeft -le 30) { "Fail" } elseif ($daysLeft -le 90) { "Warning" } else { "Pass" }
                        $current424 = "$($tlsCert.Subject) — expires $($tlsCert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days remaining)"
                        $exp424     = "Valid certificate with > 90 days until expiry"
                    }
                    $splatCheck = @{
                        CheckId        = "DC-4.24"
                        CheckName      = "TLS Certificate Configured and Not Expiring"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.24"]
                        Status         = $status424
                        CurrentValue   = $current424
                        ExpectedValue  = $exp424
                        Remediation    = "Install a CA-issued certificate, then configure it in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Certificate tab. Restart SQL Server service."
                        Reference      = "SQL Server TLS Best Practices — auto-generated self-signed certs cannot be validated by clients; expiring certs cause sudden connection failures"
                        SqlQuery       = $sql["DC-4.24"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.24: $($_.Exception.Message)" }

                # DC-4.25 Force Encryption Enabled
                try {
                    $forceEnc   = Get-DbaForceNetworkEncryption -SqlInstance $instance -EnableException
                    $splatCheck = @{
                        CheckId        = "DC-4.25"
                        CheckName      = "Force Encryption Enabled"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.25"]
                        Status         = if ($forceEnc.ForceEncryption) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($forceEnc.ForceEncryption) { "Enabled" } else { "Disabled" }
                        ExpectedValue  = "Enabled"
                        Remediation    = "SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > Properties > Force Encryption = Yes. Restart SQL Server service."
                        Reference      = "SQL Server TLS Best Practices — without force encryption clients may connect unencrypted even when a certificate is configured"
                        SqlQuery       = $sql["DC-4.25"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.25: $($_.Exception.Message)" }

                # DC-4.26 TDE Encryption Status
                try {
                    $tdeEnabled  = @($userDbs | Where-Object { $_.EncryptionEnabled })
                    $splatCheck  = @{
                        CheckId        = "DC-4.26"
                        CheckName      = "TDE Encryption Status"
                        Category       = "Security"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-4.26"]
                        Status         = "Manual"
                        CurrentValue   = if ($tdeEnabled) {
                            "TDE enabled: $($tdeEnabled.Name -join ', ')"
                        } else { "No user databases have TDE enabled" }
                        ExpectedValue  = "Review — TDE requirement depends on data classification and compliance mandate"
                        Remediation    = "To enable TDE: (1) CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE <cert>; (2) ALTER DATABASE [<db>] SET ENCRYPTION ON;"
                        Reference      = "SQL Server TDE — Transparent Data Encryption protects data files at rest; required for PCI-DSS, HIPAA, and many SOC 2 controls"
                        SqlQuery       = $sql["DC-4.26"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.26: $($_.Exception.Message)" }

                # DC-4.27 SQL Server Audit Configured
                try {
                    $serverAudits  = @(Get-DbaInstanceAudit @connSplat)
                    $enabledAudits = @($serverAudits | Where-Object { $_.Enabled })
                    $splatCheck    = @{
                        CheckId        = "DC-4.27"
                        CheckName      = "SQL Server Audit Configured"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.27"]
                        Status         = if ($enabledAudits.Count -gt 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($serverAudits.Count -eq 0) {
                            "No server audits defined"
                        } elseif ($enabledAudits.Count -eq 0) {
                            "Audits defined but none enabled: $($serverAudits.Name -join ', ')"
                        } else {
                            "$($enabledAudits.Count) enabled audit(s): $($enabledAudits.Name -join ', ')"
                        }
                        ExpectedValue  = "At least one enabled server audit capturing security-relevant events"
                        Remediation    = "CREATE SERVER AUDIT to define an audit target, then CREATE SERVER AUDIT SPECIFICATION to capture login events, permission changes, and schema changes. Enable with ALTER SERVER AUDIT <name> WITH (STATE = ON)."
                        Reference      = "SQL Server Audit Best Practices — SQL Server Audit writes to Windows Event Log or file; required for SOX, PCI-DSS, and SOC 2 logging controls"
                        SqlQuery       = $sql["DC-4.27"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.27: $($_.Exception.Message)" }

                # DC-4.28 Non-Standard Global Trace Flags
                try {
                    $traceFlags = @(Get-DbaTraceFlag @connSplat | Where-Object { $_.Global })
                    $splatCheck = @{
                        CheckId        = "DC-4.28"
                        CheckName      = "Non-Standard Global Trace Flags"
                        Category       = "Security"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-4.28"]
                        Status         = if (-not $traceFlags) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($traceFlags) {
                            "Active global trace flags: $($traceFlags.TraceFlag -join ', ')"
                        } else { "No global trace flags active" }
                        ExpectedValue  = "No undocumented global trace flags"
                        Remediation    = "Review each flag. Remove undocumented or test flags with DBCC TRACEOFF(<flag>, -1). Document any intentional trace flags and their purpose."
                        Reference      = "SQL Server Trace Flags — global trace flags alter engine behavior for all connections; undocumented flags are unsupported and may cause instability"
                        SqlQuery       = $sql["DC-4.28"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.28: $($_.Exception.Message)" }

                # DC-4.29 SQL Server Port Access Restricted at Firewall
                try {
                    $splatCheck = @{
                        CheckId        = "DC-4.29"
                        CheckName      = "SQL Server Port Access Restricted at Firewall"
                        Category       = "Security"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-4.29"]
                        Status         = "Manual"
                        CurrentValue   = "Review required — automated firewall rule enumeration not available"
                        ExpectedValue  = "SQL TCP port accessible only from authorized application servers and admin hosts; blocked from broad network ranges"
                        Remediation    = "Review Windows Firewall Advanced Security inbound rules or network ACLs. Confirm SQL port (default 1433) is restricted to known source IPs."
                        Reference      = "SQL Server Network Security — unrestricted inbound access to SQL port exposes the instance to brute-force login attempts and unauthenticated CVE exploitation"
                        SqlQuery       = $sql["DC-4.29"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-4.29: $($_.Exception.Message)" }
            }

            # ── §5 Storage Layout ───────────────────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Storage Layout"

                # DC-5.1 NTFS Allocation Unit = 64K on SQL Volumes
                try {
                    $diskAlloc  = @(Test-DbaDiskAllocation -ComputerName $computerName -EnableException)
                    $badDisks   = @($diskAlloc | Where-Object { $_.IsSqlDisk -and -not $_.IsBestPractice })
                    $badDetail  = $badDisks | ForEach-Object { "$($_.DiskName): $([math]::Round($_.BlockSize / 1024))KB" }
                    $splatCheck = @{
                        CheckId        = "DC-5.1"
                        CheckName      = "NTFS Allocation Unit = 64KB on SQL Volumes"
                        Category       = "Storage"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-5.1"]
                        Status         = if (-not $badDisks) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($badDetail) { $badDetail -join "; " } else { "All SQL volumes formatted at 64KB" }
                        ExpectedValue  = "64KB allocation unit on all volumes hosting SQL Server files"
                        Remediation    = "Reformat the volume at 64KB: backup all data, format /FS:NTFS /A:65536, restore. This is disruptive."
                        Reference      = "SQL Server Storage Best Practices — 4KB allocation unit causes 8 I/Os per 64KB SQL Server extent read/write"
                        SqlQuery       = $sql["DC-5.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-5.1: $($_.Exception.Message)" }

                # DC-5.2 Data Files and Log Files on Separate Volumes
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $mixedDbs = @()
                    foreach ($dbName in $userDbNames) {
                        $dbF       = @($dbFiles | Where-Object { $_.Database -eq $dbName })
                        if ($dbF.Count -eq 0) { continue }
                        $dataRoots = @($dbF | Where-Object { $_.TypeDescription -eq 'ROWS' } |
                            ForEach-Object { [System.IO.Path]::GetPathRoot($_.PhysicalName).ToUpper().TrimEnd('\') } |
                            Sort-Object -Unique)
                        $logRoots  = @($dbF | Where-Object { $_.TypeDescription -eq 'LOG' } |
                            ForEach-Object { [System.IO.Path]::GetPathRoot($_.PhysicalName).ToUpper().TrimEnd('\') } |
                            Sort-Object -Unique)
                        $overlap   = @($dataRoots | Where-Object { $_ -in $logRoots })
                        if ($overlap.Count -gt 0) { $mixedDbs += "$dbName (shared: $($overlap -join ','))" }
                    }
                    $splatCheck = @{
                        CheckId        = "DC-5.2"
                        CheckName      = "Data and Log Files on Separate Volumes"
                        Category       = "Storage"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-5.2"]
                        Status         = if (-not $mixedDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($mixedDbs) { $mixedDbs -join "; " } else { "All databases: data and log on separate volumes" }
                        ExpectedValue  = "No database has data and log files on the same volume"
                        Remediation    = "Move log files to a dedicated volume: ALTER DATABASE [<db>] MODIFY FILE (NAME = N'<log>', FILENAME = N'<new_path>'); then detach/attach or use OFFLINE."
                        Reference      = "SQL Server Storage Best Practices — co-located data+log risks I/O contention and makes volume-full scenarios catastrophic for recovery"
                        SqlQuery       = $sql["DC-5.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-5.2: $($_.Exception.Message)" }

                # DC-5.3 TempDB on Its Own Volume (separate from user databases)
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $tmpRoots  = @($dbFiles | Where-Object { $_.Database -eq 'tempdb' -and $_.TypeDescription -eq 'ROWS' } |
                        ForEach-Object { [System.IO.Path]::GetPathRoot($_.PhysicalName).ToUpper().TrimEnd('\') } |
                        Sort-Object -Unique)
                    $userRoots = @($dbFiles | Where-Object { $_.Database -in $userDbNames -and $_.TypeDescription -eq 'ROWS' } |
                        ForEach-Object { [System.IO.Path]::GetPathRoot($_.PhysicalName).ToUpper().TrimEnd('\') } |
                        Sort-Object -Unique)
                    $shared    = @($tmpRoots | Where-Object { $_ -in $userRoots })
                    $splatCheck = @{
                        CheckId        = "DC-5.3"
                        CheckName      = "TempDB on Dedicated Volume"
                        Category       = "Storage"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-5.3"]
                        Status         = if (-not $shared) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($shared) { "TempDB shares volume(s) with user databases: $($shared -join ', ')" } else { "TempDB on dedicated volume(s): $($tmpRoots -join ', ')" }
                        ExpectedValue  = "TempDB data files on a volume not shared with user databases"
                        Remediation    = "Move TempDB files to a dedicated volume: ALTER DATABASE [tempdb] MODIFY FILE (NAME = N'tempdev', FILENAME = N'<dedicated_path>\tempdev.mdf'); restart SQL Server."
                        Reference      = "SQL Server Storage Best Practices — TempDB I/O competes with user database I/O on shared volumes, causing latency under load"
                        SqlQuery       = $sql["DC-5.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-5.3: $($_.Exception.Message)" }

                # DC-5.4 Disk Space Free on SQL Volumes
                try {
                    if (-not $dbFilesFetched) { throw "Database file data not available — Get-DbaDbFile pre-fetch failed" }
                    $sqlRoots   = @($dbFiles |
                        ForEach-Object { [System.IO.Path]::GetPathRoot($_.PhysicalName).ToUpper().TrimEnd('\') } |
                        Sort-Object -Unique)
                    $diskSpace  = @(Get-DbaDiskSpace -ComputerName $computerName -EnableException |
                        Where-Object { $_.Name.ToUpper().TrimEnd('\') -in $sqlRoots })
                    $failDisks  = @($diskSpace | Where-Object { $_.PercentFree -lt 10 })
                    $warnDisks  = @($diskSpace | Where-Object { $_.PercentFree -ge 10 -and $_.PercentFree -lt 20 })
                    $status54   = if ($failDisks) { "Fail" } elseif ($warnDisks) { "Warning" } else { "Pass" }
                    $detail54   = $diskSpace | ForEach-Object {
                        "$($_.Name): $([math]::Round($_.Free.Gigabytes, 1))GB free of $([math]::Round($_.Capacity.Gigabytes, 1))GB ($([math]::Round($_.PercentFree, 1))%)"
                    }
                    $splatCheck = @{
                        CheckId        = "DC-5.4"
                        CheckName      = "Disk Space Free on SQL Volumes"
                        Category       = "Storage"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-5.4"]
                        Status         = $status54
                        CurrentValue   = if ($detail54) { $detail54 -join "; " } else { "No SQL volumes found" }
                        ExpectedValue  = ">= 20% free on all volumes hosting SQL Server files"
                        Remediation    = "Free disk space or add capacity. Monitor via SQL Agent job or disk monitoring alerts."
                        Reference      = "SQL Server Storage Best Practices — full data volumes crash the instance; full log volumes cause transactions to fail and risk data loss"
                        SqlQuery       = $sql["DC-5.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-5.4: $($_.Exception.Message)" }
            }

            # ── §6 Database Health ──────────────────────────────────────────
            if (ShouldRun "6") {
                Write-Verbose "[$instance] §6 Database Health"

                # ── Pre-fetch: last backup data (DC-6.3, DC-6.4) ─────────────
                $lastBackupData = @()
                $backupFetched  = $false
                try {
                    $lastBackupData = @(Get-DbaLastBackup @connSplat -WarningAction SilentlyContinue)
                    $backupFetched  = $true
                } catch { Write-Warning "[$instance] Get-DbaLastBackup failed — DC-6.3/DC-6.4 skipped: $($_.Exception.Message)" }

                # DC-6.1 Excessive VLF Count
                try {
                    $vlfs      = @(Measure-DbaDbVirtualLogFile @connSplat | Where-Object { $_.Database -in $userDbNames })
                    $highVlfs  = @($vlfs | Where-Object { $_.Total -gt 1000 } | ForEach-Object { "$($_.Database) ($($_.Total))" })
                    $warnVlfs  = @($vlfs | Where-Object { $_.Total -gt 500 -and $_.Total -le 1000 } | ForEach-Object { "$($_.Database) ($($_.Total))" })
                    $status61  = if ($highVlfs) { "Fail" } elseif ($warnVlfs) { "Warning" } else { "Pass" }
                    $current61 = if ($highVlfs) { "Critical (>1000): $($highVlfs -join '; ')" }
                                 elseif ($warnVlfs) { "Elevated (>500): $($warnVlfs -join '; ')" }
                                 else { "All databases within acceptable VLF count" }
                    $splatCheck = @{
                        CheckId        = "DC-6.1"
                        CheckName      = "VLF Count Within Acceptable Range"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.1"]
                        Status         = $status61
                        CurrentValue   = $current61
                        ExpectedValue  = "<= 500 VLFs per database"
                        Remediation    = "Shrink the log, set a fixed-MB growth increment, then grow it back in controlled increments to consolidate VLFs."
                        Reference      = "SQL Server VLF Best Practices — excessive VLFs cause slow log backups, slow recovery, and slow database attach"
                        SqlQuery       = $sql["DC-6.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.1: $($_.Exception.Message)" }

                # DC-6.2 DBCC CHECKDB Recency
                try {
                    $lastCheck  = @(Get-DbaLastGoodCheckDb @connSplat | Where-Object { $_.Database -in $userDbNames })
                    $staleCheck = @($lastCheck | Where-Object {
                        $null -eq $_.LastGoodCheckDb -or [int]$_.DaysSinceLastGoodCheckDb -gt 30
                    } | ForEach-Object {
                        $days = if ($null -eq $_.LastGoodCheckDb) { "never" } else { "$([int]$_.DaysSinceLastGoodCheckDb) days ago" }
                        "$($_.Database) ($days)"
                    })
                    $splatCheck = @{
                        CheckId        = "DC-6.2"
                        CheckName      = "DBCC CHECKDB Run Within 30 Days"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.2"]
                        Status         = if (-not $staleCheck) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($staleCheck) { $staleCheck -join "; " } else { "All databases checked within 30 days" }
                        ExpectedValue  = "DBCC CHECKDB completed successfully within the last 30 days for all user databases"
                        Remediation    = "DBCC CHECKDB ([<dbname>]) WITH NO_INFOMSGS; -- Schedule weekly via SQL Agent job."
                        Reference      = "SQL Server Integrity Best Practices — corruption undetected beyond the backup retention window is unrecoverable"
                        SqlQuery       = $sql["DC-6.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.2: $($_.Exception.Message)" }

                # DC-6.3 Full Backup Recency
                try {
                    if (-not $backupFetched) { throw "Backup data not available — Get-DbaLastBackup pre-fetch failed" }
                    $lastBackup = @($lastBackupData | Where-Object { $_.Database -in $userDbNames })
                    $noBackup   = @($lastBackup | Where-Object {
                        $null -eq $_.LastFullBackup -or
                        $_.LastFullBackup -eq [datetime]::MinValue -or
                        $null -eq $_.SinceFull -or
                        [double]$_.SinceFull.TotalDays -gt 7
                    } | ForEach-Object {
                        $age = if ($null -eq $_.LastFullBackup -or $_.LastFullBackup -eq [datetime]::MinValue) { "never" }
                               else { "$([math]::Round([double]$_.SinceFull.TotalDays, 1)) days ago" }
                        "$($_.Database) ($age)"
                    })
                    $splatCheck = @{
                        CheckId        = "DC-6.3"
                        CheckName      = "Full Backup Within 7 Days"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.3"]
                        Status         = if (-not $noBackup) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($noBackup) { $noBackup -join "; " } else { "All databases have a recent full backup" }
                        ExpectedValue  = "Full backup completed within the last 7 days for all user databases"
                        Remediation    = "BACKUP DATABASE [<dbname>] TO DISK = N'<path>' WITH COMPRESSION, STATS = 10; -- Schedule via SQL Agent."
                        Reference      = "SQL Server Backup Best Practices — full backups older than 7 days indicate a gap in RPO coverage"
                        SqlQuery       = $sql["DC-6.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.3: $($_.Exception.Message)" }

                # DC-6.4 Log Backup Recency (FULL/BULK_LOGGED databases)
                try {
                    if (-not $backupFetched) { throw "Backup data not available — Get-DbaLastBackup pre-fetch failed" }
                    $fullRecovDbs = @($userDbs | Where-Object { $_.RecoveryModel.ToString() -ne 'Simple' } | Select-Object -ExpandProperty Name)
                    if ($fullRecovDbs.Count -eq 0) {
                        $status64  = "Pass"
                        $current64 = "All user databases in SIMPLE recovery — log backups not applicable"
                    } else {
                        $logBackups = @($lastBackupData | Where-Object { $_.Database -in $fullRecovDbs })
                        $staleLog   = @($logBackups | Where-Object {
                            $null -eq $_.LastLogBackup -or
                            $_.LastLogBackup -eq [datetime]::MinValue -or
                            $null -eq $_.SinceLog -or
                            [double]$_.SinceLog.TotalHours -gt 24
                        } | ForEach-Object {
                            $age = if ($null -eq $_.LastLogBackup -or $_.LastLogBackup -eq [datetime]::MinValue) { "never" }
                                   else { "$([math]::Round([double]$_.SinceLog.TotalHours, 1)) hours ago" }
                            "$($_.Database) ($age)"
                        })
                        $warnLog    = @($logBackups | Where-Object {
                            $null -ne $_.LastLogBackup -and
                            $_.LastLogBackup -ne [datetime]::MinValue -and
                            $null -ne $_.SinceLog -and
                            [double]$_.SinceLog.TotalHours -gt 4 -and
                            [double]$_.SinceLog.TotalHours -le 24
                        } | ForEach-Object { "$($_.Database) ($([math]::Round([double]$_.SinceLog.TotalHours, 1)) hours ago)" })
                        $status64  = if ($staleLog) { "Fail" } elseif ($warnLog) { "Warning" } else { "Pass" }
                        $current64 = if ($staleLog) { "No log backup >24h: $($staleLog -join '; ')" }
                                     elseif ($warnLog) { "Log backup >4h ago: $($warnLog -join '; ')" }
                                     else { "All FULL/BULK_LOGGED databases have a recent log backup" }
                    }
                    $splatCheck = @{
                        CheckId        = "DC-6.4"
                        CheckName      = "Log Backup Within 4 Hours"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.4"]
                        Status         = $status64
                        CurrentValue   = $current64
                        ExpectedValue  = "Log backup within 4 hours for all FULL/BULK_LOGGED recovery databases"
                        Remediation    = "BACKUP LOG [<dbname>] TO DISK = N'<path>' WITH COMPRESSION; -- Schedule via SQL Agent every 15-60 minutes for production databases."
                        Reference      = "SQL Server Backup Best Practices — FULL recovery model without frequent log backups leaves an RPO gap equal to the time since the last full backup"
                        SqlQuery       = $sql["DC-6.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.4: $($_.Exception.Message)" }

                # DC-6.5 No Databases in Problem States
                # No dbatools cmdlet returns engine-set database states (SUSPECT, EMERGENCY) — using Invoke-DbaQuery
                try {
                    $splatProblemDbQ = @{
                        SqlInstance = $instance
                        Query       = $sql["DC-6.5"]
                    }
                    if ($SqlCredential) { $splatProblemDbQ.SqlCredential = $SqlCredential }
                    $problemDbs = @(Invoke-DbaQuery @splatProblemDbQ)
                    $failDbs    = @($problemDbs | Where-Object { $_.state_desc -in @('SUSPECT', 'EMERGENCY') } |
                        ForEach-Object { "$($_.name) ($($_.state_desc))" })
                    $warnDbs    = @($problemDbs | Where-Object { $_.state_desc -notin @('SUSPECT', 'EMERGENCY') } |
                        ForEach-Object { "$($_.name) ($($_.state_desc))" })
                    $status65   = if ($failDbs) { "Fail" } elseif ($warnDbs) { "Warning" } else { "Pass" }
                    $detail65   = if ($failDbs) { $failDbs -join "; " }
                                  elseif ($warnDbs) { $warnDbs -join "; " }
                                  else { "All databases online or intentionally offline" }
                    $splatCheck = @{
                        CheckId        = "DC-6.5"
                        CheckName      = "No Databases in Problem States"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.5"]
                        Status         = $status65
                        CurrentValue   = $detail65
                        ExpectedValue  = "No databases in SUSPECT, EMERGENCY, RESTORING, or RECOVERY_PENDING state"
                        Remediation    = "Investigate immediately: review SQL Server error log and run DBCC CHECKDB. SUSPECT state may indicate data loss."
                        Reference      = "SQL Server Database Health — SUSPECT/EMERGENCY state indicates an unrecoverable error or corruption; requires immediate DBA attention"
                        SqlQuery       = $sql["DC-6.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.5: $($_.Exception.Message)" }

                # DC-6.6 No Suspect Pages
                try {
                    $suspectPages  = @(Get-DbaSuspectPage @connSplat)
                    $activeCorrupt = @($suspectPages | Where-Object { $_.EventType -notin @('Restored', 'Repaired', 'Deallocated') })
                    $splatCheck    = @{
                        CheckId        = "DC-6.6"
                        CheckName      = "No Suspect Pages"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.6"]
                        Status         = if ($activeCorrupt) { "Fail" } else { "Pass" }
                        CurrentValue   = if ($activeCorrupt) {
                            ($activeCorrupt | ForEach-Object { "$($_.Database) FileId:$($_.FileId) PageId:$($_.PageId) ($($_.EventType))" }) -join "; "
                        } else { "No suspect pages found" }
                        ExpectedValue  = "No unresolved entries in msdb.dbo.suspect_pages"
                        Remediation    = "Run DBCC CHECKDB against the affected database. If corruption is confirmed, restore from a known-good backup immediately."
                        Reference      = "SQL Server Data Integrity — suspect pages indicate unresolved I/O errors (823/824), bad checksums, or torn pages; each entry is a potential data loss event"
                        SqlQuery       = $sql["DC-6.6"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.6: $($_.Exception.Message)" }

                # DC-6.7 Identity Column Saturation
                try {
                    $splatIdent    = @{
                        SqlInstance   = $instance
                        ExcludeSystem = $true
                        Threshold     = 80
                    }
                    if ($SqlCredential) { $splatIdent.SqlCredential = $SqlCredential }
                    $identityData  = @(Test-DbaIdentityUsage @splatIdent)
                    $critical      = @($identityData | Where-Object { $_.PercentUsed -ge 90 })
                    $warned        = @($identityData | Where-Object { $_.PercentUsed -ge 80 -and $_.PercentUsed -lt 90 })
                    $splatCheck    = @{
                        CheckId        = "DC-6.7"
                        CheckName      = "Identity Column Saturation"
                        Category       = "Database Health"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-6.7"]
                        Status         = if ($critical) { "Fail" } elseif ($warned) { "Warning" } else { "Pass" }
                        CurrentValue   = if ($critical) {
                            ($critical | ForEach-Object { "$($_.Database).$($_.Schema).$($_.Table).$($_.Column): $($_.PercentUsed)%" }) -join "; "
                        } elseif ($warned) {
                            ($warned | ForEach-Object { "$($_.Database).$($_.Schema).$($_.Table).$($_.Column): $($_.PercentUsed)%" }) -join "; "
                        } else { "No identity columns above 80% capacity" }
                        ExpectedValue  = "No identity columns above 80% of data type capacity"
                        Remediation    = "Reseed: DBCC CHECKIDENT('<table>', RESEED, 0) if rows were deleted. Otherwise change the column to BIGINT to extend range."
                        Reference      = "SQL Server Identity Overflow — INT identity wraps at 2,147,483,647; SMALLINT at 32,767. Overflow causes INSERT failures and application errors with no warning beforehand"
                        SqlQuery       = $sql["DC-6.7"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.7: $($_.Exception.Message)" }

                # DC-6.8 Backup Restore Tested Within Last 90 Days
                try {
                    $splatCheck = @{
                        CheckId        = "DC-6.8"
                        CheckName      = "Backup Restore Tested Within Last 90 Days"
                        Category       = "Database Health"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-6.8"]
                        Status         = "Manual"
                        CurrentValue   = "Review required — restore history exists but does not confirm a successful validation test"
                        ExpectedValue  = "Documented restore test per database within the last 90 days, validated for completeness and application consistency"
                        Remediation    = "Schedule periodic restore tests to a non-production environment. Use Test-DbaLastBackup to perform automated file-level backup verification."
                        Reference      = "SQL Server Backup Best Practices — a backup that has never been restored is unvalidated; recovery tests confirm both file integrity and restoration procedures"
                        SqlQuery       = $sql["DC-6.8"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-6.8: $($_.Exception.Message)" }
            }

            # ── §7 SQL Agent / Alerting ─────────────────────────────────────
            if (ShouldRun "7") {
                Write-Verbose "[$instance] §7 SQL Agent"

                # Pre-fetch alerts once for DC-7.2 and DC-7.3
                $agentAlerts  = @()
                $alertsFetched = $false
                try {
                    $agentAlerts  = @(Get-DbaAgentAlert @connSplat)
                    $alertsFetched = $true
                } catch { Write-Warning "[$instance] Get-DbaAgentAlert failed — DC-7.2/DC-7.3 skipped: $($_.Exception.Message)" }

                # DC-7.1 SQL Agent Service Running
                try {
                    $agentSvc   = @(Get-DbaService -ComputerName $computerName -Type Agent -EnableException)
                    $isRunning  = ($agentSvc | Where-Object { $_.State -eq 'Running' }).Count -gt 0
                    $svcState   = if ($agentSvc.Count -gt 0) { $agentSvc[0].State } else { "Service not found" }
                    $splatCheck = @{
                        CheckId        = "DC-7.1"
                        CheckName      = "SQL Agent Service Running"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.1"]
                        Status         = if ($isRunning) { "Pass" } else { "Fail" }
                        CurrentValue   = $svcState
                        ExpectedValue  = "Running"
                        Remediation    = "Start-DbaService -ComputerName $computerName -Type Agent  (or: net start SQLSERVERAGENT)"
                        Reference      = "SQL Server Agent Best Practices — stopped agent means all jobs and alerts are silently not executing"
                        SqlQuery       = $sql["DC-7.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.1: $($_.Exception.Message)" }

                # DC-7.2 Severity 17-25 Alerts Configured
                try {
                    if (-not $alertsFetched) { throw "Alert data not available — Get-DbaAgentAlert failed" }
                    $coveredSev  = @($agentAlerts | Where-Object { $_.IsEnabled -and $_.Severity -ge 17 -and $_.Severity -le 25 } |
                        Select-Object -ExpandProperty Severity | Sort-Object -Unique)
                    $missingSev  = @(17..25 | Where-Object { $_ -notin $coveredSev })
                    $splatCheck  = @{
                        CheckId        = "DC-7.2"
                        CheckName      = "Severity 17-25 Alerts Configured"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.2"]
                        Status         = if (-not $missingSev) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingSev) { "Missing severities: $($missingSev -join ', ')" } else { "Severities 17-25 all covered" }
                        ExpectedValue  = "Enabled alert for each severity 17 through 25"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Severity <n>', @severity = <n>, @enabled = 1, @notification_message = N'Severity <n> error';"
                        Reference      = "SQL Server Alerting Best Practices — severity 17+ indicates resource or engine errors that require DBA attention"
                        SqlQuery       = $sql["DC-7.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.2: $($_.Exception.Message)" }

                # DC-7.3 Error 825 Alert Configured
                try {
                    if (-not $alertsFetched) { throw "Alert data not available — Get-DbaAgentAlert failed" }
                    $err825     = @($agentAlerts | Where-Object { $_.IsEnabled -and $_.MessageId -eq 825 })
                    $splatCheck = @{
                        CheckId        = "DC-7.3"
                        CheckName      = "Error 825 Alert Configured"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.3"]
                        Status         = if ($err825.Count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($err825.Count -gt 0) { "Alert configured: $($err825[0].Name)" } else { "No enabled alert for error 825" }
                        ExpectedValue  = "At least one enabled alert with MessageId = 825"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Error 825 - I/O Soft Error', @message_id = 825, @enabled = 1;"
                        Reference      = "SQL Server Alerting Best Practices — error 825 is a retried I/O; it indicates disk sub-system problems and is a precursor to hardware failure"
                        SqlQuery       = $sql["DC-7.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.3: $($_.Exception.Message)" }

                # DC-7.4 At Least One Enabled Operator
                try {
                    $operators  = @(Get-DbaAgentOperator @connSplat)
                    $enabledOps = @($operators | Where-Object { $_.IsEnabled })
                    $opNames    = $enabledOps | Select-Object -ExpandProperty Name
                    $splatCheck = @{
                        CheckId        = "DC-7.4"
                        CheckName      = "SQL Agent Operator Configured"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.4"]
                        Status         = if ($enabledOps.Count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($enabledOps.Count -gt 0) { "$($enabledOps.Count) enabled: $($opNames -join ', ')" } else { "No enabled operators" }
                        ExpectedValue  = "At least one enabled SQL Agent operator"
                        Remediation    = "EXEC msdb.dbo.sp_add_operator @name = N'<DBA Team>', @enabled = 1, @email_address = N'<email>';"
                        Reference      = "SQL Server Alerting Best Practices — without an operator, alerts fire but generate no notification"
                        SqlQuery       = $sql["DC-7.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.4: $($_.Exception.Message)" }

                # DC-7.5 Alerts Have Notifications (no dbatools cmdlet for notification membership — Invoke-DbaQuery against msdb)
                try {
                    $splatNotif  = @{
                        SqlInstance = $instance
                        Database    = "msdb"
                        Query       = $sql["DC-7.5"]
                    }
                    if ($SqlCredential) { $splatNotif.SqlCredential = $SqlCredential }
                    $noNotif     = @(Invoke-DbaQuery @splatNotif)
                    $noNotifNames = $noNotif | Select-Object -ExpandProperty name
                    $splatCheck  = @{
                        CheckId        = "DC-7.5"
                        CheckName      = "All Alerts Have Notifications"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.5"]
                        Status         = if (-not $noNotif) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($noNotifNames) { "No notification: $($noNotifNames -join ', ')" } else { "All enabled alerts have at least one notification" }
                        ExpectedValue  = "All enabled alerts have at least one operator notification configured"
                        Remediation    = "EXEC msdb.dbo.sp_add_notification @alert_name = N'<alert>', @operator_name = N'<operator>', @notification_method = 1;"
                        Reference      = "SQL Server Alerting Best Practices — an alert with no notification configured fires silently; no one is paged"
                        SqlQuery       = $sql["DC-7.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.5: $($_.Exception.Message)" }

                # DC-7.6 System Health XE Session Running and Auto-Start Enabled
                try {
                    $sysHealth   = Get-DbaXESession @connSplat | Where-Object { $_.Name -eq 'system_health' } | Select-Object -First 1
                    $notFound    = $null -eq $sysHealth
                    $notRunning  = -not $notFound -and $sysHealth.Status -ne 'Running'
                    $noAutoStart = -not $notFound -and -not $sysHealth.AutoStart
                    $status76    = if ($notFound -or $notRunning) { "Fail" } elseif ($noAutoStart) { "Warning" } else { "Pass" }
                    $current76   = if ($notFound) { "system_health session not found" }
                                   elseif ($notRunning) { "Status: $($sysHealth.Status); AutoStart: $($sysHealth.AutoStart)" }
                                   elseif ($noAutoStart) { "Running but AutoStart = False — session will not restart after SQL Server restart" }
                                   else { "Running with AutoStart enabled" }
                    $splatCheck  = @{
                        CheckId        = "DC-7.6"
                        CheckName      = "System Health XE Session Running"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.6"]
                        Status         = $status76
                        CurrentValue   = $current76
                        ExpectedValue  = "system_health session Running with AutoStart = True"
                        Remediation    = "ALTER EVENT SESSION [system_health] ON SERVER STATE = START; ALTER EVENT SESSION [system_health] ON SERVER WITH (STARTUP_STATE = ON);"
                        Reference      = "SQL Server Diagnostics Best Practices — system_health captures deadlocks, memory pressure, connectivity errors, and wait stats; loss of this session eliminates key post-incident evidence"
                        SqlQuery       = $sql["DC-7.6"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.6: $($_.Exception.Message)" }

                # DC-7.7 No Agent Job Failures in Last 24 Hours
                try {
                    $splatJobHist  = @{
                        SqlInstance = $instance
                        OutcomeType = 'Failed'
                        StartDate   = (Get-Date).AddHours(-24)
                    }
                    if ($SqlCredential) { $splatJobHist.SqlCredential = $SqlCredential }
                    $failedJobs    = @(Get-DbaAgentJobHistory @splatJobHist)
                    $failedNames   = @($failedJobs | Select-Object -ExpandProperty Job -Unique)
                    $splatCheck    = @{
                        CheckId        = "DC-7.7"
                        CheckName      = "No Agent Job Failures in Last 24 Hours"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.7"]
                        Status         = if ($failedNames) { "Fail" } else { "Pass" }
                        CurrentValue   = if ($failedNames) { $failedNames -join "; " } else { "No failed jobs in last 24 hours" }
                        ExpectedValue  = "No failed SQL Agent jobs in last 24 hours"
                        Remediation    = "Review job history: SSMS > SQL Server Agent > Jobs > right-click > View History, or query msdb.dbo.sysjobhistory WHERE run_status = 0 AND step_id = 0."
                        Reference      = "SQL Server Operational Health — failed jobs may indicate missed backups, maintenance failures, or ETL errors that compound if not addressed promptly"
                        SqlQuery       = $sql["DC-7.7"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.7: $($_.Exception.Message)" }

                # DC-7.8 No Agent Jobs Running Longer Than 60 Minutes
                # Get-DbaRunningJob identifies executing jobs but does not expose current run duration — using Invoke-DbaQuery against msdb.dbo.sysjobactivity
                try {
                    $longJobSql    = @"
SELECT [j].[name]                                          AS [JobName],
       [a].[start_execution_date]                          AS [StartTime],
       DATEDIFF(MINUTE, [a].[start_execution_date], GETDATE()) AS [RunMinutes]
FROM   [msdb].[dbo].[sysjobactivity] [a]
JOIN   [msdb].[dbo].[sysjobs]        [j] ON [j].[job_id] = [a].[job_id]
WHERE  [a].[start_execution_date] IS NOT NULL
AND    [a].[stop_execution_date]  IS NULL
AND    [a].[run_requested_date]   IS NOT NULL
AND    DATEDIFF(MINUTE, [a].[start_execution_date], GETDATE()) > 60
ORDER  BY [RunMinutes] DESC;
"@
                    $splatLongJobQ = @{
                        SqlInstance = $instance
                        Query       = $longJobSql
                    }
                    if ($SqlCredential) { $splatLongJobQ.SqlCredential = $SqlCredential }
                    $longJobs      = @(Invoke-DbaQuery @splatLongJobQ)
                    $splatCheck    = @{
                        CheckId        = "DC-7.8"
                        CheckName      = "No Agent Jobs Running Longer Than 60 Minutes"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.8"]
                        Status         = if ($longJobs) { "Warning" } else { "Pass" }
                        CurrentValue   = if ($longJobs) {
                            ($longJobs | ForEach-Object { "$($_.JobName) ($($_.RunMinutes) min)" }) -join "; "
                        } else { "No jobs running longer than 60 minutes" }
                        ExpectedValue  = "No jobs exceeding 60-minute run time"
                        Remediation    = "Determine whether the run time is expected (e.g., overnight maintenance) or indicates blocking, resource contention, or a runaway process."
                        Reference      = "SQL Server Operational Health — jobs significantly exceeding their normal run time may indicate blocking chains, I/O saturation, or runaway queries"
                        SqlQuery       = $sql["DC-7.8"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.8: $($_.Exception.Message)" }

                # DC-7.9 Ola Hallengren Maintenance Solution Installed
                try {
                    $splatOlaProcs = @{
                        SqlInstance = $instance
                        Database    = "master"
                    }
                    if ($SqlCredential) { $splatOlaProcs.SqlCredential = $SqlCredential }
                    $olaProcs      = @(Get-DbaDbStoredProcedure @splatOlaProcs |
                        Where-Object { $_.Name -in @('DatabaseBackup', 'DatabaseIntegrityCheck', 'IndexOptimize', 'CommandExecute') })
                    $olaInstalled  = $olaProcs.Count -eq 4
                    $splatCheck    = @{
                        CheckId        = "DC-7.9"
                        CheckName      = "Ola Hallengren Maintenance Solution Installed"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.9"]
                        Status         = if ($olaInstalled) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($olaInstalled) {
                            "All 4 Ola stored procedures present in master"
                        } else {
                            "Found $($olaProcs.Count)/4 procedures: $(if ($olaProcs) { $olaProcs.Name -join ', ' } else { 'none' })"
                        }
                        ExpectedValue  = "DatabaseBackup, DatabaseIntegrityCheck, IndexOptimize, CommandExecute installed in master"
                        Remediation    = "Install-DbaMaintenanceSolution -SqlInstance $instance -Database master -InstallJobs -LogToTable"
                        Reference      = "SQL Server Maintenance Best Practices — Ola's solution provides reliable, logged backup/integrity/index maintenance with robust error handling and history retention"
                        SqlQuery       = $sql["DC-7.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.9: $($_.Exception.Message)" }

                # DC-7.10 Database Mail Profile Configured
                try {
                    $mailProfiles = @(Get-DbaDbMailProfile @connSplat)
                    $mailAccounts = @(Get-DbaDbMailAccount @connSplat)
                    $splatCheck   = @{
                        CheckId        = "DC-7.10"
                        CheckName      = "Database Mail Profile Configured"
                        Category       = "SQL Agent"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-7.10"]
                        Status         = if ($mailProfiles.Count -gt 0 -and $mailAccounts.Count -gt 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($mailProfiles.Count -eq 0) {
                            "No Database Mail profiles defined"
                        } else {
                            "$($mailProfiles.Count) profile(s): $($mailProfiles.Name -join ', '); $($mailAccounts.Count) account(s)"
                        }
                        ExpectedValue  = "At least one Database Mail profile with an associated account configured"
                        Remediation    = "Configure Database Mail via SSMS > Management > Database Mail wizard, or use msdb stored procedures: sysmail_add_account_sp, sysmail_add_profile_sp, sysmail_add_profileaccount_sp."
                        Reference      = "SQL Server Agent Alerting — Database Mail is required for SQL Agent operator notifications; without it alert notifications fire but no one receives them"
                        SqlQuery       = $sql["DC-7.10"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-7.10: $($_.Exception.Message)" }
            }

            # ── §8 High Availability / HADR ──────────────────────────────────
            if (ShouldRun "8") {
                Write-Verbose "[$instance] §8 HADR"

                # Pre-fetch: HADR enabled state
                $hadrEnabled = $false
                try {
                    $hadrStatus  = Get-DbaAgHadr @connSplat -EnableException
                    $hadrEnabled = $hadrStatus.IsHadrEnabled
                } catch { Write-Warning "[$instance] Get-DbaAgHadr failed: $($_.Exception.Message)" }

                # Pre-fetch: AG list, replicas, AG databases, listeners (conditional on HADR state)
                $agList    = @()
                $replicas  = @()
                $agDbs     = @()
                $listeners = @()
                $hasAGs    = $false

                if ($hadrEnabled) {
                    try {
                        $agList = @(Get-DbaAvailabilityGroup @connSplat)
                        $hasAGs = $agList.Count -gt 0
                    } catch { Write-Warning "[$instance] Get-DbaAvailabilityGroup failed: $($_.Exception.Message)" }

                    if ($hasAGs) {
                        try { $replicas  = @(Get-DbaAgReplica  @connSplat) } catch { Write-Warning "[$instance] Get-DbaAgReplica failed: $($_.Exception.Message)"  }
                        try { $agDbs     = @(Get-DbaAgDatabase @connSplat) } catch { Write-Warning "[$instance] Get-DbaAgDatabase failed: $($_.Exception.Message)" }
                        try { $listeners = @(Get-DbaAgListener @connSplat) } catch { Write-Warning "[$instance] Get-DbaAgListener failed: $($_.Exception.Message)" }
                    }
                }

                # Shared skip reason for HA-2.x and HA-3.x checks
                $agSkipReason = if (-not $hadrEnabled) {
                    "HADR not enabled on this instance"
                } elseif (-not $hasAGs) {
                    "HADR enabled but no availability groups configured"
                } else { $null }

                # DC-8.1 Always On / HADR Enabled
                try {
                    $splatCheck = @{
                        CheckId        = "DC-8.1"
                        CheckName      = "Always On / HADR Enabled"
                        Category       = "HADR Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-8.1"]
                        Status         = if ($hadrEnabled) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($hadrEnabled) {
                            "Enabled — $($agList.Count) availability group(s) configured"
                        } else { "Not enabled — standalone instance with no AG protection" }
                        ExpectedValue  = "Enabled, or documented as intentionally standalone"
                        Remediation    = "Enable via SQL Server Configuration Manager or: Enable-DbaAgHadr -SqlInstance $instance -Force. Requires SQL Server service restart."
                        Reference      = "SQL Server HA Best Practices — HADR must be enabled before any AG can be created; standalone instances have no automatic failover capability"
                        SqlQuery       = $sql["DC-8.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.1: $($_.Exception.Message)" }

                # DC-8.2 Legacy Database Mirroring Not in Use
                try {
                    $mirroredDbs = @(Get-DbaDbMirror @connSplat)
                    $splatCheck  = @{
                        CheckId        = "DC-8.2"
                        CheckName      = "Legacy Database Mirroring Not in Use"
                        Category       = "HADR Config"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-8.2"]
                        Status         = if (-not $mirroredDbs) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($mirroredDbs) {
                            ($mirroredDbs | ForEach-Object { "$($_.Name): $($_.MirroringStatus)" }) -join "; "
                        } else { "No mirrored databases detected" }
                        ExpectedValue  = "No database mirroring — migrate to Always On Availability Groups"
                        Remediation    = "Migrate mirrored databases to an Always On AG. Mirroring was deprecated in SQL Server 2012 and removed in SQL Server 2022."
                        Reference      = "SQL Server Deprecation — database mirroring is removed in SQL Server 2022; migrate all versions to Always On AGs"
                        SqlQuery       = $sql["DC-8.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.2: $($_.Exception.Message)" }

                # DC-8.3 All AG Replicas Connected
                try {
                    if ($agSkipReason) {
                        $splatCheck = @{
                            CheckId        = "DC-8.3"
                            CheckName      = "All AG Replicas Connected"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.3"]
                            Status         = "Skip"
                            CurrentValue   = $agSkipReason
                            ExpectedValue  = "All replicas in Connected state"
                            Remediation    = "N/A"
                            Reference      = "SQL Server AG Health — a disconnected replica cannot receive log records and will diverge from primary"
                            SqlQuery       = $sql["DC-8.3"]
                        }
                    } else {
                        $disconnected = @($replicas | Where-Object { $_.ConnectionState -ne 'Connected' })
                        $splatCheck   = @{
                            CheckId        = "DC-8.3"
                            CheckName      = "All AG Replicas Connected"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.3"]
                            Status         = if ($disconnected) { "Fail" } else { "Pass" }
                            CurrentValue   = if ($disconnected) {
                                ($disconnected | ForEach-Object { "$($_.Name): $($_.ConnectionState)" }) -join "; "
                            } else { "All $($replicas.Count) replica(s) connected" }
                            ExpectedValue  = "All replicas in Connected state"
                            Remediation    = "Check network connectivity between replicas, verify the AG mirroring endpoint is online, and review the SQL Server error log on the disconnected replica."
                            Reference      = "SQL Server AG Health — a disconnected replica cannot receive log records and will diverge from primary until reconnected and resynchronized"
                            SqlQuery       = $sql["DC-8.3"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.3: $($_.Exception.Message)" }

                # DC-8.4 All AG Replicas Synchronized
                try {
                    if ($agSkipReason) {
                        $splatCheck = @{
                            CheckId        = "DC-8.4"
                            CheckName      = "All AG Replicas Synchronized"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.4"]
                            Status         = "Skip"
                            CurrentValue   = $agSkipReason
                            ExpectedValue  = "All replicas Synchronized or Synchronizing"
                            Remediation    = "N/A"
                            Reference      = "SQL Server AG Health — unsynchronized replicas increase data loss exposure and cannot participate in automatic failover"
                            SqlQuery       = $sql["DC-8.4"]
                        }
                    } else {
                        $notSynced  = @($replicas | Where-Object { $_.RollupSynchronizationState -eq 'NotSynchronizing' })
                        $syncing    = @($replicas | Where-Object { $_.RollupSynchronizationState -eq 'Synchronizing' })
                        $splatCheck = @{
                            CheckId        = "DC-8.4"
                            CheckName      = "All AG Replicas Synchronized"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.4"]
                            Status         = if ($notSynced) { "Fail" } elseif ($syncing) { "Warning" } else { "Pass" }
                            CurrentValue   = if ($notSynced) {
                                ($notSynced | ForEach-Object { "$($_.Name): $($_.RollupSynchronizationState)" }) -join "; "
                            } elseif ($syncing) {
                                ($syncing | ForEach-Object { "$($_.Name): $($_.RollupSynchronizationState)" }) -join "; "
                            } else { "All $($replicas.Count) replica(s) synchronized" }
                            ExpectedValue  = "All replicas Synchronized (synchronous) or Synchronizing (async in progress)"
                            Remediation    = "Review AG dashboard in SSMS. To resume suspended data movement: ALTER DATABASE [<db>] SET HADR RESUME;"
                            Reference      = "SQL Server AG Health — NotSynchronizing means data movement is suspended or the replica has diverged and requires manual intervention"
                            SqlQuery       = $sql["DC-8.4"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.4: $($_.Exception.Message)" }

                # DC-8.5 Automatic Failover Configured
                try {
                    if ($agSkipReason) {
                        $splatCheck = @{
                            CheckId        = "DC-8.5"
                            CheckName      = "Automatic Failover Configured"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.5"]
                            Status         = "Skip"
                            CurrentValue   = $agSkipReason
                            ExpectedValue  = "At least one replica pair configured for Automatic failover"
                            Remediation    = "N/A"
                            Reference      = "SQL Server AG Best Practices — without automatic failover a DBA must manually intervene during an outage"
                            SqlQuery       = $sql["DC-8.5"]
                        }
                    } else {
                        $autoReplicas = @($replicas | Where-Object { $_.FailoverMode -eq 'Automatic' })
                        $splatCheck   = @{
                            CheckId        = "DC-8.5"
                            CheckName      = "Automatic Failover Configured"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.5"]
                            Status         = if ($autoReplicas.Count -ge 2) { "Pass" } else { "Warning" }
                            CurrentValue   = if ($autoReplicas) {
                                "Automatic failover on: $($autoReplicas.Name -join ', ')"
                            } else { "All replicas set to Manual failover only" }
                            ExpectedValue  = "At least two replicas (primary + one secondary) configured for Automatic failover"
                            Remediation    = "ALTER AVAILABILITY GROUP [<ag>] MODIFY REPLICA ON '<secondary>' WITH (FAILOVER_MODE = AUTOMATIC, AVAILABILITY_MODE = SYNCHRONOUS_COMMIT);"
                            Reference      = "SQL Server AG Best Practices — automatic failover requires synchronous commit mode and allows SQL Server to fail over without DBA intervention"
                            SqlQuery       = $sql["DC-8.5"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.5: $($_.Exception.Message)" }

                # DC-8.6 AG Database Synchronization Lag
                try {
                    if ($agSkipReason) {
                        $splatCheck = @{
                            CheckId        = "DC-8.6"
                            CheckName      = "AG Database Synchronization Lag"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.6"]
                            Status         = "Skip"
                            CurrentValue   = $agSkipReason
                            ExpectedValue  = "All secondary databases lag < 30 seconds"
                            Remediation    = "N/A"
                            Reference      = "SQL Server AG Health — secondary lag represents potential data loss on unplanned failover; synchronous lag blocks primary commits"
                            SqlQuery       = $sql["DC-8.6"]
                        }
                    } else {
                        $lagData    = @($agDbs | Where-Object { $null -ne $_.SecondaryLagSeconds })
                        $critLag    = @($lagData | Where-Object { $_.SecondaryLagSeconds -gt 120 })
                        $warnLag    = @($lagData | Where-Object { $_.SecondaryLagSeconds -gt 30 -and $_.SecondaryLagSeconds -le 120 })
                        $maxLag     = if ($lagData) { ($lagData | Measure-Object -Property SecondaryLagSeconds -Maximum).Maximum } else { 0 }
                        $splatCheck = @{
                            CheckId        = "DC-8.6"
                            CheckName      = "AG Database Synchronization Lag"
                            Category       = "AG Health"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.6"]
                            Status         = if ($critLag) { "Fail" } elseif ($warnLag) { "Warning" } else { "Pass" }
                            CurrentValue   = if ($critLag) {
                                ($critLag | ForEach-Object { "$($_.DatabaseName) ($($_.AvailabilityGroupName)): $($_.SecondaryLagSeconds)s" }) -join "; "
                            } elseif ($warnLag) {
                                ($warnLag | ForEach-Object { "$($_.DatabaseName) ($($_.AvailabilityGroupName)): $($_.SecondaryLagSeconds)s" }) -join "; "
                            } else { "Max lag: ${maxLag}s across all secondary databases" }
                            ExpectedValue  = "All secondary databases < 30 seconds lag"
                            Remediation    = "Investigate network bandwidth between replicas, I/O throughput on the secondary, and redo thread performance. Review sys.dm_hadr_database_replica_states."
                            Reference      = "SQL Server AG Health — lag > 30s on synchronous replicas stalls primary commits; lag on async replicas directly sets the recovery point objective"
                            SqlQuery       = $sql["DC-8.6"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.6: $($_.Exception.Message)" }

                # DC-8.7 AG Listener Configured for Each AG
                try {
                    if ($agSkipReason) {
                        $splatCheck = @{
                            CheckId        = "DC-8.7"
                            CheckName      = "AG Listener Configured"
                            Category       = "AG Configuration"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.7"]
                            Status         = "Skip"
                            CurrentValue   = $agSkipReason
                            ExpectedValue  = "Each availability group has at least one listener"
                            Remediation    = "N/A"
                            Reference      = "SQL Server AG Best Practices — without a listener, clients must hard-code the primary replica name and update connection strings after every failover"
                            SqlQuery       = $sql["DC-8.7"]
                        }
                    } else {
                        $agNamesWithListeners = @($listeners | Select-Object -ExpandProperty AvailabilityGroupName -Unique)
                        $agsWithoutListeners  = @($agList | Where-Object { $_.Name -notin $agNamesWithListeners } | Select-Object -ExpandProperty Name)
                        $splatCheck           = @{
                            CheckId        = "DC-8.7"
                            CheckName      = "AG Listener Configured"
                            Category       = "AG Configuration"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-8.7"]
                            Status         = if ($agsWithoutListeners) { "Warning" } else { "Pass" }
                            CurrentValue   = if ($agsWithoutListeners) {
                                "AGs without listeners: $($agsWithoutListeners -join ', ')"
                            } else {
                                "$($listeners.Count) listener(s): $(($listeners | Select-Object -ExpandProperty Name) -join ', ')"
                            }
                            ExpectedValue  = "Each availability group has at least one listener configured"
                            Remediation    = "ALTER AVAILABILITY GROUP [<ag>] ADD LISTENER '<name>' (WITH IP (('<ip>','<mask>')), PORT = 1433);"
                            Reference      = "SQL Server AG Best Practices — listeners provide a stable, failover-transparent connection endpoint so clients do not need to track which replica is primary"
                            SqlQuery       = $sql["DC-8.7"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-8.7: $($_.Exception.Message)" }
            }

            # ── §9 Log Shipping ──────────────────────────────────────────────
            if (ShouldRun "9") {
                Write-Verbose "[$instance] §9 Log Shipping"

                # Pre-fetch: log shipping status (empty result = not configured)
                $lsAll        = @()
                $lsFetched    = $false
                try {
                    $lsAll     = @(Test-DbaDbLogShipStatus @connSplat -WarningAction SilentlyContinue)
                    $lsFetched = $true
                } catch { Write-Warning "[$instance] Test-DbaDbLogShipStatus failed: $($_.Exception.Message)" }
                $lsConfigured = $lsFetched -and $lsAll.Count -gt 0
                $lsPrimary    = @($lsAll | Where-Object { $_.InstanceType -eq 'Primary'   })
                $lsSecondary  = @($lsAll | Where-Object { $_.InstanceType -eq 'Secondary' })

                # DC-9.1 Log Shipping Configuration Detection
                try {
                    $lsDetail   = if ($lsConfigured) {
                        $parts = @()
                        if ($lsPrimary)   { $parts += "$($lsPrimary.Count) database(s) as Primary"   }
                        if ($lsSecondary) { $parts += "$($lsSecondary.Count) database(s) as Secondary" }
                        $parts -join "; "
                    } else { "Log shipping not configured on this instance" }
                    $splatCheck = @{
                        CheckId        = "DC-9.1"
                        CheckName      = "Log Shipping Configured"
                        Category       = "Log Shipping"
                        AssessmentType = "Automated"
                        Priority       = $priority["DC-9.1"]
                        Status         = "Pass"
                        CurrentValue   = $lsDetail
                        ExpectedValue  = "Informational — documents presence or absence of log shipping"
                        Remediation    = "N/A — informational check"
                        Reference      = "SQL Server Log Shipping — still used for read-only reporting copies and DR where Always On licensing is unavailable"
                        SqlQuery       = $sql["DC-9.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-9.1: $($_.Exception.Message)" }

                # DC-9.2 Log Shipping Backup Within Threshold
                try {
                    if (-not $lsConfigured -or -not $lsPrimary) {
                        $skipReason = if (-not $lsConfigured) { "Log shipping not configured" } else { "Not a log shipping primary" }
                        $splatCheck = @{
                            CheckId        = "DC-9.2"
                            CheckName      = "Log Shipping Backup Within Threshold"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.2"]
                            Status         = "Skip"
                            CurrentValue   = $skipReason
                            ExpectedValue  = "All primary databases backed up within configured threshold"
                            Remediation    = "N/A"
                            Reference      = "SQL Server Log Shipping Health — backup latency on the primary directly sets the recovery point objective for the secondary"
                            SqlQuery       = $sql["DC-9.2"]
                        }
                    } else {
                        $latePrimary = @($lsPrimary | Where-Object { $_.Status -notlike '*All OK*' })
                        $splatCheck  = @{
                            CheckId        = "DC-9.2"
                            CheckName      = "Log Shipping Backup Within Threshold"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.2"]
                            Status         = if ($latePrimary) { "Fail" } else { "Pass" }
                            CurrentValue   = if ($latePrimary) {
                                ($latePrimary | ForEach-Object { "$($_.Database): $($_.Status)" }) -join "; "
                            } else { "All $($lsPrimary.Count) primary database(s) within backup threshold" }
                            ExpectedValue  = "All primary databases backed up within their configured threshold"
                            Remediation    = "Check SQL Agent log shipping backup jobs for failures and verify disk space on the backup share."
                            Reference      = "SQL Server Log Shipping Health — each missed log backup increases the data gap between primary and secondary"
                            SqlQuery       = $sql["DC-9.2"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-9.2: $($_.Exception.Message)" }

                # DC-9.3 Log Shipping Restore Within Threshold
                try {
                    if (-not $lsConfigured -or -not $lsSecondary) {
                        $skipReason = if (-not $lsConfigured) { "Log shipping not configured" } else { "Not a log shipping secondary" }
                        $splatCheck = @{
                            CheckId        = "DC-9.3"
                            CheckName      = "Log Shipping Restore Within Threshold"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.3"]
                            Status         = "Skip"
                            CurrentValue   = $skipReason
                            ExpectedValue  = "All secondary databases restored within configured threshold"
                            Remediation    = "N/A"
                            Reference      = "SQL Server Log Shipping Health — restore latency on the secondary is the actual data gap (RPO) that would apply if the primary failed now"
                            SqlQuery       = $sql["DC-9.3"]
                        }
                    } else {
                        $lateSec    = @($lsSecondary | Where-Object { $_.Status -notlike '*All OK*' })
                        $splatCheck = @{
                            CheckId        = "DC-9.3"
                            CheckName      = "Log Shipping Restore Within Threshold"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.3"]
                            Status         = if ($lateSec) { "Fail" } else { "Pass" }
                            CurrentValue   = if ($lateSec) {
                                ($lateSec | ForEach-Object { "$($_.Database): $($_.Status)" }) -join "; "
                            } else { "All $($lsSecondary.Count) secondary database(s) within restore threshold" }
                            ExpectedValue  = "All secondary databases restored within their configured threshold"
                            Remediation    = "Check SQL Agent log shipping copy and restore jobs for failures and verify the log share is accessible from the secondary."
                            Reference      = "SQL Server Log Shipping Health — restore latency represents the actual RPO in effect; exceeding threshold means the secondary is farther behind than acceptable"
                            SqlQuery       = $sql["DC-9.3"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-9.3: $($_.Exception.Message)" }

                # DC-9.4 No Log Shipping Errors in Last 24 Hours
                try {
                    if (-not $lsConfigured) {
                        $splatCheck = @{
                            CheckId        = "DC-9.4"
                            CheckName      = "No Log Shipping Errors in Last 24 Hours"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.4"]
                            Status         = "Skip"
                            CurrentValue   = "Log shipping not configured"
                            ExpectedValue  = "No log shipping errors in last 24 hours"
                            Remediation    = "N/A"
                            Reference      = "SQL Server Log Shipping Health — error history captures backup, copy, and restore job failures with timestamps and messages"
                            SqlQuery       = $sql["DC-9.4"]
                        }
                    } else {
                        $splatLsErr = @{
                            SqlInstance  = $instance
                            DateTimeFrom = (Get-Date).AddHours(-24)
                        }
                        if ($SqlCredential) { $splatLsErr.SqlCredential = $SqlCredential }
                        $lsErrors   = @(Get-DbaDbLogShipError @splatLsErr)
                        $splatCheck = @{
                            CheckId        = "DC-9.4"
                            CheckName      = "No Log Shipping Errors in Last 24 Hours"
                            Category       = "Log Shipping"
                            AssessmentType = "Automated"
                            Priority       = $priority["DC-9.4"]
                            Status         = if ($lsErrors) { "Fail" } else { "Pass" }
                            CurrentValue   = if ($lsErrors) {
                                ($lsErrors | Group-Object Action | ForEach-Object { "$($_.Name): $($_.Count) error(s)" }) -join "; "
                            } else { "No log shipping errors in last 24 hours" }
                            ExpectedValue  = "No log shipping errors in last 24 hours"
                            Remediation    = "Review SQL Agent job history for log shipping backup, copy, and restore jobs. Use Get-DbaDbLogShipError for detailed messages."
                            Reference      = "SQL Server Log Shipping Health — persistent errors indicate configuration problems, network issues, or resource constraints building undetected"
                            SqlQuery       = $sql["DC-9.4"]
                        }
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-9.4: $($_.Exception.Message)" }
            }

            # ── §10 Operational Governance ──────────────────────────────────────
            if (ShouldRun "10") {
                Write-Verbose "[$instance] §10 Operational Governance"

                # DC-10.1 DR Runbook Documented and Current
                try {
                    $splatCheck = @{
                        CheckId        = "DC-10.1"
                        CheckName      = "DR Runbook Documented and Current"
                        Category       = "Governance"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-10.1"]
                        Status         = "Manual"
                        CurrentValue   = "Review required — runbook existence and currency cannot be verified automatically"
                        ExpectedValue  = "Documented DR runbook tested within the last 12 months, covering failover steps, restore procedures, RTO/RPO targets, and contact list"
                        Remediation    = "Create or update a DR runbook covering: failover steps, backup restore procedures, DBA contact list, RTO/RPO targets, and a validation checklist. Review and test annually."
                        Reference      = "SQL Server Operational Governance — an untested DR runbook provides false assurance; the first real outage should not be the first time the procedure is followed"
                        SqlQuery       = $sql["DC-10.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-10.1: $($_.Exception.Message)" }

                # DC-10.2 Application Connectivity Documented
                try {
                    $splatCheck = @{
                        CheckId        = "DC-10.2"
                        CheckName      = "Application Connectivity Documented"
                        Category       = "Governance"
                        AssessmentType = "Manual"
                        Priority       = $priority["DC-10.2"]
                        Status         = "Manual"
                        CurrentValue   = "Review required — application-to-database connections cannot be enumerated automatically"
                        ExpectedValue  = "Current documentation mapping each application to its databases, login(s), and connection string location"
                        Remediation    = "Document: application name, database(s) accessed, login used, connection string location, and application owner. Review when applications or logins change."
                        Reference      = "SQL Server Operational Governance — without a connection map, login changes and database moves carry unknown blast radius; outage triage is significantly slowed"
                        SqlQuery       = $sql["DC-10.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] DC-10.2: $($_.Exception.Message)" }
            }
        }
    }

    end {}
}
