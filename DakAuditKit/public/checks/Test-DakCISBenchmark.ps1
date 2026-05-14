function Test-DakCISBenchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against the CIS Microsoft SQL Server 2025 Benchmark.

    .DESCRIPTION
        Runs CIS Microsoft SQL Server 2025 Benchmark v1.0.0 checks. Returns one result
        object per check per instance (type: DakAuditKit.AuditResult).

        AssessmentType on each result indicates whether the tool made the determination:
            Automated — pass/fail determined by the tool
            Manual    — tool collected evidence; a human must determine compliance

        Manual results always have Compliant = $null. They include a Remediation note
        with the benchmark's audit procedure so the reviewer knows what to verify.

        Every result carries: RunDate, RunBy, SqlInstance, CheckId, CheckName,
        AssessmentType, Priority, Status, CurrentValue, ExpectedValue, Remediation, SqlQuery.

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        CIS sections to run: 1–8, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

    .PARAMETER OutputPath
        When specified, exports to a dated Excel workbook. Requires ImportExcel.

    .EXAMPLE
        Test-DakCISBenchmark -SqlInstance 'SQL-ENT-TEST\ENT'

    .EXAMPLE
        Test-DakCISBenchmark -SqlInstance 'SQL-ENT-TEST\ENT' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Test-DakCISBenchmark -SqlInstance 'SQL-ENT-TEST\ENT' | Where-Object AssessmentType -eq 'Manual'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("1", "2", "3", "4", "5", "6", "7", "8", "All")]
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

        $runAll  = $Section -contains "All"
        $runDate = Get-Date
        $runBy   = "$env:USERDOMAIN\$env:USERNAME"

        function ShouldRun ([string]$s) { $runAll -or $Section -contains $s }

        # Priority ratings: how critical each check is when it fails.
        $cisPriority = @{
            "1.1"  = "High"    # Running behind on patches is a known exploitation vector
            "1.2"  = "Low"     # Architectural — informational
            "2.1"  = "Low"     # Ad Hoc Distributed Queries — low risk in most environments
            "2.2"  = "Medium"  # CLR — needed for some applications (e.g. GP Nodus)
            "2.3"  = "Low"     # Cross DB ownership chaining
            "2.4"  = "Medium"  # Database Mail XPs — surface area
            "2.5"  = "Low"     # OLE Automation
            "2.6"  = "Medium"  # Remote Access
            "2.7"  = "Medium"  # Remote Admin Connections
            "2.8"  = "Medium"  # Scan for Startup Procedures
            "2.9"  = "Medium"  # Trustworthy databases
            "2.10" = "Medium"  # Unnecessary protocols — fail if Named Pipes/VIA/other non-standard enabled
            "2.11" = "Low"     # Non-standard TCP port
            "2.12" = "Low"     # Hide instance
            "2.13" = "High"    # sa login enabled is a direct attack target
            "2.14" = "Medium"  # sa login not renamed
            "2.15" = "Low"     # AUTO_CLOSE on contained DBs
            "2.16" = "Medium"  # Login named sa still exists
            "2.17" = "Medium"  # CLR strict security
            "3.1"  = "High"    # Mixed mode auth — SQL logins can bypass AD controls
            "3.2"  = "Low"     # Guest CONNECT
            "3.3"  = "Medium"  # Orphaned users — attack surface in each DB
            "3.4"  = "Low"     # SQL auth in contained DBs
            "3.5"  = "High"    # MSSQL engine service account privilege escalation risk
            "3.6"  = "High"    # SQLAgent service account privilege escalation risk
            "3.7"  = "Low"     # Full-text service account
            "3.8"  = "Low"     # Public server role permissions
            "3.9"  = "High"    # BUILTIN groups — uncontrolled local admin access
            "3.10" = "Low"     # Local Windows groups
            "3.11" = "Low"     # Agent proxy public access
            "3.12" = "High"    # Excess sysadmin members — privilege escalation
            "3.13" = "Low"     # msdb admin role members
            "3.14" = "Medium"  # CONTROL SERVER permission
            "3.15" = "Low"     # sp_invoke_external_rest_endpoint access
            "4.1"  = "Medium"  # MUST_CHANGE logins
            "4.2"  = "High"    # Sysadmin logins without CHECK_EXPIRATION
            "4.3"  = "High"    # SQL logins without CHECK_POLICY
            "5.1"  = "Low"     # Error log count retention
            "5.2"  = "Low"     # Default trace enabled
            "5.3"  = "Medium"  # Login audit level — failure detection
            "5.4"  = "High"    # SQL Server Audit — SOX/compliance requirement
            "6.1"  = "Medium"  # Input sanitization — SQL injection risk
            "6.2"  = "High"    # UNSAFE CLR assemblies — code execution risk
            "7.1"  = "Low"     # Symmetric key algorithms (Level 1)
            "7.2"  = "Low"     # Asymmetric key size (Level 1)
            "7.3"  = "Medium"  # Backup encryption (Level 2)
            "7.4"  = "Medium"  # Network encryption (Level 2)
            "7.5"  = "Low"     # TDE (Level 2)
            "8.1"  = "Low"     # SQL Browser service
        }

        # T-SQL equivalents for every Automated check.
        # Manual checks note that the audit requires out-of-band verification.
        $sql = @{
            "1.1"  = "SELECT SERVERPROPERTY('ProductVersion') AS Build, SERVERPROPERTY('ProductLevel') AS SPLevel, SERVERPROPERTY('ProductUpdateLevel') AS CULevel, SERVERPROPERTY('Edition') AS Edition;"
            "1.2"  = "-- Manual check. Verify via OS/infrastructure review that no other server roles (IIS, file server, etc.) are installed on the SQL Server host."
            "2.1"  = "SELECT name, value_in_use AS RunningValue, value AS ConfiguredValue FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
            "2.2"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'clr enabled';"
            "2.3"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'cross db ownership chaining';"
            "2.4"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Database Mail XPs';"
            "2.5"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
            "2.6"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'remote access';"
            "2.7"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;  -- Not applicable on clustered instances."
            "2.8"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'scan for startup procs';"
            "2.9"  = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';"
            "2.10" = "-- Automated via Get-DbaInstanceProtocol. No T-SQL equivalent; protocol state is read from WMI (root\Microsoft\SQLServer)."
            "2.11" = "IF (SELECT value_data FROM sys.dm_server_registry WHERE value_name = 'ListenOnAllIPs') = 1 SELECT COUNT(*) AS PortCount FROM sys.dm_server_registry WHERE registry_key LIKE '%IPAll%' AND value_name LIKE '%Tcp%' AND value_data = '1433'; ELSE SELECT COUNT(*) AS PortCount FROM sys.dm_server_registry WHERE value_name LIKE '%Tcp%' AND value_data = '1433';  -- 0 = compliant"
            "2.12" = "DECLARE @v INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib', N'HideInstance', @v OUTPUT; SELECT @v AS HideInstance;  -- 1 = hidden (compliant)"
            "2.13" = "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;  -- No rows = compliant"
            "2.14" = "SELECT name FROM sys.server_principals WHERE sid = 0x01;  -- Name should not be 'sa'"
            "2.15" = "SELECT name, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 AND is_auto_close_on = 1;  -- No rows = compliant (contained databases only)"
            "2.16" = "SELECT principal_id, name FROM sys.server_principals WHERE name = 'sa';  -- No rows = compliant"
            "2.17" = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'clr strict security';"
            "3.1"  = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = Windows only (compliant)"
            "3.2"  = "-- Run per user database (exclude master, msdb, tempdb):`nSELECT DB_NAME() AS DatabaseName, permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
            "3.3"  = "-- Run per database:`nSELECT dp.name AS OrphanedUser FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE dp.type IN ('S','U','G') AND dp.principal_id > 4 AND sp.sid IS NULL AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys','MS_DataCollectorInternalUser') AND NOT (dp.name = 'cdc' AND (SELECT is_cdc_enabled FROM sys.databases WHERE name = DB_NAME()) = 1);"
            "3.4"  = "-- Run per contained database:`nSELECT name AS DBUser FROM sys.database_principals WHERE name NOT IN ('dbo','Information_Schema','sys','guest') AND type IN ('U','S','G') AND authentication_type = 2;"
            "3.5"  = "-- Automated via Get-DbaService (WMI) + Get-LocalGroupMember. T-SQL reference: SELECT servicename, service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%';"
            "3.6"  = "-- Automated via Get-DbaService (WMI) + Get-LocalGroupMember. T-SQL reference: SELECT servicename, service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server Agent (%';"
            "3.7"  = "SELECT servicename, service_account FROM sys.dm_server_services WHERE servicename LIKE '%FDLauncher%' AND service_account IN ('NT AUTHORITY\SYSTEM','LocalSystem','NT AUTHORITY\LocalSystem');"
            "3.8"  = "SELECT permission_name, state_desc, class_desc FROM sys.server_permissions WHERE grantee_principal_id = SUSER_SID(N'public') AND state_desc LIKE 'GRANT%' AND NOT (permission_name = 'VIEW ANY DATABASE' AND class_desc = 'SERVER') AND NOT (permission_name = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id IN (2,3,4,5));"
            "3.9"  = "SELECT pr.name, pe.permission_name, pe.state_desc FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name LIKE 'BUILTIN%';"
            "3.10" = "SELECT pr.name AS LocalGroupName, pe.permission_name, pe.state_desc FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.type_desc = 'WINDOWS_GROUP' AND pr.name LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';"
            "3.11" = "USE msdb; SELECT sp.name AS ProxyName FROM dbo.sysproxylogin spl JOIN sys.database_principals dp ON dp.sid = spl.sid JOIN sysproxies sp ON sp.proxy_id = spl.proxy_id WHERE principal_id = USER_ID('public');"
            "3.12" = "-- Manual check. List all sysadmin members and verify each is a legitimate administrative or built-in account:`nSELECT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT IN ('NT SERVICE\SQLWriter','NT SERVICE\Winmgmt','NT SERVICE\MSSQLSERVER','NT SERVICE\SQLSERVERAGENT');"
            "3.13" = "USE msdb; SELECT r.name AS RoleName, m.name AS MemberName FROM sys.database_role_members drm JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE r.name IN ('db_owner','db_securityadmin','db_ddladmin','db_datawriter') AND m.name <> 'dbo';"
            "3.14" = "SELECT sys.server_permissions.permission_name, sys.server_permissions.state_desc, grantee.name AS GranteeName, grantee.type_desc AS GranteeType FROM sys.server_principals AS grantee INNER JOIN sys.server_permissions ON sys.server_permissions.grantee_principal_id = grantee.principal_id INNER JOIN sys.server_principals AS grantor ON grantor.principal_id = sys.server_permissions.grantor_principal_id WHERE sys.server_permissions.permission_name = 'CONTROL SERVER' AND grantee.name <> '##MS_PolicySigningCertificate##';"
            "3.15" = "-- Run per database:`nSELECT dp.name AS PrincipalName, dp.type_desc, perm.permission_name, perm.state_desc FROM sys.database_permissions perm JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id WHERE perm.major_id = OBJECT_ID('sys.sp_invoke_external_rest_endpoint') AND perm.permission_name = 'EXECUTE';"
            "4.1"  = "-- Manual check. Review logins with MUST_CHANGE set; verify each represents a legitimate new account awaiting first login:`nSELECT name, CAST(LOGINPROPERTY(name, 'IsMustChange') AS bit) AS IsMustChange FROM sys.server_principals WHERE type = 'S' AND CAST(LOGINPROPERTY(name, 'IsMustChange') AS bit) = 1;"
            "4.2"  = "SELECT l.name, 'sysadmin membership' AS Access_Method FROM sys.sql_logins AS l WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND l.is_expiration_checked <> 1 AND l.is_disabled = 0 UNION ALL SELECT l.name, 'CONTROL SERVER' FROM sys.sql_logins AS l JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id WHERE p.type = 'CL' AND p.state IN ('G','W') AND l.is_expiration_checked <> 1 AND l.is_disabled = 0;"
            "4.3"  = "SELECT name, is_disabled FROM sys.sql_logins WHERE is_policy_checked = 0;"
            "5.1"  = "DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, -1) AS NumberOfLogFiles;  -- Compliant if >= 12 or -1 (no limit configured)"
            "5.2"  = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'default trace enabled';"
            "5.3"  = "EXEC xp_loginconfig 'audit level';  -- Compliant if config_value is 'failure' or 'all'"
            "5.4"  = "SELECT S.name AS AuditName, CASE S.is_state_enabled WHEN 1 THEN 'Y' ELSE 'N' END AS AuditEnabled, SA.name AS SpecName, CASE SA.is_state_enabled WHEN 1 THEN 'Y' ELSE 'N' END AS SpecEnabled, SAD.audit_action_name, SAD.audited_result FROM sys.server_audit_specification_details AS SAD JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid WHERE SAD.audit_action_id IN ('CNAU','LGFL','LGSD','ADDP','ADSP','OPSV') OR (SAD.audit_action_id IN ('DAGS','DAGF') AND (SELECT COUNT(*) FROM sys.databases WHERE containment = 1) > 0);"
            "6.1"  = "-- Manual check. Review application code and database stored procedures for dynamic SQL concatenation. Verify all external input is parameterized or validated before use."
            "6.2"  = "-- Run per user database:`nSELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1 AND permission_set_desc NOT IN ('SAFE_ACCESS') AND name <> 'Microsoft.SqlServer.Types';"
            "7.1"  = "-- Run per user database:`nSELECT DB_NAME() AS DatabaseName, name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND DB_ID() > 4;"
            "7.2"  = "-- Run per user database:`nSELECT DB_NAME() AS DatabaseName, name, key_length FROM sys.asymmetric_keys WHERE key_length < 2048 AND DB_ID() > 4;"
            "7.3"  = "SELECT b.key_algorithm, b.encryptor_type, d.is_encrypted, b.database_name, b.backup_finish_date FROM msdb.dbo.backupset b INNER JOIN sys.databases d ON b.database_name = d.name WHERE b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted = 0;  -- No rows = compliant (Level 2)"
            "7.4"  = "SELECT DISTINCT encrypt_option FROM sys.dm_exec_connections c WHERE net_transport <> 'Shared memory' AND c.endpoint_id NOT IN (SELECT endpoint_id FROM sys.database_mirroring_endpoints WHERE encryption_algorithm IS NOT NULL);  -- TRUE = compliant (Level 2)"
            "7.5"  = "SELECT database_id, name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted != 1;  -- No rows = compliant (Level 2)"
            "8.1"  = "-- Manual check. Evaluate whether Browser service should be enabled based on environment: disable for default instances and app-only named instances; enable for named instances where end users connect interactively."
        }
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) { Write-Host "CIS Benchmark — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] CIS 2025 benchmark — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "CIS"
                RunDate      = $runDate
                RunBy        = $runBy
            }

            $emit = {
                param ([PSCustomObject]$r)
                $color = switch ($r.Status) {
                    "Pass"    { "Green"  }
                    "Fail"    { "Red"    }
                    "Warning" { "Yellow" }
                    "Manual"  { "Cyan"   }
                    default   { "Gray"   }
                }
                if (-not $Quiet) { Write-Host ("  [{0,-4}] {1,-52} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Manual", "Error") {
                    $r
                }
            }

            # ── §1 Installation & Patches ──────────────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Patches"

                # 1.1 Patch Level — CIS labels this Manual but Test-DbaBuild automates it.
                try {
                    $build = Test-DbaBuild @connSplat -Latest -Update -WarningAction SilentlyContinue | Select-Object -First 1
                    $splatCheck = @{
                        CheckId        = "1.1"
                        CheckName      = "Latest Patch Level"
                        Category       = "Installation"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["1.1"]
                        Status         = if ($build.Compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = $build.BuildLevel.ToString()
                        ExpectedValue  = $build.BuildTarget.ToString()
                        Remediation    = "Apply the latest SQL Server CU: $($build.CUTarget)"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §1.1"
                        SqlQuery       = $sql["1.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 1.1: $($_.Exception.Message)" }

                # 1.2 Single-Function Member Servers — purely architectural, no T-SQL audit.
                $splatCheck = @{
                    CheckId        = "1.2"
                    CheckName      = "Single-Function Member Server"
                    Category       = "Installation"
                    AssessmentType = "Manual"
                    Priority       = $cisPriority["1.2"]
                    Status         = "Manual"
                    CurrentValue   = "Cannot be determined from SQL Server"
                    ExpectedValue  = "SQL Server installed on a dedicated host with no other server roles"
                    Remediation    = "Audit the host OS: verify no additional Windows Server roles (IIS, File Server, etc.) are installed alongside SQL Server. Uninstall excess roles if found."
                    Reference      = "CIS SQL Server 2025 v1.0.0 §1.2"
                    SqlQuery       = $sql["1.2"]
                }
                & $emit (New-DakCheckResult @sharedParams @splatCheck)
            }

            # ── §2 Surface Area Reduction ──────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Surface Area"

                $configMap = [ordered]@{
                    AdHocDistributedQueriesEnabled = @{ CheckId="2.1";  Priority=$cisPriority["2.1"];  CheckName="Ad Hoc Distributed Queries";   Expected=0; Fix="EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;";         Ref="CIS SQL Server 2025 v1.0.0 §2.1"  }
                    IsSqlClrEnabled                = @{ CheckId="2.2";  Priority=$cisPriority["2.2"];  CheckName="CLR Integration";              Expected=0; Fix="EXEC sp_configure 'clr enabled', 0; RECONFIGURE;";                         Ref="CIS SQL Server 2025 v1.0.0 §2.2"  }
                    CrossDBOwnershipChaining       = @{ CheckId="2.3";  Priority=$cisPriority["2.3"];  CheckName="Cross DB Ownership Chaining";  Expected=0; Fix="EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;";         Ref="CIS SQL Server 2025 v1.0.0 §2.3"  }
                    DatabaseMailEnabled            = @{ CheckId="2.4";  Priority=$cisPriority["2.4"];  CheckName="Database Mail XPs";            Expected=0; Fix="EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;";                   Ref="CIS SQL Server 2025 v1.0.0 §2.4"  }
                    OleAutomationProceduresEnabled = @{ CheckId="2.5";  Priority=$cisPriority["2.5"];  CheckName="OLE Automation Procedures";    Expected=0; Fix="EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;";           Ref="CIS SQL Server 2025 v1.0.0 §2.5"  }
                    RemoteAccess                   = @{ CheckId="2.6";  Priority=$cisPriority["2.6"];  CheckName="Remote Access";                Expected=0; Fix="EXEC sp_configure 'remote access', 0; RECONFIGURE WITH OVERRIDE;";         Ref="CIS SQL Server 2025 v1.0.0 §2.6"  }
                    RemoteDacConnectionsEnabled    = @{ CheckId="2.7";  Priority=$cisPriority["2.7"];  CheckName="Remote Admin Connections";     Expected=0; Fix="EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;  -- Not applicable on clustered instances."; Ref="CIS SQL Server 2025 v1.0.0 §2.7" }
                    ScanForStartupProcedures       = @{ CheckId="2.8";  Priority=$cisPriority["2.8"];  CheckName="Scan for Startup Procedures";  Expected=0; Fix="EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE;  -- Note: replication requires this enabled."; Ref="CIS SQL Server 2025 v1.0.0 §2.8" }
                }

                try {
                    $allCfg = Get-DbaSpConfigure @connSplat -WarningAction SilentlyContinue
                    foreach ($cfgName in $configMap.Keys) {
                        $m   = $configMap[$cfgName]
                        $row = $allCfg | Where-Object Name -eq $cfgName
                        if ($row) {
                            $splatCheck = @{
                                CheckId        = $m.CheckId
                                CheckName      = $m.CheckName
                                Category       = "Surface Area"
                                AssessmentType = "Automated"
                                Priority       = $m.Priority
                                Status         = if ($row.RunningValue -eq $m.Expected) { "Pass" } else { "Fail" }
                                CurrentValue   = $row.RunningValue.ToString()
                                ExpectedValue  = $m.Expected.ToString()
                                Remediation    = $m.Fix
                                Reference      = $m.Ref
                                SqlQuery       = $sql[$m.CheckId]
                            }
                            & $emit (New-DakCheckResult @sharedParams @splatCheck)
                        }
                    }
                } catch { Write-Warning "[$instance] §2 sp_configure: $($_.Exception.Message)" }

                # 2.9 Trustworthy
                try {
                    $trustDbs = Get-DbaDatabase @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -ne "msdb" -and $_.Trustworthy -eq $true }
                    $count = if ($trustDbs) { @($trustDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "2.9"
                        CheckName      = "Trustworthy Databases"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["2.9"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($trustDbs.Name -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "ALTER DATABASE [dbname] SET TRUSTWORTHY OFF;"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §2.9"
                        SqlQuery       = $sql["2.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.9: $($_.Exception.Message)" }

                # 2.10 Protocols — Automated: Fail if anything other than Shared Memory or TCP/IP is enabled.
                try {
                    $protocols = Get-DbaInstanceProtocol -ComputerName $computerName -WarningAction SilentlyContinue
                    if ($protocols) {
                        $allowed    = @("Shared Memory", "TCP/IP")
                        $unexpected = @($protocols | Where-Object { $_.IsEnabled -and $_.DisplayName -notin $allowed })
                        $summary    = ($protocols | ForEach-Object {
                            "$($_.DisplayName): $(if ($_.IsEnabled) { "Enabled" } else { "Disabled" })"
                        }) -join "; "
                        $splatCheck = @{
                            CheckId        = "2.10"
                            CheckName      = "Unnecessary SQL Server Protocols"
                            Category       = "Surface Area"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["2.10"]
                            Status         = if ($unexpected.Count -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $summary
                            ExpectedValue  = "Only Shared Memory and TCP/IP enabled"
                            Remediation    = "In SQL Server Configuration Manager > SQL Server Network Configuration, disable Named Pipes, VIA, and any other non-required protocol. Restart the SQL Server service after changes."
                            Reference      = "CIS SQL Server 2025 v1.0.0 §2.10"
                            SqlQuery       = $sql["2.10"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.10: $($_.Exception.Message)" }

                # 2.11 TCP Port — use sys.dm_server_registry (CIS 2025 audit query).
                try {
                    $portQuery = @"
IF (SELECT value_data FROM sys.dm_server_registry WHERE value_name = 'ListenOnAllIPs') = 1
    SELECT COUNT(*) AS PortCount FROM sys.dm_server_registry
    WHERE registry_key LIKE '%IPAll%' AND value_name LIKE '%Tcp%' AND value_data = '1433'
ELSE
    SELECT COUNT(*) AS PortCount FROM sys.dm_server_registry
    WHERE value_name LIKE '%Tcp%' AND value_data = '1433';
"@
                    $portResult = Invoke-DbaQuery @connSplat -Query $portQuery -WarningAction SilentlyContinue
                    $portCount  = if ($portResult) { $portResult.PortCount } else { 0 }
                    $splatCheck = @{
                        CheckId        = "2.11"
                        CheckName      = "Non-Standard TCP Port"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["2.11"]
                        Status         = if ($portCount -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($portCount -eq 0) { "Non-default port configured" } else { "Port 1433 in use" }
                        ExpectedValue  = "0 (no instances of port 1433)"
                        Remediation    = "Change the SQL Server TCP port in SQL Server Configuration Manager > SQL Server Network Configuration > TCP/IP > IP Addresses > IPAll > TCP Port."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §2.11"
                        SqlQuery       = $sql["2.11"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.11: $($_.Exception.Message)" }

                # 2.12 Hide Instance
                try {
                    $hide = Get-DbaHideInstance @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($hide) {
                        $splatCheck = @{
                            CheckId        = "2.12"
                            CheckName      = "Hide Instance"
                            Category       = "Surface Area"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["2.12"]
                            Status         = if ($hide.HideInstance) { "Pass" } else { "Fail" }
                            CurrentValue   = if ($hide.HideInstance) { "Hidden" } else { "Visible" }
                            ExpectedValue  = "Hidden"
                            Remediation    = "Enable HideInstance in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties > Flags tab."
                            Reference      = "CIS SQL Server 2025 v1.0.0 §2.12"
                            SqlQuery       = $sql["2.12"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.12: $($_.Exception.Message)" }

                # 2.13 sa Disabled (check by SID 0x01 so rename is also caught)
                try {
                    $saDisabled = Invoke-DbaQuery @connSplat -Query "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;" -WarningAction SilentlyContinue
                    $enabled    = $saDisabled -and @($saDisabled).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "2.13"
                        CheckName      = "sa Login Disabled"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["2.13"]
                        Status         = if (-not $enabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($enabled) { "Enabled (name: $($saDisabled.name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "USE [master]; DECLARE @tsql nvarchar(max); SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'; EXEC (@tsql);"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §2.13"
                        SqlQuery       = $sql["2.13"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.13: $($_.Exception.Message)" }

                # 2.14 sa Renamed
                try {
                    $saName = Invoke-DbaQuery @connSplat -Query "SELECT name FROM sys.server_principals WHERE sid = 0x01;" -WarningAction SilentlyContinue
                    if ($saName) {
                        $splatCheck = @{
                            CheckId        = "2.14"
                            CheckName      = "sa Login Renamed"
                            Category       = "Surface Area"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["2.14"]
                            Status         = if ($saName.name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saName.name
                            ExpectedValue  = "Not sa"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "CIS SQL Server 2025 v1.0.0 §2.14"
                            SqlQuery       = $sql["2.14"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.14: $($_.Exception.Message)" }

                # 2.15 AUTO_CLOSE — CIS 2025 scopes this to contained databases only.
                try {
                    $acQuery = "SELECT name, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 AND is_auto_close_on = 1;"
                    $acDbs   = Invoke-DbaQuery @connSplat -Query $acQuery -WarningAction SilentlyContinue
                    $count   = if ($acDbs) { @($acDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "2.15"
                        CheckName      = "AUTO_CLOSE on Contained Databases"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["2.15"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($acDbs.name -join ", ") }
                        ExpectedValue  = "None (contained databases only)"
                        Remediation    = "ALTER DATABASE [dbname] SET AUTO_CLOSE OFF;"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §2.15"
                        SqlQuery       = $sql["2.15"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.15: $($_.Exception.Message)" }

                # 2.16 No login named 'sa'
                try {
                    $saExists = Invoke-DbaQuery @connSplat -Query "SELECT principal_id, name FROM sys.server_principals WHERE name = 'sa';" -WarningAction SilentlyContinue
                    $exists   = $saExists -and @($saExists).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "2.16"
                        CheckName      = "No Login Named 'sa'"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["2.16"]
                        Status         = if (-not $exists) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($exists) { "Login named sa exists" } else { "Not present" }
                        ExpectedValue  = "No login named sa"
                        Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];  -- Rename the sa login to a non-obvious name."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §2.16"
                        SqlQuery       = $sql["2.16"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.16: $($_.Exception.Message)" }

                # 2.17 CLR Strict Security
                try {
                    $allCfg217 = Get-DbaSpConfigure @connSplat -Name ClrStrictSecurity -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($allCfg217) {
                        $splatCheck = @{
                            CheckId        = "2.17"
                            CheckName      = "CLR Strict Security"
                            Category       = "Surface Area"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["2.17"]
                            Status         = if ($allCfg217.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $allCfg217.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'clr strict security', 1; RECONFIGURE;"
                            Reference      = "CIS SQL Server 2025 v1.0.0 §2.17"
                            SqlQuery       = $sql["2.17"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.17: $($_.Exception.Message)" }
            }

            # ── §3 Authentication & Authorization ──────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 Authentication"

                # 3.1 Auth Mode
                try {
                    $authMode = Get-DbaInstanceProperty @connSplat -InstanceProperty LoginMode -WarningAction SilentlyContinue | Select-Object -First 1
                    $winOnly  = ($authMode.Value -eq 1)
                    $splatCheck = @{
                        CheckId        = "3.1"
                        CheckName      = "Windows Authentication Mode"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.1"]
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- Restart required."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.1"
                        SqlQuery       = $sql["3.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.1: $($_.Exception.Message)" }

                # 3.2 Guest CONNECT
                try {
                    $guestDbs = Get-DbaDbUser @connSplat -ExcludeDatabase master, msdb, tempdb -User "guest" -WarningAction SilentlyContinue |
                        Where-Object { $_.HasDbAccess -eq $true }
                    $count = if ($guestDbs) { @($guestDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.2"
                        CheckName      = "Guest CONNECT Permission"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($guestDbs.Database -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "USE [dbname]; REVOKE CONNECT FROM guest;"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.2"
                        SqlQuery       = $sql["3.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.2: $($_.Exception.Message)" }

                # 3.3 Orphaned Users
                try {
                    $orphans = Get-DbaDbOrphanUser @connSplat -WarningAction SilentlyContinue
                    $count   = if ($orphans) { @($orphans).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.3"
                        CheckName      = "Orphaned Database Users"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count orphaned" }
                        ExpectedValue  = "None"
                        Remediation    = "Repair-DbaDbOrphanUser -SqlInstance $instance  -- or: USE [db]; DROP USER [name];"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.3"
                        SqlQuery       = $sql["3.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.3: $($_.Exception.Message)" }

                # 3.4 Contained DB SQL Auth
                try {
                    $containedDbs = Get-DbaDatabase @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.ContainmentType -ne "None" }
                    if ($containedDbs) {
                        $sqlUsers = foreach ($db in $containedDbs) {
                            Get-DbaDbUser @connSplat -Database $db.Name -WarningAction SilentlyContinue |
                                Where-Object { $_.AuthenticationType -eq "Database" }
                        }
                        $count = if ($sqlUsers) { @($sqlUsers).Count } else { 0 }
                        $splatCheck = @{
                            CheckId        = "3.4"
                            CheckName      = "SQL Auth in Contained Databases"
                            Category       = "Authentication"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["3.4"]
                            Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = if ($count -eq 0) { "None" } else { "$count users" }
                            ExpectedValue  = "None"
                            Remediation    = "Use Windows-authenticated users in contained databases instead of SQL-authenticated users."
                            Reference      = "CIS SQL Server 2025 v1.0.0 §3.4"
                            SqlQuery       = $sql["3.4"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    } else {
                        $splatCheck = @{
                            CheckId        = "3.4"
                            CheckName      = "SQL Auth in Contained Databases"
                            Category       = "Authentication"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["3.4"]
                            Status         = "Pass"
                            CurrentValue   = "No contained databases"
                            ExpectedValue  = "N/A"
                            Reference      = "CIS SQL Server 2025 v1.0.0 §3.4"
                            SqlQuery       = $sql["3.4"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 3.4: $($_.Exception.Message)" }

                # 3.5 MSSQL Engine / 3.6 SQL Agent — Automated: fail if LocalSystem or member of local Administrators.
                $svcInstanceName = if ($instance -match "\\") { ($instance -split "\\")[1] -split "," | Select-Object -First 1 } else { "MSSQLSERVER" }
                try {
                    $localAdmins = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
                    } -ErrorAction SilentlyContinue

                    foreach ($sc in @(
                        @{ Id = "3.5"; Type = "Engine"; Name = "MSSQL Engine Service Account" }
                        @{ Id = "3.6"; Type = "Agent";  Name = "SQLAgent Service Account"      }
                    )) {
                        try {
                            $splatSvc = @{
                                ComputerName  = $computerName
                                Type          = $sc.Type
                                WarningAction = "SilentlyContinue"
                            }
                            $svc = Get-DbaService @splatSvc |
                                Where-Object { $_.InstanceName -eq $svcInstanceName } |
                                Select-Object -First 1
                            if ($svc) {
                                $account    = $svc.StartName
                                $isLocalSys = $account -in ("NT AUTHORITY\SYSTEM", "LocalSystem", "NT AUTHORITY\LocalSystem")
                                $inAdmins   = $null -ne $localAdmins -and ($localAdmins -contains $account)
                                $canAuto    = $null -ne $localAdmins
                                $splatCheck = @{
                                    CheckId        = $sc.Id
                                    CheckName      = $sc.Name
                                    Category       = "Authentication"
                                    AssessmentType = if ($canAuto) { "Automated" } else { "Manual" }
                                    Priority       = $cisPriority[$sc.Id]
                                    Status         = if ($isLocalSys -or $inAdmins) { "Fail" } elseif ($canAuto) { "Pass" } else { "Manual" }
                                    CurrentValue   = $account
                                    ExpectedValue  = "Dedicated low-privilege service account; not a member of local Administrators"
                                    Remediation    = if ($isLocalSys) {
                                        "Use SQL Server Configuration Manager to change to a dedicated low-privilege service account."
                                    } elseif ($inAdmins) {
                                        "Remove $account from the local Administrators group and reassign via SQL Server Configuration Manager."
                                    } else {
                                        "Verify $account is not a member of the local Administrators group."
                                    }
                                    Reference      = "CIS SQL Server 2025 v1.0.0 §$($sc.Id)"
                                    SqlQuery       = $sql[$sc.Id]
                                }
                                & $emit (New-DakCheckResult @sharedParams @splatCheck)
                            }
                        } catch { Write-Warning "[$instance] $($sc.Id): $($_.Exception.Message)" }
                    }
                } catch { Write-Warning "[$instance] 3.5-3.6 service account check: $($_.Exception.Message)" }

                # 3.7 Full-Text Service Account — Manual; T-SQL only detects LocalSystem; admin membership requires manual review.
                try {
                    $svcQuery37 = "SELECT servicename, service_account FROM sys.dm_server_services WHERE servicename LIKE '%FDLauncher%';"
                    $svcRows37  = Invoke-DbaQuery @connSplat -Query $svcQuery37 -WarningAction SilentlyContinue
                    if ($svcRows37) {
                        foreach ($row in @($svcRows37)) {
                            $isLocalSystem = $row.service_account -in ("NT AUTHORITY\SYSTEM", "LocalSystem", "NT AUTHORITY\LocalSystem")
                            $splatCheck = @{
                                CheckId        = "3.7"
                                CheckName      = "Full-Text Service Account"
                                Category       = "Authentication"
                                AssessmentType = "Manual"
                                Priority       = $cisPriority["3.7"]
                                Status         = if ($isLocalSystem) { "Fail" } else { "Manual" }
                                CurrentValue   = $row.service_account
                                ExpectedValue  = "Dedicated low-privilege service account; not a member of Administrators"
                                Remediation    = if ($isLocalSystem) {
                                    "Use SQL Server Configuration Manager to change to a dedicated low-privilege service account."
                                } else {
                                    "Verify that $($row.service_account) is not a member of the local Administrators group or any privileged AD group."
                                }
                                Reference      = "CIS SQL Server 2025 v1.0.0 §3.7"
                                SqlQuery       = $sql["3.7"]
                            }
                            & $emit (New-DakCheckResult @sharedParams @splatCheck)
                        }
                    }
                } catch { Write-Warning "[$instance] 3.7: $($_.Exception.Message)" }

                # 3.8 Public Server Role Permissions
                try {
                    $q3_8  = "SELECT COUNT(*) AS ExtraPerms FROM master.sys.server_permissions WHERE grantee_principal_id = SUSER_SID(N'public') AND state_desc LIKE 'GRANT%' AND NOT (permission_name = 'VIEW ANY DATABASE' AND class_desc = 'SERVER') AND NOT (permission_name = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id IN (2,3,4,5));"
                    $r3_8  = Invoke-DbaQuery @connSplat -Query $q3_8 -WarningAction SilentlyContinue
                    $count = if ($r3_8) { $r3_8.ExtraPerms } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.8"
                        CheckName      = "Public Role Server Permissions"
                        Category       = "Authorization"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.8"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count extra permissions"
                        ExpectedValue  = "0"
                        Remediation    = "USE [master]; REVOKE [permission_name] FROM public;  -- Query sys.server_permissions WHERE grantee_principal_id = SUSER_SID(N'public') for the full list."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.8"
                        SqlQuery       = $sql["3.8"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.8: $($_.Exception.Message)" }

                # 3.9 BUILTIN Groups
                try {
                    $builtins = Get-DbaLogin @connSplat -WarningAction SilentlyContinue | Where-Object { $_.Name -like "BUILTIN\*" }
                    $count    = if ($builtins) { @($builtins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.9"
                        CheckName      = "BUILTIN Groups"
                        Category       = "Authorization"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.9"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtins.Name -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "USE [master]; DROP LOGIN [BUILTIN\Administrators];  -- Ensure equivalent AD groups are in place before dropping."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.9"
                        SqlQuery       = $sql["3.9"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.9: $($_.Exception.Message)" }

                # 3.10 Local Windows Groups
                try {
                    $localGroups = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.LoginType -eq "WindowsGroup" -and $_.Name -like "$computerName\*" }
                    $count = if ($localGroups) { @($localGroups).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.10"
                        CheckName      = "Local Windows Groups"
                        Category       = "Authorization"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.10"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($localGroups.Name -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "Replace local group logins with domain group logins, then USE [master]; DROP LOGIN [localgroup];"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.10"
                        SqlQuery       = $sql["3.10"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.10: $($_.Exception.Message)" }

                # 3.11 Agent Proxy — public access
                try {
                    $q3_11 = "SELECT COUNT(*) AS ProxyCount FROM msdb.dbo.sysproxylogin spl JOIN sys.database_principals dp ON dp.sid = spl.sid JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id WHERE principal_id = USER_ID('public');"
                    $r3_11 = Invoke-DbaQuery @connSplat -Database msdb -Query $q3_11 -WarningAction SilentlyContinue
                    $count = if ($r3_11) { $r3_11.ProxyCount } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.11"
                        CheckName      = "Agent Proxy Public Access"
                        Category       = "Authorization"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.11"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count proxies accessible to public"
                        ExpectedValue  = "0"
                        Remediation    = "USE [msdb]; EXEC dbo.sp_revoke_login_from_proxy @name = N''public'', @proxy_name = N''<proxyname>'';"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.11"
                        SqlQuery       = $sql["3.11"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.11: $($_.Exception.Message)" }

                # 3.12 SYSADMIN Role — Manual per CIS 2025. Collect membership for review.
                try {
                    $sysadmins = Invoke-DbaQuery @connSplat -Query "SELECT DISTINCT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT IN ('NT SERVICE\SQLWriter','NT SERVICE\Winmgmt','NT SERVICE\MSSQLSERVER','NT SERVICE\SQLSERVERAGENT') AND name NOT LIKE '##%';" -WarningAction SilentlyContinue
                    $count = if ($sysadmins) { @($sysadmins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.12"
                        CheckName      = "SYSADMIN Role Membership"
                        Category       = "Authorization"
                        AssessmentType = "Manual"
                        Priority       = $cisPriority["3.12"]
                        Status         = "Manual"
                        CurrentValue   = "$count non-system sysadmin members"
                        ExpectedValue  = "Only explicitly approved administrative accounts"
                        Remediation    = "Review the member list from the SqlQuery. For any account that should not have sysadmin: ALTER SERVER ROLE sysadmin DROP MEMBER [account];"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.12"
                        SqlQuery       = $sql["3.12"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.12: $($_.Exception.Message)" }

                # 3.13 msdb Admin Roles
                try {
                    $msdbHighRoles = Get-DbaDbRoleMember @connSplat -Database msdb -WarningAction SilentlyContinue |
                        Where-Object { $_.Role -in "db_owner","db_securityadmin","db_ddladmin","db_datawriter" -and $_.UserName -ne "dbo" }
                    $count = if ($msdbHighRoles) { @($msdbHighRoles).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.13"
                        CheckName      = "msdb Admin Role Members"
                        Category       = "Authorization"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["3.13"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count members" }
                        ExpectedValue  = "None (dbo only)"
                        Remediation    = "USE [msdb]; ALTER ROLE [db_owner] DROP MEMBER [username];"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.13"
                        SqlQuery       = $sql["3.13"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.13: $($_.Exception.Message)" }

                # 3.14 Control Server Permission — Manual per CIS 2025.
                try {
                    $ctrlQuery = @"
SELECT sys.server_permissions.permission_name, sys.server_permissions.state_desc,
       grantee.name AS GranteeName, grantee.type_desc AS GranteeType
FROM sys.server_principals AS grantee
INNER JOIN sys.server_permissions ON sys.server_permissions.grantee_principal_id = grantee.principal_id
INNER JOIN sys.server_principals AS grantor ON grantor.principal_id = sys.server_permissions.grantor_principal_id
WHERE sys.server_permissions.permission_name = 'CONTROL SERVER'
  AND grantee.name <> '##MS_PolicySigningCertificate##';
"@
                    $ctrlRows = Invoke-DbaQuery @connSplat -Query $ctrlQuery -WarningAction SilentlyContinue
                    $count    = if ($ctrlRows) { @($ctrlRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.14"
                        CheckName      = "Control Server Permission"
                        Category       = "Authorization"
                        AssessmentType = "Manual"
                        Priority       = $cisPriority["3.14"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($count -eq 0) { "None granted" } else { "$count accounts with CONTROL SERVER" }
                        ExpectedValue  = "None — CONTROL SERVER allows privilege escalation to sysadmin"
                        Remediation    = if ($count -eq 0) { $null } else { "Review each account in the SqlQuery result. If not explicitly approved: USE [master]; REVOKE CONTROL SERVER FROM [login];" }
                        Reference      = "CIS SQL Server 2025 v1.0.0 §3.14"
                        SqlQuery       = $sql["3.14"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.14: $($_.Exception.Message)" }

                # 3.15 sp_invoke_external_rest_endpoint — Manual per CIS 2025.
                # This stored procedure was introduced in SQL Server 2022 for REST endpoint calls.
                try {
                    $restQuery = @"
SELECT dp.name AS PrincipalName, dp.type_desc AS PrincipalType,
       perm.permission_name, perm.state_desc,
       OBJECT_SCHEMA_NAME(perm.major_id) + '.' + OBJECT_NAME(perm.major_id) AS ObjectName
FROM sys.database_permissions perm
JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id
WHERE perm.major_id = OBJECT_ID('sys.sp_invoke_external_rest_endpoint')
  AND perm.permission_name = 'EXECUTE';
"@
                    $restRows   = Invoke-DbaQuery @connSplat -Query $restQuery -WarningAction SilentlyContinue
                    $procExists = Invoke-DbaQuery @connSplat -Query "SELECT OBJECT_ID('sys.sp_invoke_external_rest_endpoint') AS ProcId;" -WarningAction SilentlyContinue
                    if ($null -eq $procExists.ProcId) {
                        $splatCheck = @{
                            CheckId        = "3.15"
                            CheckName      = "sp_invoke_external_rest_endpoint Access"
                            Category       = "Authorization"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["3.15"]
                            Status         = "Pass"
                            CurrentValue   = "Not applicable (procedure does not exist on this version)"
                            ExpectedValue  = "N/A"
                            Reference      = "CIS SQL Server 2025 v1.0.0 §3.15"
                            SqlQuery       = $sql["3.15"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    } else {
                        $count = if ($restRows) { @($restRows).Count } else { 0 }
                        $splatCheck = @{
                            CheckId        = "3.15"
                            CheckName      = "sp_invoke_external_rest_endpoint Access"
                            Category       = "Authorization"
                            AssessmentType = "Manual"
                            Priority       = $cisPriority["3.15"]
                            Status         = if ($count -eq 0) { "Pass" } else { "Manual" }
                            CurrentValue   = if ($count -eq 0) { "No explicit grants found" } else { "$count explicit grants" }
                            ExpectedValue  = "Only trusted accounts; sysadmin members have implicit access and will not appear"
                            Remediation    = if ($count -eq 0) { $null } else { "Review each grant in the SqlQuery result. Remove untrusted accounts: REVOKE EXECUTE ON OBJECT::sys.sp_invoke_external_rest_endpoint FROM [account];" }
                            Reference      = "CIS SQL Server 2025 v1.0.0 §3.15"
                            SqlQuery       = $sql["3.15"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 3.15: $($_.Exception.Message)" }
            }

            # ── §4 Password Policies ───────────────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Password Policies"

                # 4.1 MUST_CHANGE — Manual per CIS 2025.
                try {
                    $mustChange = Get-DbaLogin @connSplat -Type SQL -Detailed -WarningAction SilentlyContinue |
                        Where-Object { $_.IsMustChange -eq $true }
                    $count = if ($mustChange) { @($mustChange).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "4.1"
                        CheckName      = "MUST_CHANGE Logins"
                        Category       = "Password Policy"
                        AssessmentType = "Manual"
                        Priority       = $cisPriority["4.1"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count logins with MUST_CHANGE set" }
                        ExpectedValue  = "MUST_CHANGE = ON for all new SQL logins; zero logins with an unclaimed change"
                        Remediation    = if ($count -eq 0) { $null } else { "Review each login with MUST_CHANGE set. If the account is legitimate and active, ensure the user has changed their password. If stale: DROP LOGIN [name];" }
                        Reference      = "CIS SQL Server 2025 v1.0.0 §4.1"
                        SqlQuery       = $sql["4.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 4.1: $($_.Exception.Message)" }

                # 4.2 CHECK_EXPIRATION for sysadmin and CONTROL SERVER SQL logins
                try {
                    $expQuery = @"
SELECT l.name, 'sysadmin membership' AS Access_Method
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1
  AND l.is_expiration_checked <> 1 AND l.is_disabled = 0
UNION ALL
SELECT l.name, 'CONTROL SERVER' AS Access_Method
FROM sys.sql_logins AS l
JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL' AND p.state IN ('G','W')
  AND l.is_expiration_checked <> 1 AND l.is_disabled = 0;
"@
                    $expRows = Invoke-DbaQuery @connSplat -Query $expQuery -WarningAction SilentlyContinue
                    $count   = if ($expRows) { @($expRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "4.2"
                        CheckName      = "Sysadmin CHECK_EXPIRATION"
                        Category       = "Password Policy"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["4.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count logins without expiration" }
                        ExpectedValue  = "All enabled"
                        Remediation    = "ALTER LOGIN [name] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §4.2"
                        SqlQuery       = $sql["4.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 4.2: $($_.Exception.Message)" }

                # 4.3 CHECK_POLICY
                try {
                    $noPolicy = Invoke-DbaQuery @connSplat -Query "SELECT name, is_disabled FROM sys.sql_logins WHERE is_policy_checked = 0;" -WarningAction SilentlyContinue
                    $count    = if ($noPolicy) { @($noPolicy).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "4.3"
                        CheckName      = "CHECK_POLICY Enabled"
                        Category       = "Password Policy"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["4.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count logins without policy" }
                        ExpectedValue  = "All enabled"
                        Remediation    = "ALTER LOGIN [name] WITH CHECK_POLICY = ON;"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §4.3"
                        SqlQuery       = $sql["4.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 4.3: $($_.Exception.Message)" }
            }

            # ── §5 Auditing & Logging ──────────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Auditing"

                # 5.1 Error Log File Count
                try {
                    $logCfg   = Get-DbaErrorLogConfig @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    $rawCount = if ($logCfg) { $logCfg.LogCount } else { 0 }
                    $count    = if ($rawCount -lt 0) { 6 } else { $rawCount }
                    $display  = if ($rawCount -lt 0) { "default (6) — registry key absent" } else { $count.ToString() }
                    $splatCheck = @{
                        CheckId        = "5.1"
                        CheckName      = "Error Log File Count"
                        Category       = "Auditing"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["5.1"]
                        Status         = if ($count -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $display
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §5.1"
                        SqlQuery       = $sql["5.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 5.1: $($_.Exception.Message)" }

                # 5.2 Default Trace
                try {
                    $defTrace = Get-DbaSpConfigure @connSplat -Name "DefaultTraceEnabled" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($defTrace) {
                        $splatCheck = @{
                            CheckId        = "5.2"
                            CheckName      = "Default Trace Enabled"
                            Category       = "Auditing"
                            AssessmentType = "Automated"
                            Priority       = $cisPriority["5.2"]
                            Status         = if ($defTrace.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $defTrace.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "CIS SQL Server 2025 v1.0.0 §5.2"
                            SqlQuery       = $sql["5.2"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 5.2: $($_.Exception.Message)" }

                # 5.3 Login Audit Level
                try {
                    $auditResult = Invoke-DbaQuery @connSplat -Query "EXEC xp_loginconfig 'audit level';" -WarningAction SilentlyContinue
                    $rawLevel    = if ($auditResult) { $auditResult[0].config_value } else { $null }
                    $level       = if ($rawLevel) { $rawLevel.Trim() } else { "none" }
                    $splatCheck = @{
                        CheckId        = "5.3"
                        CheckName      = "Login Audit Level"
                        Category       = "Auditing"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["5.3"]
                        Status         = if ($level -in "all", "failure") { "Pass" } else { "Fail" }
                        CurrentValue   = $level
                        ExpectedValue  = "failure or all"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 2  -- 2=failure, 3=all; SQL Server service restart required."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §5.3"
                        SqlQuery       = $sql["5.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 5.3: $($_.Exception.Message)" }

                # 5.4 SQL Server Audit — CIS 2025 requires specific action groups, not just existence.
                try {
                    $auditQuery = @"
SELECT SAD.audit_action_name, SAD.audited_result,
       S.is_state_enabled AS AuditEnabled, SA.is_state_enabled AS SpecEnabled
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('CNAU','LGFL','LGSD','ADDP','ADSP','OPSV')
   OR (SAD.audit_action_id IN ('DAGS','DAGF') AND (SELECT COUNT(*) FROM sys.databases WHERE containment = 1) > 0);
"@
                    $auditRows   = Invoke-DbaQuery @connSplat -Query $auditQuery -WarningAction SilentlyContinue
                    $required    = @("AUDIT_CHANGE_GROUP","FAILED_LOGIN_GROUP","SUCCESSFUL_LOGIN_GROUP",
                                     "DATABASE_ROLE_MEMBER_CHANGE_GROUP","SERVER_ROLE_MEMBER_CHANGE_GROUP","SERVER_OPERATION_GROUP")
                    $foundGroups = if ($auditRows) { @($auditRows | Where-Object { $_.AuditEnabled -and $_.SpecEnabled } | Select-Object -ExpandProperty audit_action_name -Unique) } else { @() }
                    $missing     = $required | Where-Object { $_ -notin $foundGroups }
                    $compliant   = $missing.Count -eq 0
                    $splatCheck = @{
                        CheckId        = "5.4"
                        CheckName      = "SQL Server Audit — Required Action Groups"
                        Category       = "Auditing"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["5.4"]
                        Status         = if ($compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($foundGroups.Count -eq 0) { "No enabled audit configured" } else { "$($foundGroups.Count) of $($required.Count) required groups found" }
                        ExpectedValue  = "All 6 required action groups captured and both Audit + Specification enabled"
                        Remediation    = if ($compliant) { $null } else { "Missing groups: $($missing -join ", "). See CIS §5.4 for CREATE SERVER AUDIT and SERVER AUDIT SPECIFICATION T-SQL." }
                        Reference      = "CIS SQL Server 2025 v1.0.0 §5.4"
                        SqlQuery       = $sql["5.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 5.4: $($_.Exception.Message)" }
            }

            # ── §6 Application Development ─────────────────────────────
            if (ShouldRun "6") {
                Write-Verbose "[$instance] §6 Application Development"

                # 6.1 Input Sanitization — purely architectural/code review, no T-SQL audit.
                $splatCheck = @{
                    CheckId        = "6.1"
                    CheckName      = "Database/Application Input Sanitization"
                    Category       = "AppDev"
                    AssessmentType = "Manual"
                    Priority       = $cisPriority["6.1"]
                    Status         = "Manual"
                    CurrentValue   = "Cannot be determined from SQL Server"
                    ExpectedValue  = "All external input parameterized or validated before reaching SQL Server"
                    Remediation    = "Review application code and stored procedures: (1) Confirm no dynamic SQL built from string concatenation. (2) Verify all external input uses parameterized queries or sp_executesql with typed parameters. (3) Restrict DML permissions to stored procedures only where possible."
                    Reference      = "CIS SQL Server 2025 v1.0.0 §6.1"
                    SqlQuery       = $sql["6.1"]
                }
                & $emit (New-DakCheckResult @sharedParams @splatCheck)

                # 6.2 CLR Assembly Permission Sets
                try {
                    $q6_2        = "SELECT COUNT(*) AS UnsafeAssemblies FROM sys.assemblies WHERE is_user_defined = 1 AND permission_set_desc NOT IN ('SAFE_ACCESS') AND name <> 'Microsoft.SqlServer.Types';"
                    $dbs         = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $unsafeCount = 0
                    foreach ($db in $dbs) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $q6_2 -WarningAction SilentlyContinue
                        if ($r) { $unsafeCount += $r.UnsafeAssemblies }
                    }
                    $splatCheck = @{
                        CheckId        = "6.2"
                        CheckName      = "CLR Assembly Permission Sets"
                        Category       = "AppDev"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["6.2"]
                        Status         = if ($unsafeCount -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$unsafeCount UNSAFE/EXTERNAL assemblies"
                        ExpectedValue  = "0"
                        Remediation    = "Test in non-production first. If safe: USE [db]; ALTER ASSEMBLY [name] WITH PERMISSION_SET = SAFE;  -- vendor assemblies may require EXTERNAL_ACCESS."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §6.2"
                        SqlQuery       = $sql["6.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.2: $($_.Exception.Message)" }
            }

            # ── §7 Encryption (Level 2) ────────────────────────────────
            if (ShouldRun "7") {
                Write-Verbose "[$instance] §7 Encryption"

                # 7.1 Symmetric Key Algorithms
                try {
                    $q7_1      = "SELECT COUNT(*) AS WeakKeys FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND DB_ID() > 4;"
                    $dbs       = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $weakKeys  = 0
                    foreach ($db in $dbs) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $q7_1 -WarningAction SilentlyContinue
                        if ($r) { $weakKeys += $r.WeakKeys }
                    }
                    $splatCheck = @{
                        CheckId        = "7.1"
                        CheckName      = "Symmetric Key Algorithms"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["7.1"]
                        Status         = if ($weakKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeys non-AES symmetric keys"
                        ExpectedValue  = "0"
                        Remediation    = "Recreate symmetric keys using AES_128, AES_192, or AES_256. See: ALTER SYMMETRIC KEY docs."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §7.1"
                        SqlQuery       = $sql["7.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.1: $($_.Exception.Message)" }

                # 7.2 Asymmetric Key Size
                try {
                    $q7_2      = "SELECT COUNT(*) AS SmallKeys FROM sys.asymmetric_keys WHERE key_length < 2048 AND DB_ID() > 4;"
                    $dbs       = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $smallKeys = 0
                    foreach ($db in $dbs) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $q7_2 -WarningAction SilentlyContinue
                        if ($r) { $smallKeys += $r.SmallKeys }
                    }
                    $splatCheck = @{
                        CheckId        = "7.2"
                        CheckName      = "Asymmetric Key Size"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["7.2"]
                        Status         = if ($smallKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$smallKeys keys < 2048 bit"
                        ExpectedValue  = "0"
                        Remediation    = "Recreate asymmetric keys at RSA_2048 or higher. See: ALTER ASYMMETRIC KEY docs."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §7.2"
                        SqlQuery       = $sql["7.2"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.2: $($_.Exception.Message)" }

                # 7.3 Backup Encryption (Level 2)
                try {
                    $q7_3 = "SELECT COUNT(*) AS UnencBackups FROM msdb.dbo.backupset b JOIN sys.databases d ON b.database_name = d.name WHERE b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted = 0;"
                    $r7_3 = Invoke-DbaQuery @connSplat -Query $q7_3 -WarningAction SilentlyContinue
                    $count = if ($r7_3) { $r7_3.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "7.3"
                        CheckName      = "Backup Encryption (Level 2)"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["7.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup records"
                        ExpectedValue  = "0"
                        Remediation    = "Enable backup encryption (WITH ENCRYPTION clause on BACKUP DATABASE) or enable TDE — TDE-encrypted databases produce automatically encrypted backups."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §7.3 (Level 2)"
                        SqlQuery       = $sql["7.3"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.3: $($_.Exception.Message)" }

                # 7.4 Network Encryption (Level 2) — CIS 2025 audit expects only TRUE rows.
                try {
                    $q7_4 = "SELECT DISTINCT encrypt_option FROM sys.dm_exec_connections c WHERE net_transport <> 'Shared memory' AND c.endpoint_id NOT IN (SELECT endpoint_id FROM sys.database_mirroring_endpoints WHERE encryption_algorithm IS NOT NULL);"
                    $r7_4 = Invoke-DbaQuery @connSplat -Query $q7_4 -WarningAction SilentlyContinue
                    $unenc = if ($r7_4) { @($r7_4 | Where-Object { $_.encrypt_option -ne "TRUE" }).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "7.4"
                        CheckName      = "Network Encryption (Level 2)"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["7.4"]
                        Status         = if ($unenc -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unenc -eq 0) { "All connections encrypted" } else { "$unenc unencrypted connection types" }
                        ExpectedValue  = "All non-shared-memory connections encrypted"
                        Remediation    = "Configure Force Encryption in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties, or enforce TLS at the certificate level."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §7.4 (Level 2)"
                        SqlQuery       = $sql["7.4"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.4: $($_.Exception.Message)" }

                # 7.5 TDE (Level 2) — CIS 2025 audit: no user databases with is_encrypted != 1.
                try {
                    $q7_5  = "SELECT name FROM sys.databases WHERE database_id > 4 AND is_encrypted != 1;"
                    $r7_5  = Invoke-DbaQuery @connSplat -Query $q7_5 -WarningAction SilentlyContinue
                    $count = if ($r7_5) { @($r7_5).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "7.5"
                        CheckName      = "Transparent Data Encryption (Level 2)"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $cisPriority["7.5"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases encrypted" } else { "$count unencrypted user databases" }
                        ExpectedValue  = "0 unencrypted user databases"
                        Remediation    = "Enable TDE on each sensitive database: Get-DbaDatabase -SqlInstance $instance | Where-Object IsSystemObject -eq `$false | Enable-DbaDatabaseEncryption"
                        Reference      = "CIS SQL Server 2025 v1.0.0 §7.5 (Level 2)"
                        SqlQuery       = $sql["7.5"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.5: $($_.Exception.Message)" }
            }

            # ── §8 Additional ──────────────────────────────────────────
            if (ShouldRun "8") {
                Write-Verbose "[$instance] §8 Additional"

                # 8.1 SQL Browser Service — Manual per CIS 2025.
                # The benchmark explicitly states no universal recommendation; context determines correctness.
                try {
                    $browser = Get-DbaService -ComputerName $computerName -WarningAction SilentlyContinue |
                        Where-Object { $_.ServiceType -eq "Browser" } | Select-Object -First 1
                    $currentVal = if ($browser) { "State=$($browser.State); StartMode=$($browser.StartMode)" } else { "Service not found" }
                    $splatCheck = @{
                        CheckId        = "8.1"
                        CheckName      = "SQL Server Browser Service"
                        Category       = "Additional"
                        AssessmentType = "Manual"
                        Priority       = $cisPriority["8.1"]
                        Status         = "Manual"
                        CurrentValue   = $currentVal
                        ExpectedValue  = "Depends on environment: Disabled for default instances; Enabled only for named instances accessed interactively by end users"
                        Remediation    = "Default instance or app-only named instance: disable and set to Manual or Disabled start. Named instance with interactive end-user connections: Browser service may be required. Document the decision and ensure firewall rules compensate if disabled."
                        Reference      = "CIS SQL Server 2025 v1.0.0 §8.1"
                        SqlQuery       = $sql["8.1"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.1: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] CIS 2025 complete"
        }
    }

    end {}

}
