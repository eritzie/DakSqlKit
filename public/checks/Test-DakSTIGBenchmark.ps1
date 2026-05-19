. "$PSScriptRoot\Private\AccessControl.ps1"
. "$PSScriptRoot\Private\Audit.ps1"
. "$PSScriptRoot\Private\BackupIntegrity.ps1"
. "$PSScriptRoot\Private\Configuration.ps1"
. "$PSScriptRoot\Private\Encryption.ps1"
. "$PSScriptRoot\Private\Operations.ps1"

function Test-DakSTIGBenchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against the DISA STIG for Microsoft SQL Server 2022.

    .DESCRIPTION
        Runs checks from the DISA STIG SQL Server 2022 Instance STIG V1R4 and
        Database STIG V1R3. Returns one result object per check per instance
        (type: DakSqlKit.AuditResult).

        Only checks that can be evaluated programmatically are included.
        AssessmentType on each result indicates whether the tool made the determination:
            Automated — pass/fail determined by the tool
            Manual    — tool collected evidence; a human must determine compliance

        Sections:
            1 — Authentication & Access Control
            2 — Audit & Logging
            3 — Surface Area Reduction
            4 — Encryption & Transport Security
            5 — Operational
            6 — Database-Level Checks

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        Sections to run: 1–6, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

    .PARAMETER Quiet
        Suppress Write-Host progress output.

    .EXAMPLE
        Test-DakSTIGBenchmark -SqlInstance 'SQL-ENT-TEST\ENT'

    .EXAMPLE
        Test-DakSTIGBenchmark -SqlInstance 'SQL-ENT-TEST\ENT' -Section 2 -FailedOnly
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("1", "2", "3", "4", "5", "6", "All")]
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

        $stigPriority = @{
            "V-271264" = "High"    # CAT I — SPN / Kerberos auth
            "V-271265" = "High"    # CAT I — Windows-only auth
            "V-271270" = "Medium"  # CAT II — Audit configured
            "V-271272" = "Medium"  # CAT II — SCHEMA_OBJECT_ACCESS_GROUP audited
            "V-271273" = "Medium"  # CAT II — Audit starts at startup
            "V-271290" = "Medium"  # CAT II — Sample databases removed
            "V-271292" = "Medium"  # CAT II — Replication XPs disabled
            "V-271293" = "Medium"  # CAT II — External Scripts disabled
            "V-271295" = "Medium"  # CAT II — Remote Data Archive disabled
            "V-271296" = "Medium"  # CAT II — Allow Polybase Export disabled
            "V-271297" = "Medium"  # CAT II — Hadoop Connectivity disabled
            "V-271298" = "Medium"  # CAT II — Remote Access disabled
            "V-271299" = "Medium"  # CAT II — Linked servers restricted
            "V-271300" = "Medium"  # CAT II — Non-standard extended SPs
            "V-271301" = "Medium"  # CAT II — CLR disabled
            "V-271302" = "Medium"  # CAT II — xp_cmdshell disabled
            "V-271303" = "Medium"  # CAT II — Non-standard ports
            "V-271304" = "Medium"  # CAT II — Protocols restricted
            "V-271306" = "High"    # CAT I — Contained DB Windows principals
            "V-271307" = "High"    # CAT I — SQL login password policy
            "V-271309" = "High"    # CAT I — Force encryption
            "V-271310" = "High"    # CAT I — TLS 1.2 required
            "V-271314" = "High"    # CAT I — FIPS 140-2/3 enabled
            "V-271324" = "High"    # CAT I — Data at rest (TDE)
            "V-271328" = "Medium"  # CAT II — Common criteria compliance
            "V-271334" = "Medium"  # CAT II — Error message masking
            "V-271342" = "Medium"  # CAT II — Credentials/proxies restricted
            "V-271345" = "Medium"  # CAT II — Audit failure alerts
            "V-271351" = "Medium"  # CAT II — 30 required audit action groups
            "V-271358" = "Medium"  # CAT II — Unique service accounts
            "V-271359" = "Medium"  # CAT II — CLR execution domain
            "V-271365" = "High"    # CAT I — Supported SQL Server version
            "V-271370" = "Medium"  # CAT II — SCHEMA_OBJECT_CHANGE_GROUP
            "V-271375" = "Medium"  # CAT II — Login/logoff groups
            "V-271381" = "Medium"  # CAT II — No audit filters blocking direct access
            "V-271387" = "Medium"  # CAT II — SQL Browser disabled
            "V-271388" = "Medium"  # CAT II — Telemetry audit configured
            "V-271389" = "Medium"  # CAT II — Customer feedback disabled
            "V-271400" = "Medium"  # CAT II — MUST_CHANGE on account recovery
            "V-274444" = "Medium"  # CAT II — sa account disabled
            "V-274445" = "Medium"  # CAT II — sa renamed
            "V-274446" = "Medium"  # CAT II — Startup stored procs restricted
            "V-274447" = "Medium"  # CAT II — Mirroring endpoint uses AES
            "V-274448" = "Medium"  # CAT II — Service Broker endpoint uses AES
            "V-274449" = "Medium"  # CAT II — xp_reg* permissions revoked
            "V-274450" = "Medium"  # CAT II — Filestream disabled
            "V-274451" = "Medium"  # CAT II — OLE Automation disabled
            "V-274452" = "Medium"  # CAT II — User Options disabled
            "V-271118" = "High"    # CAT I — DB auth via Windows principals
            "V-271122" = "Medium"  # CAT II — Trustworthy databases restricted
            "V-271147" = "Medium"  # CAT II — DDL permissions restricted
            "V-271168" = "Medium"  # CAT II — Backup/recovery plan exists
            "V-271170" = "Medium"  # CAT II — DMK encrypted appropriately
            "V-271188" = "Medium"  # CAT II — EXECUTE AS usage restricted
            "V-271195" = "Medium"  # CAT II — DB owners not in fixed server roles
            "V-271199" = "High"    # CAT I — NSA-approved crypto (FIPS)
            "V-271201" = "High"    # CAT I — Crypto for data at rest
            "V-283667" = "Medium"  # CAT II — No computer accounts in DB
        }

        # T-SQL references for each check (used in SqlQuery field of output)
        $stigSql = @{
            "V-271264" = "-- Automated via Test-DbaSpn (dbatools). T-SQL reference: SELECT servicename, service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%';"
            "V-271265" = "SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'Mixed Mode' END AS [Authentication Mode];"
            "V-271270" = "SELECT name AS AuditName, status_desc AS AuditStatus FROM sys.dm_server_audit_status;"
            "V-271272" = "SELECT d.audit_action_name FROM sys.server_audit_specification_details d JOIN sys.server_audit_specifications sa ON d.server_specification_id = sa.server_specification_id JOIN sys.server_audits a ON sa.audit_guid = a.audit_guid WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';"
            "V-271273" = "SELECT name, status_desc FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED';"
            "V-271290" = "SELECT name FROM sys.databases WHERE name LIKE '%pubs%' OR name LIKE '%northwind%' OR name LIKE '%adventureworks%' OR name LIKE '%wideworldimporters%' OR name LIKE '%contoso%';"
            "V-271292" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Replication Xps';"
            "V-271293" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'External Scripts Enabled';"
            "V-271295" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Remote Data Archive';"
            "V-271296" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Allow Polybase Export';"
            "V-271297" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Hadoop Connectivity';"
            "V-271298" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Remote Access';"
            "V-271299" = "SELECT name FROM sys.servers WHERE is_linked = 1;"
            "V-271300" = "USE [master]; SELECT X.xp_name, X.source_dll FROM (SELECT xp_name, source_dll FROM OPENQUERY([LOCALSERVER], 'EXEC sp_helpextendedproc')) X JOIN sys.all_objects O ON X.xp_name = O.name WHERE O.is_ms_shipped = 0;"
            "V-271301" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'clr enabled';"
            "V-271302" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
            "V-271303" = "SELECT ISNULL(CONVERT(VARCHAR(25), local_tcp_port), 'Dynamic') AS Port FROM sys.dm_exec_connections WHERE session_id = @@SPID;"
            "V-271304" = "-- Automated via Get-DbaInstanceProtocol (dbatools WMI)."
            "V-271306" = "SELECT DB_NAME() AS DatabaseName, name FROM sys.database_principals dp INNER JOIN sys.databases d ON d.name = dp.name WHERE dp.authentication_type = 2 AND d.containment = 1;"
            "V-271307" = "SELECT name, is_expiration_checked, is_policy_checked FROM sys.sql_logins WHERE is_disabled = 0 AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##','##MS_PolicyEventProcessingLogin##') AND sid <> 1;"
            "V-271309" = "-- Automated via Get-DbaInstanceProtocol (dbatools WMI — check ForceEncryption flag)."
            "V-271310" = "-- No dbatools equivalent — registry check: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
            "V-271314" = "-- No dbatools equivalent — registry check: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
            "V-271324" = "SELECT db.name AS DatabaseName, db.is_encrypted FROM sys.databases db WHERE db.database_id > 4;"
            "V-271328" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'common criteria compliance enabled';"
            "V-271334" = "DBCC TRACESTATUS;"
            "V-271342" = "SELECT C.name AS credential_name, C.credential_identity FROM sys.credentials C;"
            "V-271345" = "-- Manual check. Verify alerting configured for audit failures via SQL Agent alerts or external SIEM."
            "V-271351" = "SELECT a.name AS AuditName, d.audit_action_name FROM sys.server_audit_specifications s JOIN sys.server_audits a ON s.audit_guid = a.audit_guid JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id WHERE a.is_state_enabled = 1 ORDER BY d.audit_action_name;"
            "V-271358" = "SELECT servicename, service_account FROM sys.dm_server_services;"
            "V-271359" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'clr enabled';"
            "V-271365" = "SELECT @@VERSION AS Version, SERVERPROPERTY('ProductVersion') AS Build;"
            "V-271370" = "SELECT d.audit_action_name FROM sys.server_audit_specification_details d JOIN sys.server_audit_specifications sa ON d.server_specification_id = sa.server_specification_id JOIN sys.server_audits a ON sa.audit_guid = a.audit_guid WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP';"
            "V-271375" = "SELECT d.audit_action_name FROM sys.server_audit_specification_details d JOIN sys.server_audit_specifications sa ON d.server_specification_id = sa.server_specification_id JOIN sys.server_audits a ON sa.audit_guid = a.audit_guid WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('SUCCESSFUL_LOGIN_GROUP','FAILED_LOGIN_GROUP');"
            "V-271381" = "SELECT name AS AuditName, predicate AS AuditFilter FROM sys.server_audits WHERE predicate IS NOT NULL;"
            "V-271387" = "-- Automated via Get-DbaService (dbatools)."
            "V-271388" = "-- No dbatools equivalent — registry check: HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceId]\CPE\UserRequestedLocalAuditDirectory"
            "V-271389" = "-- No dbatools equivalent — registry check: HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceId]\CPE and \160 for CustomerFeedback and EnableErrorReporting"
            "V-271400" = "SELECT name, CAST(LOGINPROPERTY(name, 'IsMustChange') AS bit) AS IsMustChange FROM sys.server_principals WHERE type = 'S' AND CAST(LOGINPROPERTY(name, 'IsMustChange') AS bit) = 1;"
            "V-274444" = "SELECT name, is_disabled FROM sys.sql_logins WHERE principal_id = 1;"
            "V-274445" = "SELECT name FROM sys.server_principals WHERE sid = 0x01;"
            "V-274446" = "SELECT name FROM sys.procedures WHERE OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1;"
            "V-274447" = "SELECT name, type_desc, encryption_algorithm_desc FROM sys.database_mirroring_endpoints WHERE encryption_algorithm != 2;"
            "V-274448" = "SELECT name, type_desc, encryption_algorithm_desc FROM sys.service_broker_endpoints WHERE encryption_algorithm != 2;"
            "V-274449" = "SELECT OBJECT_NAME(major_id) AS [Stored Procedure], dpr.name AS [Principal] FROM sys.database_permissions AS dp INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id WHERE major_id IN (OBJECT_ID('xp_regaddmultistring'),OBJECT_ID('xp_regdeletekey'),OBJECT_ID('xp_regdeletevalue'),OBJECT_ID('xp_regenumvalues'),OBJECT_ID('xp_regenumkeys'),OBJECT_ID('xp_regremovemultistring'),OBJECT_ID('xp_regwrite')) AND dp.type = 'EX' ORDER BY dpr.name;"
            "V-274450" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'filestream access level';"
            "V-274451" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
            "V-274452" = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'user options';"
            "V-271118" = "SELECT name FROM sys.database_principals WHERE type_desc = 'SQL_USER' AND authentication_type_desc = 'DATABASE';"
            "V-271122" = "SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb';"
            "V-271147" = "SELECT P.type_desc AS principal_type, P.name AS principal_name, DP.permission_name FROM sys.database_permissions DP JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53);"
            "V-271168" = "SELECT name, recovery_model_desc FROM sys.databases WHERE database_id > 4 ORDER BY name;"
            "V-271170" = "SELECT name FROM [master].sys.databases WHERE is_master_key_encrypted_by_server = 1 AND state = 0;"
            "V-271188" = "SELECT S.name AS schema_name, O.name AS module_name, USER_NAME(M.execute_as_principal_id) AS execute_as FROM sys.sql_modules M JOIN sys.objects O ON M.object_id = O.object_id JOIN sys.schemas S ON O.schema_id = S.schema_id WHERE execute_as_principal_id IS NOT NULL;"
            "V-271195" = "SELECT D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name FROM sys.databases D WHERE D.database_id > 4;"
            "V-271199" = "-- No dbatools equivalent — registry check: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy (same as V-271314)"
            "V-271201" = "SELECT db.name, db.is_encrypted FROM sys.databases db LEFT JOIN sys.dm_database_encryption_keys dm ON db.database_id = dm.database_id WHERE db.database_id > 4;"
            "V-283667" = "SELECT name FROM sys.database_principals WHERE type IN ('U','G') AND name LIKE '%`$';"
        }

        # The 30 required audit action groups from SQLI-22-011800
        $requiredAuditGroups = @(
            'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
            'AUDIT_CHANGE_GROUP',
            'BACKUP_RESTORE_GROUP',
            'DATABASE_CHANGE_GROUP',
            'DATABASE_OBJECT_ACCESS_GROUP',
            'DATABASE_OBJECT_CHANGE_GROUP',
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OPERATION_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'DBCC_GROUP',
            'LOGIN_CHANGE_PASSWORD_GROUP',
            'LOGOUT_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OPERATION_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_PRINCIPAL_CHANGE_GROUP',
            'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SERVER_STATE_CHANGE_GROUP',
            'TRACE_CHANGE_GROUP',
            'USER_CHANGE_PASSWORD_GROUP'
        )
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) { Write-Host "STIG Benchmark — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] DISA STIG SQL Server 2022 — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "STIG"
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
                if (-not $Quiet) { Write-Host ("  [{0,-10}] {1,-52} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Manual", "Error") {
                    $r
                }
            }

            # ── §1 Authentication & Access Control ────────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Auth/Access"
                $saData1   = Get-SaLogin   -ctx $connSplat
                $authData1 = Get-AuthMode  -ctx $connSplat

                # V-271264 — SPN / Kerberos authentication
                try {
                    $spnResult = Test-DbaSpn @connSplat -WarningAction SilentlyContinue
                    $spnFail   = @($spnResult | Where-Object { $_.Error })
                    $splatCheck = @{
                        CheckId        = "V-271264"
                        CheckName      = "SPN Kerberos Authentication"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271264"]
                        Status         = if ($spnFail.Count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($spnFail.Count -eq 0) { "SPNs valid" } else { "$($spnFail.Count) SPN issue(s) detected" }
                        ExpectedValue  = "All SPNs registered and valid"
                        Remediation    = "Register missing SPNs using: setspn -S MSSQLSvc/<FQDN>:<port> <ServiceAccount>. See SQLI-22-003800."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-003800 (V-271264)"
                        SqlQuery       = $stigSql["V-271264"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271264: $($_.Exception.Message)" }

                # V-271265 — Windows-only authentication
                try {
                    $loginMode = $authData1.LoginMode
                    $splatCheck = @{
                        CheckId        = "V-271265"
                        CheckName      = "Windows-Only Authentication Mode"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271265"]
                        Status         = if ($loginMode -eq 1) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($loginMode -eq 1) { "Windows Authentication" } elseif ($loginMode -eq 2) { "Mixed Mode" } else { $loginMode.ToString() }
                        ExpectedValue  = "Windows Authentication (LoginMode = 1)"
                        Remediation    = "Set authentication to Windows only: right-click instance in SSMS > Properties > Security > Windows Authentication Mode, then restart SQL Server."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-003700 (V-271265)"
                        SqlQuery       = $stigSql["V-271265"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271265: $($_.Exception.Message)" }

                # V-271306 — Contained databases must use Windows principals
                try {
                    $contQ = @"
SELECT d.name AS DatabaseName
FROM sys.databases d
WHERE d.containment = 1;
"@
                    $contDbs = @(Invoke-DbaQuery @connSplat -Query $contQ -WarningAction SilentlyContinue)
                    if ($contDbs.Count -eq 0) {
                        $splatCheck = @{
                            CheckId        = "V-271306"
                            CheckName      = "Contained DB Windows Principals"
                            Category       = "Authentication"
                            AssessmentType = "Automated"
                            Priority       = $stigPriority["V-271306"]
                            Status         = "Pass"
                            CurrentValue   = "No contained databases"
                            ExpectedValue  = "No SQL auth users in contained databases"
                            Remediation    = "N/A — no contained databases present."
                            Reference      = "DISA STIG SQL Server 2022 SQLI-22-008000 (V-271306)"
                            SqlQuery       = $stigSql["V-271306"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    } else {
                        $sqlAuthQ = @"
SELECT d.name AS DatabaseName, dp.name AS UserName
FROM sys.database_principals dp
INNER JOIN sys.databases d ON d.name = DB_NAME()
WHERE dp.authentication_type = 2 AND d.containment = 1;
"@
                        $sqlAuthUsers = @()
                        foreach ($cdb in $contDbs) {
                            $splatQ = @{ Database = $cdb.DatabaseName }
                            $sqlAuthUsers += @(Invoke-DbaQuery @connSplat @splatQ -Query $sqlAuthQ -WarningAction SilentlyContinue)
                        }
                        $splatCheck = @{
                            CheckId        = "V-271306"
                            CheckName      = "Contained DB Windows Principals"
                            Category       = "Authentication"
                            AssessmentType = "Automated"
                            Priority       = $stigPriority["V-271306"]
                            Status         = if ($sqlAuthUsers.Count -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = if ($sqlAuthUsers.Count -eq 0) { "No SQL auth users in contained DBs" } else { ($sqlAuthUsers | ForEach-Object { "$($_.DatabaseName)\$($_.UserName)" }) -join ", " }
                            ExpectedValue  = "No SQL auth users in contained databases"
                            Remediation    = "Remove SQL auth users from contained databases; use Windows/Entra principals only."
                            Reference      = "DISA STIG SQL Server 2022 SQLI-22-008000 (V-271306)"
                            SqlQuery       = $stigSql["V-271306"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] V-271306: $($_.Exception.Message)" }

                # V-271307 — SQL logins must enforce password policy and expiration
                try {
                    $sqlLogins = @(Get-DbaLogin @connSplat -Type SQL -WarningAction SilentlyContinue |
                        Where-Object {
                            $_.IsDisabled -eq $false -and
                            $_.Name -notlike '##MS_%' -and
                            $_.Name -ne 'sa' -and
                            $_.Sid.Length -ne 1
                        })
                    $badLogins = @($sqlLogins | Where-Object { -not $_.PasswordExpirationEnabled -or -not $_.PasswordPolicyEnforced })
                    $splatCheck = @{
                        CheckId        = "V-271307"
                        CheckName      = "SQL Login Password Policy Enforcement"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271307"]
                        Status         = if ($badLogins.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($badLogins.Count -eq 0) { "All SQL logins enforce policy/expiration" } else { "Non-compliant: $($badLogins.Name -join ', ')" }
                        ExpectedValue  = "All SQL logins: CHECK_POLICY=ON and CHECK_EXPIRATION=ON"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION=ON, CHECK_POLICY=ON; for each non-compliant login."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-007900 (V-271307)"
                        SqlQuery       = $stigSql["V-271307"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271307: $($_.Exception.Message)" }

                # V-271309 — Force encryption on connections
                try {
                    $proto = Get-DbaInstanceProtocol @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -eq "tcp" } | Select-Object -First 1
                    $forceEnc = if ($proto) { [bool]$proto.ForceEncryption } else { $null }
                    $splatCheck = @{
                        CheckId        = "V-271309"
                        CheckName      = "Force Encryption on Connections"
                        Category       = "Authentication"
                        AssessmentType = if ($null -ne $forceEnc) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271309"]
                        Status         = if ($null -eq $forceEnc) { "Manual" } elseif ($forceEnc) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $forceEnc) { "Could not read protocol properties" } elseif ($forceEnc) { "ForceEncryption = True" } else { "ForceEncryption = False" }
                        ExpectedValue  = "ForceEncryption = True with DOD-approved certificate"
                        Remediation    = "Open SQL Server Configuration Manager > Protocols > Properties > Flags tab > set ForceEncryption to Yes. Requires DOD-approved certificate on Certificate tab."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-008200 (V-271309)"
                        SqlQuery       = $stigSql["V-271309"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271309: $($_.Exception.Message)" }

                # V-271400 — MUST_CHANGE on account recovery
                try {
                    $mustChangeQ = "SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND sid <> 0x01 AND name NOT LIKE '##MS_%' AND CAST(LOGINPROPERTY(name,'IsMustChange') AS bit) = 0 AND CAST(LOGINPROPERTY(name,'IsBadPassword') AS bit) = 0;"
                    $noMustChange = @(Invoke-DbaQuery @connSplat -Query $mustChangeQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271400"
                        CheckName      = "MUST_CHANGE on Account Recovery"
                        Category       = "Authentication"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271400"]
                        Status         = "Manual"
                        CurrentValue   = "SQL logins present: $($noMustChange.Count)"
                        ExpectedValue  = "New/recovered SQL logins must include MUST_CHANGE in creation/reset scripts"
                        Remediation    = "Verify all CREATE LOGIN and password reset scripts include MUST_CHANGE, CHECK_EXPIRATION=ON, CHECK_POLICY=ON."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-019500 (V-271400)"
                        SqlQuery       = $stigSql["V-271400"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271400: $($_.Exception.Message)" }

                # V-274444 — sa account disabled
                try {
                    $saLogin = $saData1.Login
                    $splatCheck = @{
                        CheckId        = "V-274444"
                        CheckName      = "SA Account Disabled"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-274444"]
                        Status         = if (-not $saLogin) { "Pass" } elseif ($saLogin.IsDisabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if (-not $saLogin) { "SA principal not found" } elseif ($saLogin.IsDisabled) { "Disabled" } else { "Enabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "ALTER LOGIN [sa] DISABLE;"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016200 (V-274444)"
                        SqlQuery       = $stigSql["V-274444"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274444: $($_.Exception.Message)" }

                # V-274445 — sa renamed
                try {
                    $saLogin    = $saData1.Login
                    $saName     = if ($saLogin) { $saLogin.Name } else { "" }
                    $splatCheck = @{
                        CheckId        = "V-274445"
                        CheckName      = "SA Account Renamed"
                        Category       = "Authentication"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-274445"]
                        Status         = if ($saName -eq "sa" -or $saName -eq "SA") { "Fail" } else { "Pass" }
                        CurrentValue   = if ($saName) { $saName } else { "SA principal not found" }
                        ExpectedValue  = "Name other than 'sa'"
                        Remediation    = "ALTER LOGIN [sa] WITH NAME = [<new_name>];"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016300 (V-274445)"
                        SqlQuery       = $stigSql["V-274445"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274445: $($_.Exception.Message)" }
            }

            # ── §2 Audit & Logging ─────────────────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Audit"
                $auditData2 = Get-SqlAudits -ctx $connSplat

                # V-271270 — At least one audit configured and enabled
                try {
                    $activeAudit = @($auditData2.EnabledRows | Select-Object -ExpandProperty AuditEnabled -Unique)
                    $splatCheck = @{
                        CheckId        = "V-271270"
                        CheckName      = "Server Audit Configured and Enabled"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271270"]
                        Status         = if ($activeAudit.Count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($activeAudit.Count -gt 0) { "Active audit specification(s) found" } else { "No active audit found" }
                        ExpectedValue  = "At least one active server audit specification"
                        Remediation    = "Create and enable a server audit and server audit specification. Refer to supplemental file SQL2022Audit.sql."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-004300 (V-271270)"
                        SqlQuery       = $stigSql["V-271270"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271270: $($_.Exception.Message)" }

                # V-271272 — SCHEMA_OBJECT_ACCESS_GROUP in active audit
                try {
                    $hasSOAG = $auditData2.ActionNames -contains 'SCHEMA_OBJECT_ACCESS_GROUP'
                    $splatCheck = @{
                        CheckId        = "V-271272"
                        CheckName      = "SCHEMA_OBJECT_ACCESS_GROUP Audited"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271272"]
                        Status         = if ($hasSOAG) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($hasSOAG) { "Present in active audit spec" } else { "Missing from audit spec" }
                        ExpectedValue  = "SCHEMA_OBJECT_ACCESS_GROUP in active server audit specification"
                        Remediation    = "Add SCHEMA_OBJECT_ACCESS_GROUP to the server audit specification."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-004600 (V-271272)"
                        SqlQuery       = $stigSql["V-271272"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271272: $($_.Exception.Message)" }

                # V-271273 — Audit must start at instance startup
                try {
                    $startedQ = "SELECT COUNT(*) AS StartedCount FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED';"
                    $startedR = Invoke-DbaQuery @connSplat -Query $startedQ -WarningAction SilentlyContinue
                    $started  = if ($startedR) { $startedR.StartedCount } else { 0 }
                    $splatCheck = @{
                        CheckId        = "V-271273"
                        CheckName      = "Audit Starts at Instance Startup"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271273"]
                        Status         = if ($started -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($started -gt 0) { "$started audit(s) in STARTED state" } else { "No audits in STARTED state" }
                        ExpectedValue  = "At least one audit in STARTED state"
                        Remediation    = "ALTER SERVER AUDIT [<AuditName>] WITH (STATE = ON);"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-004700 (V-271273)"
                        SqlQuery       = $stigSql["V-271273"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271273: $($_.Exception.Message)" }

                # V-271345 — Real-time alert on audit log failure (Manual)
                $splatCheck = @{
                    CheckId        = "V-271345"
                    CheckName      = "Real-Time Alert on Audit Log Failure"
                    Category       = "Audit"
                    AssessmentType = "Manual"
                    Priority       = $stigPriority["V-271345"]
                    Status         = "Manual"
                    CurrentValue   = "Cannot be determined automatically"
                    ExpectedValue  = "SQL Agent alert or external SIEM configured to notify on audit failure"
                    Remediation    = "Configure a SQL Agent alert for event 33205 (Audit Failure) or integrate with a SIEM that monitors SQL Server audit logs."
                    Reference      = "DISA STIG SQL Server 2022 SQLI-22-011100 (V-271345)"
                    SqlQuery       = $stigSql["V-271345"]
                }
                & $emit (New-DakCheckResult @sharedParams @splatCheck)

                # V-271351 — 30 required audit action groups
                try {
                    $presentGroups = $auditData2.ActionNames
                    $missingGroups = @($requiredAuditGroups | Where-Object { $_ -notin $presentGroups })
                    $splatCheck = @{
                        CheckId        = "V-271351"
                        CheckName      = "30 Required Audit Action Groups Present"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271351"]
                        Status         = if ($missingGroups.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingGroups.Count -eq 0) { "All 30 groups present" } else { "Missing ($($missingGroups.Count)): $($missingGroups -join ', ')" }
                        ExpectedValue  = "All 30 required action groups in active server audit specification"
                        Remediation    = "Add missing action groups to the server audit specification. Refer to supplemental file SQL2022Audit.sql."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-011800 (V-271351)"
                        SqlQuery       = $stigSql["V-271351"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271351: $($_.Exception.Message)" }

                # V-271370 — SCHEMA_OBJECT_CHANGE_GROUP audited
                try {
                    $hasSCG = $auditData2.ActionNames -contains 'SCHEMA_OBJECT_CHANGE_GROUP'
                    $splatCheck = @{
                        CheckId        = "V-271370"
                        CheckName      = "SCHEMA_OBJECT_CHANGE_GROUP Audited"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271370"]
                        Status         = if ($hasSCG) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($hasSCG) { "Present in active audit spec" } else { "Missing from audit spec" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP in active server audit specification"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to the server audit specification."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-013800 (V-271370)"
                        SqlQuery       = $stigSql["V-271370"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271370: $($_.Exception.Message)" }

                # V-271375 — SUCCESSFUL_LOGIN_GROUP and FAILED_LOGIN_GROUP
                try {
                    $hasSuccLogin = $auditData2.ActionNames -contains 'SUCCESSFUL_LOGIN_GROUP'
                    $hasFailLogin = $auditData2.ActionNames -contains 'FAILED_LOGIN_GROUP'
                    $missing375   = @()
                    if (-not $hasSuccLogin) { $missing375 += 'SUCCESSFUL_LOGIN_GROUP' }
                    if (-not $hasFailLogin) { $missing375 += 'FAILED_LOGIN_GROUP' }
                    $splatCheck = @{
                        CheckId        = "V-271375"
                        CheckName      = "Login/Logoff Audit Groups Present"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271375"]
                        Status         = if ($missing375.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missing375.Count -eq 0) { "Both login groups present" } else { "Missing: $($missing375 -join ', ')" }
                        ExpectedValue  = "SUCCESSFUL_LOGIN_GROUP and FAILED_LOGIN_GROUP in active audit spec"
                        Remediation    = "Add $($missing375 -join ' and ') to the server audit specification, or enable 'Both failed and successful logins' in instance Security properties."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-014800 (V-271375)"
                        SqlQuery       = $stigSql["V-271375"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271375: $($_.Exception.Message)" }

                # V-271381 — No audit filters that exclude direct access
                try {
                    $filteredAudits = @(Invoke-DbaQuery @connSplat -Query "SELECT name, predicate FROM sys.server_audits WHERE predicate IS NOT NULL;" -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271381"
                        CheckName      = "No Audit Filters Excluding Direct Access"
                        Category       = "Audit"
                        AssessmentType = if ($filteredAudits.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271381"]
                        Status         = if ($filteredAudits.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($filteredAudits.Count -eq 0) { "No audit filters configured" } else { "Filtered audits: $($filteredAudits.name -join ', ')" }
                        ExpectedValue  = "No filters that exclude direct database access"
                        Remediation    = "Review each audit filter to ensure direct database access is not excluded. Remove or modify filters as needed."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-015500 (V-271381)"
                        SqlQuery       = $stigSql["V-271381"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271381: $($_.Exception.Message)" }
            }

            # ── §3 Surface Area Reduction ──────────────────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 Surface Area"

                try {
                    $allCfg3 = Get-DbaSpConfigure @connSplat -WarningAction SilentlyContinue

                    $cfgMap3 = [ordered]@{
                        "Replication Xps"        = @{ CheckId="V-271292"; CheckName="Replication XPs Disabled";           Ref="SQLI-22-017900" }
                        "External Scripts Enabled"= @{ CheckId="V-271293"; CheckName="External Scripts Disabled";          Ref="SQLI-22-017700" }
                        "Remote Data Archive"    = @{ CheckId="V-271295"; CheckName="Remote Data Archive Disabled";       Ref="SQLI-22-017600" }
                        "Allow Polybase Export"  = @{ CheckId="V-271296"; CheckName="Allow Polybase Export Disabled";     Ref="SQLI-22-017500" }
                        "Hadoop Connectivity"    = @{ CheckId="V-271297"; CheckName="Hadoop Connectivity Disabled";       Ref="SQLI-22-017400" }
                        "Remote Access"          = @{ CheckId="V-271298"; CheckName="Remote Access Disabled";             Ref="SQLI-22-017200" }
                        "clr enabled"            = @{ CheckId="V-271301"; CheckName="CLR Integration Disabled";           Ref="SQLI-22-007300" }
                        "xp_cmdshell"            = @{ CheckId="V-271302"; CheckName="xp_cmdshell Disabled";               Ref="SQLI-22-007200" }
                        "common criteria compliance enabled" = @{ CheckId="V-271328"; CheckName="Common Criteria Compliance Enabled"; Ref="SQLI-22-009800"; ExpectedValue=1 }
                        "filestream access level"= @{ CheckId="V-274450"; CheckName="Filestream Disabled";                Ref="SQLI-22-016800" }
                        "Ole Automation Procedures" = @{ CheckId="V-274451"; CheckName="OLE Automation Procedures Disabled"; Ref="SQLI-22-017000" }
                        "user options"           = @{ CheckId="V-274452"; CheckName="User Options Disabled";              Ref="SQLI-22-017100" }
                    }

                    foreach ($cfgName in $cfgMap3.Keys) {
                        $m   = $cfgMap3[$cfgName]
                        $row = $allCfg3 | Where-Object { $_.Name -eq $cfgName } | Select-Object -First 1
                        $expectedVal = if ($m.ContainsKey('ExpectedValue')) { $m.ExpectedValue } else { 0 }
                        if ($row) {
                            $splatCheck = @{
                                CheckId        = $m.CheckId
                                CheckName      = $m.CheckName
                                Category       = "Surface Area"
                                AssessmentType = "Automated"
                                Priority       = $stigPriority[$m.CheckId]
                                Status         = if ($row.RunningValue -eq $expectedVal) { "Pass" } else { "Fail" }
                                CurrentValue   = $row.RunningValue.ToString()
                                ExpectedValue  = $expectedVal.ToString()
                                Remediation    = "EXEC sp_configure '$cfgName', $expectedVal; RECONFIGURE WITH OVERRIDE;"
                                Reference      = "DISA STIG SQL Server 2022 $($m.Ref) ($($m.CheckId))"
                                SqlQuery       = $stigSql[$m.CheckId]
                            }
                            & $emit (New-DakCheckResult @sharedParams @splatCheck)
                        }
                    }
                } catch { Write-Warning "[$instance] §3 sp_configure: $($_.Exception.Message)" }

                # V-271290 — Sample databases removed
                try {
                    $sampleDbs = @(Get-DbaDatabase @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -match 'pubs|northwind|adventureworks|wideworldimporters|contoso' })
                    $splatCheck = @{
                        CheckId        = "V-271290"
                        CheckName      = "Sample Databases Removed"
                        Category       = "Surface Area"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271290"]
                        Status         = if ($sampleDbs.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($sampleDbs.Count -eq 0) { "None" } else { $sampleDbs.Name -join ", " }
                        ExpectedValue  = "No sample/demo databases"
                        Remediation    = "DROP DATABASE [<sample_db_name>]; for each sample database found."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-006900 (V-271290)"
                        SqlQuery       = $stigSql["V-271290"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271290: $($_.Exception.Message)" }

                # V-271299 — Linked servers restricted
                try {
                    $linkedSvrs = @(Get-DbaLinkedServer @connSplat -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271299"
                        CheckName      = "Linked Servers Restricted"
                        Category       = "Surface Area"
                        AssessmentType = if ($linkedSvrs.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271299"]
                        Status         = if ($linkedSvrs.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($linkedSvrs.Count -eq 0) { "No linked servers" } else { $linkedSvrs.Name -join ", " }
                        ExpectedValue  = "No linked servers, or each is documented and authorized"
                        Remediation    = "Review each linked server. Remove unauthorized entries: sp_dropserver '<name>', 'droplogins';"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-007500 (V-271299)"
                        SqlQuery       = $stigSql["V-271299"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271299: $($_.Exception.Message)" }

                # V-271300 — Non-standard extended stored procedures
                try {
                    $xpQ = @"
DECLARE @xplist AS TABLE (xp_name sysname, source_dll nvarchar(255));
INSERT INTO @xplist EXEC sp_helpextendedproc;
SELECT X.xp_name, X.source_dll
FROM @xplist X
JOIN sys.all_objects O ON X.xp_name = O.name
WHERE O.is_ms_shipped = 0;
"@
                    $nonStdXp = @(Invoke-DbaQuery @connSplat -Query $xpQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271300"
                        CheckName      = "Non-Standard Extended SPs Absent"
                        Category       = "Surface Area"
                        AssessmentType = if ($nonStdXp.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271300"]
                        Status         = if ($nonStdXp.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($nonStdXp.Count -eq 0) { "None found" } else { $nonStdXp.xp_name -join ", " }
                        ExpectedValue  = "No non-Microsoft extended stored procedures"
                        Remediation    = "Remove unauthorized extended SPs: sp_dropextendedproc '<proc_name>';"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-007400 (V-271300)"
                        SqlQuery       = $stigSql["V-271300"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271300: $($_.Exception.Message)" }

                # V-271303 — Non-standard TCP port (informational)
                try {
                    $tcpPort = Get-DbaTcpPort @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    $port    = if ($tcpPort) { $tcpPort.Port } else { -1 }
                    $splatCheck = @{
                        CheckId        = "V-271303"
                        CheckName      = "PPSM-Compliant Port"
                        Category       = "Surface Area"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271303"]
                        Status         = "Manual"
                        CurrentValue   = if ($port -gt 0) { "Port $port" } else { "Dynamic ports or unknown" }
                        ExpectedValue  = "Port compliant with PPSM CAL and documented"
                        Remediation    = "Verify the port in use is documented and authorized per PPSM guidance. Default SQL Server port 1433 is generally acceptable."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-007600 (V-271303)"
                        SqlQuery       = $stigSql["V-271303"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271303: $($_.Exception.Message)" }

                # V-271304 — Protocols restricted (Named Pipes / VIA disabled)
                try {
                    $protos = Get-DbaInstanceProtocol @connSplat -WarningAction SilentlyContinue
                    $enabledProtos = @($protos | Where-Object { $_.IsEnabled -and $_.Name -notmatch '^(tcp|sm)$' })
                    $splatCheck = @{
                        CheckId        = "V-271304"
                        CheckName      = "Non-Standard Protocols Disabled"
                        Category       = "Surface Area"
                        AssessmentType = if ($null -ne $protos) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271304"]
                        Status         = if ($null -eq $protos) { "Manual" } elseif ($enabledProtos.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($null -eq $protos) { "Could not read protocols" } elseif ($enabledProtos.Count -eq 0) { "Only TCP and Shared Memory enabled" } else { "Also enabled: $($enabledProtos.Name -join ', ')" }
                        ExpectedValue  = "Only TCP (and Shared Memory for local) — Named Pipes and VIA disabled unless documented"
                        Remediation    = "In SQL Server Configuration Manager > Protocols, disable Named Pipes, VIA, and any other non-authorized protocols."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-007600 (V-271304)"
                        SqlQuery       = $stigSql["V-271304"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271304: $($_.Exception.Message)" }

                # V-271359 — CLR execution domain (same config as V-271301)
                try {
                    $clrCfg = Get-DbaSpConfigure @connSplat -Name 'clr enabled' -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($clrCfg) {
                        $splatCheck = @{
                            CheckId        = "V-271359"
                            CheckName      = "CLR Execution Domain Isolated"
                            Category       = "Surface Area"
                            AssessmentType = "Automated"
                            Priority       = $stigPriority["V-271359"]
                            Status         = if ($clrCfg.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $clrCfg.RunningValue.ToString()
                            ExpectedValue  = "0 (CLR disabled)"
                            Remediation    = "EXEC sp_configure 'clr enabled', 0; RECONFIGURE WITH OVERRIDE;"
                            Reference      = "DISA STIG SQL Server 2022 SQLI-22-012300 (V-271359)"
                            SqlQuery       = $stigSql["V-271359"]
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] V-271359: $($_.Exception.Message)" }

                # V-274446 — Startup stored procedures restricted
                try {
                    $startupQ   = "SELECT name AS StoredProc FROM sys.procedures WHERE OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1;"
                    $startupSPs = @(Invoke-DbaQuery @connSplat -Query $startupQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-274446"
                        CheckName      = "Startup Stored Procedures Restricted"
                        Category       = "Surface Area"
                        AssessmentType = if ($startupSPs.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-274446"]
                        Status         = if ($startupSPs.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($startupSPs.Count -eq 0) { "None" } else { $startupSPs.StoredProc -join ", " }
                        ExpectedValue  = "No startup procedures, or each is documented and authorized"
                        Remediation    = "Review each startup SP. Disable unauthorized ones: sp_procoption '<name>', 'startup', 'off';"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016400 (V-274446)"
                        SqlQuery       = $stigSql["V-274446"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274446: $($_.Exception.Message)" }
            }

            # ── §4 Encryption & Transport Security ────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Encryption"

                # V-271310 — TLS 1.2 required; TLS 1.0/1.1/SSL 2.0/3.0 disabled
                # No dbatools equivalent — registry check via Invoke-Command
                try {
                    $tlsResult = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        $base   = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
                        $issues = @()

                        foreach ($sub in @('Client','Server')) {
                            $tls12Key = Join-Path $base "TLS 1.2\$sub"
                            if (-not (Test-Path $tls12Key)) {
                                $issues += "TLS 1.2\$sub key missing"
                            } else {
                                $props = Get-ItemProperty -Path $tls12Key -ErrorAction SilentlyContinue
                                if ($props.DisabledByDefault -ne 0) { $issues += "TLS 1.2\$sub DisabledByDefault != 0 (was $($props.DisabledByDefault))" }
                                if ($props.Enabled -ne 1)           { $issues += "TLS 1.2\$sub Enabled != 1 (was $($props.Enabled))" }
                            }
                            foreach ($proto in @('TLS 1.0','TLS 1.1','SSL 2.0','SSL 3.0')) {
                                $protoKey = Join-Path $base "$proto\$sub"
                                if (Test-Path $protoKey) {
                                    $props = Get-ItemProperty -Path $protoKey -ErrorAction SilentlyContinue
                                    if ($props.DisabledByDefault -ne 1) { $issues += "$proto\$sub DisabledByDefault != 1 (was $($props.DisabledByDefault))" }
                                    if ($props.Enabled -ne 0)           { $issues += "$proto\$sub Enabled != 0 (was $($props.Enabled))" }
                                }
                            }
                        }
                        $issues
                    } -ErrorAction SilentlyContinue

                    $splatCheck = @{
                        CheckId        = "V-271310"
                        CheckName      = "TLS 1.2 Required; Older Protocols Disabled"
                        Category       = "Encryption"
                        AssessmentType = if ($null -ne $tlsResult) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271310"]
                        Status         = if ($null -eq $tlsResult) { "Manual" } elseif ($tlsResult.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $tlsResult) { "Registry not accessible — check WinRM" } elseif ($tlsResult.Count -eq 0) { "TLS 1.2 enabled; TLS 1.0/1.1/SSL 2.0/3.0 disabled" } else { $tlsResult -join "; " }
                        ExpectedValue  = "TLS 1.2 Client+Server: DisabledByDefault=0, Enabled=1. TLS 1.0/1.1/SSL 2.0/3.0: DisabledByDefault=1, Enabled=0."
                        Remediation    = "Configure SCHANNEL registry keys under HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols. See SQLI-22-008300 for detailed steps."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-008300 (V-271310)"
                        SqlQuery       = $stigSql["V-271310"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271310: $($_.Exception.Message)" }

                # V-271314 — FIPS 140-2/3 validated crypto enabled
                # No dbatools equivalent — registry check via Invoke-Command
                try {
                    $fipsEnabled = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        $prop = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction SilentlyContinue
                        if ($prop) { $prop.Enabled } else { $null }
                    } -ErrorAction SilentlyContinue

                    $splatCheck = @{
                        CheckId        = "V-271314"
                        CheckName      = "FIPS 140-2/3 Cryptography Enabled"
                        Category       = "Encryption"
                        AssessmentType = if ($null -ne $fipsEnabled) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271314"]
                        Status         = if ($null -eq $fipsEnabled) { "Manual" } elseif ($fipsEnabled -eq 1) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $fipsEnabled) { "Registry not accessible — check WinRM" } else { "FipsAlgorithmPolicy.Enabled = $fipsEnabled" }
                        ExpectedValue  = "FipsAlgorithmPolicy.Enabled = 1"
                        Remediation    = "Enable FIPS: Local Security Policy > Local Policies > Security Options > System Cryptography: Use FIPS compliant algorithms. Restart required."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-008700 (V-271314)"
                        SqlQuery       = $stigSql["V-271314"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271314: $($_.Exception.Message)" }

                # V-271324 — Data at rest protection (TDE status)
                try {
                    $tdeData4 = Get-TdeStatus -ctx $connSplat
                    $splatCheck = @{
                        CheckId        = "V-271324"
                        CheckName      = "Data at Rest — TDE Status"
                        Category       = "Encryption"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271324"]
                        Status         = "Manual"
                        CurrentValue   = if ($tdeData4.EncryptedCount -gt 0) { "$($tdeData4.EncryptedCount) DB(s) encrypted: $($tdeData4.EncryptedNames -join ', ')" } else { "No user databases encrypted with TDE" }
                        ExpectedValue  = "All databases that handle classified/PII data encrypted (TDE or full-disk)"
                        Remediation    = "Enable TDE for databases containing classified or PII data: CREATE DATABASE ENCRYPTION KEY; ALTER DATABASE [<db>] SET ENCRYPTION ON;"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-009500 (V-271324)"
                        SqlQuery       = $stigSql["V-271324"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271324: $($_.Exception.Message)" }

                # V-274447 — Mirroring endpoint uses AES
                try {
                    $mirrorQ = "SELECT name, type_desc, encryption_algorithm_desc FROM sys.database_mirroring_endpoints WHERE encryption_algorithm != 2;"
                    $badMirror = @(Invoke-DbaQuery @connSplat -Query $mirrorQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-274447"
                        CheckName      = "Mirroring Endpoint Uses AES"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-274447"]
                        Status         = if ($badMirror.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($badMirror.Count -eq 0) { "No non-AES mirroring endpoints" } else { "Non-AES endpoints: $($badMirror.name -join ', ')" }
                        ExpectedValue  = "All mirroring endpoints use AES encryption"
                        Remediation    = "ALTER ENDPOINT [<name>] FOR DATABASE_MIRRORING (ENCRYPTION = REQUIRED ALGORITHM AES);"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016500 (V-274447)"
                        SqlQuery       = $stigSql["V-274447"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274447: $($_.Exception.Message)" }

                # V-274448 — Service Broker endpoint uses AES
                try {
                    $brokerQ = "SELECT name, type_desc, encryption_algorithm_desc FROM sys.service_broker_endpoints WHERE encryption_algorithm != 2;"
                    $badBroker = @(Invoke-DbaQuery @connSplat -Query $brokerQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-274448"
                        CheckName      = "Service Broker Endpoint Uses AES"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-274448"]
                        Status         = if ($badBroker.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($badBroker.Count -eq 0) { "No non-AES Service Broker endpoints" } else { "Non-AES endpoints: $($badBroker.name -join ', ')" }
                        ExpectedValue  = "All Service Broker endpoints use AES encryption"
                        Remediation    = "ALTER ENDPOINT [<name>] FOR SERVICE_BROKER (ENCRYPTION = REQUIRED ALGORITHM AES);"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016600 (V-274448)"
                        SqlQuery       = $stigSql["V-274448"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274448: $($_.Exception.Message)" }

                # V-274449 — xp_reg* execute permissions revoked
                try {
                    $xpRegQ = @"
SELECT OBJECT_NAME(major_id) AS [StoredProcedure], dpr.name AS [Principal]
FROM sys.database_permissions AS dp
INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
WHERE major_id IN (
    OBJECT_ID('xp_regaddmultistring'),    OBJECT_ID('xp_regdeletekey'),
    OBJECT_ID('xp_regdeletevalue'),       OBJECT_ID('xp_regenumvalues'),
    OBJECT_ID('xp_regenumkeys'),          OBJECT_ID('xp_regremovemultistring'),
    OBJECT_ID('xp_regwrite'),             OBJECT_ID('xp_instance_regaddmultistring'),
    OBJECT_ID('xp_instance_regdeletekey'),OBJECT_ID('xp_instance_regdeletevalue'),
    OBJECT_ID('xp_instance_regenumkeys'), OBJECT_ID('xp_instance_regenumvalues'),
    OBJECT_ID('xp_instance_regremovemultistring'), OBJECT_ID('xp_instance_regwrite')
)
AND dp.[type] = 'EX'
ORDER BY dpr.name;
"@
                    $xpRegPerms = @(Invoke-DbaQuery @connSplat -Query $xpRegQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-274449"
                        CheckName      = "xp_reg* Execute Permissions Revoked"
                        Category       = "Encryption"
                        AssessmentType = if ($xpRegPerms.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-274449"]
                        Status         = if ($xpRegPerms.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($xpRegPerms.Count -eq 0) { "No non-dbo principals have xp_reg* execute rights" } else { ($xpRegPerms | ForEach-Object { "$($_.Principal) -> $($_.StoredProcedure)" }) -join "; " }
                        ExpectedValue  = "Only dbo has EXECUTE on registry extended stored procedures"
                        Remediation    = "REVOKE EXECUTE ON [<xp_reg_proc>] FROM [<principal>];"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016700 (V-274449)"
                        SqlQuery       = $stigSql["V-274449"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-274449: $($_.Exception.Message)" }
            }

            # ── §5 Operational ─────────────────────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Operational"

                # V-271334 — Trace flag 3625 (error message masking)
                try {
                    $tfQ     = "DBCC TRACESTATUS(3625) WITH NO_INFOMSGS;"
                    $tfRows  = @(Invoke-DbaQuery @connSplat -Query $tfQ -WarningAction SilentlyContinue)
                    $tf3625  = @($tfRows | Where-Object { $_.TraceFlag -eq 3625 -and $_.Status -eq 1 })
                    $splatCheck = @{
                        CheckId        = "V-271334"
                        CheckName      = "Error Message Masking (TF 3625)"
                        Category       = "Operational"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271334"]
                        Status         = "Manual"
                        CurrentValue   = if ($tf3625.Count -gt 0) { "Trace flag 3625 is enabled" } else { "Trace flag 3625 is NOT enabled" }
                        ExpectedValue  = "Trace flag 3625 enabled, OR documentation that full error messages are authorized for all users"
                        Remediation    = "Enable TF 3625 in startup parameters: -T3625 in SQL Server Configuration Manager > SQL Server Properties > Startup Parameters."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-010100 (V-271334)"
                        SqlQuery       = $stigSql["V-271334"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271334: $($_.Exception.Message)" }

                # V-271342 — Credentials and proxies restricted
                try {
                    $creds  = @(Get-DbaCredential @connSplat -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271342"
                        CheckName      = "Credentials and Proxies Restricted"
                        Category       = "Operational"
                        AssessmentType = if ($creds.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271342"]
                        Status         = if ($creds.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($creds.Count -eq 0) { "No credentials defined" } else { $creds.Name -join ", " }
                        ExpectedValue  = "No credentials, or each is documented and authorized for necessary external process execution"
                        Remediation    = "Remove unauthorized credentials: DROP CREDENTIAL [<name>]; and associated proxy: msdb.dbo.sp_delete_proxy"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-010500 (V-271342)"
                        SqlQuery       = $stigSql["V-271342"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271342: $($_.Exception.Message)" }

                # V-271358 — SQL Server services use unique dedicated accounts
                try {
                    $svcData5  = Get-DbaService @connSplat -WarningAction SilentlyContinue
                    $svcAccounts = @($svcData5 | Select-Object -ExpandProperty ServiceAccount -Unique)
                    $dupAccounts = @($svcData5 | Group-Object ServiceAccount |
                        Where-Object { $_.Count -gt 1 -and $_.Name -notmatch 'LocalSystem|NetworkService|NT AUTHORITY' } |
                        Select-Object -ExpandProperty Name)
                    $splatCheck = @{
                        CheckId        = "V-271358"
                        CheckName      = "SQL Services Use Unique Dedicated Accounts"
                        Category       = "Operational"
                        AssessmentType = if ($dupAccounts.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271358"]
                        Status         = if ($dupAccounts.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($dupAccounts.Count -eq 0) { "Service accounts appear unique" } else { "Shared accounts: $($dupAccounts -join ', ')" }
                        ExpectedValue  = "Each SQL service runs under a distinct dedicated account"
                        Remediation    = "Reconfigure services sharing accounts to use individual managed service accounts (MSA or gMSA)."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-012400 (V-271358)"
                        SqlQuery       = $stigSql["V-271358"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271358: $($_.Exception.Message)" }

                # V-271365 — Supported SQL Server version
                try {
                    $build = Test-DbaBuild @connSplat -Latest -Update -WarningAction SilentlyContinue | Select-Object -First 1
                    $splatCheck = @{
                        CheckId        = "V-271365"
                        CheckName      = "Vendor-Supported SQL Server Version"
                        Category       = "Operational"
                        AssessmentType = "Automated"
                        Priority       = $stigPriority["V-271365"]
                        Status         = if ($build.Compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = $build.BuildLevel.ToString()
                        ExpectedValue  = "Current supported release"
                        Remediation    = "Apply current CU/SP: $($build.CUTarget). SQL Server 2022 mainstream support ends January 2028."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-018300 (V-271365)"
                        SqlQuery       = $stigSql["V-271365"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271365: $($_.Exception.Message)" }

                # V-271387 — SQL Server Browser service disabled
                try {
                    $browser = Get-DbaService @connSplat -Type Browser -WarningAction SilentlyContinue | Select-Object -First 1
                    $browserDisabled = $null -eq $browser -or $browser.StartMode -eq 'Disabled'
                    $splatCheck = @{
                        CheckId        = "V-271387"
                        CheckName      = "SQL Browser Service Disabled"
                        Category       = "Operational"
                        AssessmentType = if ($null -ne $browser) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271387"]
                        Status         = if ($null -eq $browser) { "Manual" } elseif ($browserDisabled) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($null -eq $browser) { "Could not determine Browser service state" } elseif ($browserDisabled) { "Disabled" } else { "StartMode = $($browser.StartMode); State = $($browser.State)" }
                        ExpectedValue  = "Disabled, or hidden instance with justification documented"
                        Remediation    = "Disable SQL Browser via Services.msc or SQL Server Configuration Manager unless documented justification exists."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-017800 (V-271387)"
                        SqlQuery       = $stigSql["V-271387"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271387: $($_.Exception.Message)" }

                # V-271388 — Telemetry audit directory configured
                # No dbatools equivalent — registry check
                try {
                    $instId = Invoke-DbaQuery @connSplat -Query "SELECT SERVERPROPERTY('InstanceName') AS InstanceName, SERVERPROPERTY('Edition') AS Edition;" -WarningAction SilentlyContinue | Select-Object -First 1
                    $instName = if ($instId -and $instId.InstanceName) { $instId.InstanceName } else { "MSSQLSERVER" }
                    $telemetryResult = Invoke-Command -ComputerName $computerName -ArgumentList $instName -ScriptBlock {
                        param ($inst)
                        $cpePaths = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -match "MSSQL\d+\.$inst" } |
                            ForEach-Object { "$($_.Name)\CPE" }
                        foreach ($path in $cpePaths) {
                            $regPath = $path -replace 'HKEY_LOCAL_MACHINE', 'HKLM:'
                            $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                            if ($props -and $props.UserRequestedLocalAuditDirectory) {
                                return $props.UserRequestedLocalAuditDirectory
                            }
                        }
                        return $null
                    } -ErrorAction SilentlyContinue

                    $splatCheck = @{
                        CheckId        = "V-271388"
                        CheckName      = "Telemetry Audit Directory Configured"
                        Category       = "Operational"
                        AssessmentType = if ($null -ne $telemetryResult) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271388"]
                        Status         = if ($null -eq $telemetryResult) { "Manual" } elseif ($telemetryResult) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($null -eq $telemetryResult) { "Registry not accessible" } elseif ($telemetryResult) { $telemetryResult } else { "UserRequestedLocalAuditDirectory not configured" }
                        ExpectedValue  = "UserRequestedLocalAuditDirectory registry value set with SQLTELEMETRY service write permissions"
                        Remediation    = "Create a folder and set HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceId]\CPE\UserRequestedLocalAuditDirectory to that path. Grant SQLTELEMETRY service read/write permissions."
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016100 (V-271388)"
                        SqlQuery       = $stigSql["V-271388"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271388: $($_.Exception.Message)" }

                # V-271389 — Customer feedback / error reporting disabled on classified systems
                # No dbatools equivalent — registry check
                try {
                    $ceipResult = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        $issues = @()
                        $sqlPaths = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -match 'MSSQL\d+\.' }
                        foreach ($sqlPath in $sqlPaths) {
                            $cpePath = Join-Path ($sqlPath.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM:') 'CPE'
                            $props = Get-ItemProperty -Path $cpePath -ErrorAction SilentlyContinue
                            if ($props -and ($props.CustomerFeedback -eq 1 -or $props.EnableErrorReporting -eq 1)) {
                                $issues += "$(Split-Path $sqlPath.Name -Leaf)\CPE: CustomerFeedback=$($props.CustomerFeedback) EnableErrorReporting=$($props.EnableErrorReporting)"
                            }
                        }
                        $p160 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\160' -ErrorAction SilentlyContinue
                        if ($p160 -and ($p160.CustomerFeedback -eq 1 -or $p160.EnableErrorReporting -eq 1)) {
                            $issues += "160: CustomerFeedback=$($p160.CustomerFeedback) EnableErrorReporting=$($p160.EnableErrorReporting)"
                        }
                        $issues
                    } -ErrorAction SilentlyContinue

                    $splatCheck = @{
                        CheckId        = "V-271389"
                        CheckName      = "Customer Feedback / Error Reporting Configured"
                        Category       = "Operational"
                        AssessmentType = if ($null -ne $ceipResult) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271389"]
                        Status         = if ($null -eq $ceipResult) { "Manual" } elseif ($ceipResult.Count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($null -eq $ceipResult) { "Registry not accessible" } elseif ($ceipResult.Count -eq 0) { "CustomerFeedback and EnableErrorReporting = 0" } else { $ceipResult -join "; " }
                        ExpectedValue  = "CustomerFeedback = 0, EnableErrorReporting = 0 (required on classified systems; review authorization on unclassified)"
                        Remediation    = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceId]\CPE' -Name CustomerFeedback -Value 0; (repeat for EnableErrorReporting and the \160 path)"
                        Reference      = "DISA STIG SQL Server 2022 SQLI-22-016000 (V-271389)"
                        SqlQuery       = $stigSql["V-271389"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271389: $($_.Exception.Message)" }
            }

            # ── §6 Database-Level Checks ────────────────────────────────────
            if (ShouldRun "6") {
                Write-Verbose "[$instance] §6 Database"
                $userDbs6 = @(Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue)

                # V-271118 — DB auth: SQL users documented and authorized
                try {
                    $sqlUserQ = "SELECT name FROM sys.database_principals WHERE type_desc = 'SQL_USER' AND authentication_type_desc = 'DATABASE';"
                    $allSqlDbUsers = @()
                    foreach ($db6 in $userDbs6) {
                        $splatQ6 = @{ Database = $db6.Name }
                        $rows = @(Invoke-DbaQuery @connSplat @splatQ6 -Query $sqlUserQ -WarningAction SilentlyContinue)
                        foreach ($r in $rows) {
                            $allSqlDbUsers += [PSCustomObject]@{ DatabaseName = $db6.Name; UserName = $r.name }
                        }
                    }
                    $splatCheck = @{
                        CheckId        = "V-271118"
                        CheckName      = "DB SQL Authentication Users Authorized"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($allSqlDbUsers.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271118"]
                        Status         = if ($allSqlDbUsers.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($allSqlDbUsers.Count -eq 0) { "No SQL_USER (DATABASE auth) principals in user DBs" } else { ($allSqlDbUsers | ForEach-Object { "$($_.DatabaseName)\$($_.UserName)" }) -join ", " }
                        ExpectedValue  = "No SQL auth database users, or each is documented and authorized"
                        Remediation    = "Replace SQL auth DB users with Windows principal mappings. See SQLD-22-000100."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-000100 (V-271118)"
                        SqlQuery       = $stigSql["V-271118"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271118: $($_.Exception.Message)" }

                # V-271122 — Trustworthy databases restricted
                try {
                    $trustDbs6 = @(Get-DbaDatabase @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -ne "msdb" -and $_.Trustworthy -eq $true })
                    $splatCheck = @{
                        CheckId        = "V-271122"
                        CheckName      = "Trustworthy Databases Restricted"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($trustDbs6.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271122"]
                        Status         = if ($trustDbs6.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($trustDbs6.Count -eq 0) { "None (excluding msdb)" } else { $trustDbs6.Name -join ", " }
                        ExpectedValue  = "No user databases with TRUSTWORTHY = ON (unless documented and the owner is not privileged)"
                        Remediation    = "ALTER DATABASE [<db>] SET TRUSTWORTHY OFF; unless a documented exception exists."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-000600 (V-271122)"
                        SqlQuery       = $stigSql["V-271122"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271122: $($_.Exception.Message)" }

                # V-271147 — DDL permissions restricted
                try {
                    $ddlQ = @"
SELECT DB_NAME() AS DatabaseName, P.name AS principal_name, P.type_desc, DP.permission_name
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
UNION ALL
SELECT DB_NAME(), M.name, M.type_desc, 'Member of ' + R.name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db_ddladmin','db_owner') AND M.name <> 'dbo';
"@
                    $ddlPerms = @()
                    foreach ($db6 in $userDbs6) {
                        $splatQ6 = @{ Database = $db6.Name }
                        $rows = @(Invoke-DbaQuery @connSplat @splatQ6 -Query $ddlQ -WarningAction SilentlyContinue)
                        $ddlPerms += $rows
                    }
                    $splatCheck = @{
                        CheckId        = "V-271147"
                        CheckName      = "DDL Permissions Restricted"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($ddlPerms.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271147"]
                        Status         = if ($ddlPerms.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($ddlPerms.Count -eq 0) { "No non-dbo ALTER or db_ddladmin/db_owner memberships" } else { "$($ddlPerms.Count) principal(s) with DDL access across $($userDbs6.Count) user DB(s)" }
                        ExpectedValue  = "Only documented authorized principals have ALTER/db_ddladmin/db_owner"
                        Remediation    = "Review and REVOKE ALTER permissions or remove db_ddladmin/db_owner memberships for unauthorized principals."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-001400 (V-271147)"
                        SqlQuery       = $stigSql["V-271147"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271147: $($_.Exception.Message)" }

                # V-271168 — Backup/recovery plan exists (evidence check)
                try {
                    $backupHist = Get-DbaDbBackupHistory @connSplat -Last -WarningAction SilentlyContinue
                    $dbsWithBackup  = @($backupHist | Select-Object -ExpandProperty Database -Unique)
                    $dbsNeedBackup  = @($userDbs6 | Where-Object { $_.Name -notin $dbsWithBackup })
                    $splatCheck = @{
                        CheckId        = "V-271168"
                        CheckName      = "Backup/Recovery Plan — Recent Backup Evidence"
                        Category       = "DatabaseLevel"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271168"]
                        Status         = "Manual"
                        CurrentValue   = if ($dbsNeedBackup.Count -eq 0) { "All user DBs have backup history" } else { "No backup history for: $($dbsNeedBackup.Name -join ', ')" }
                        ExpectedValue  = "All user databases have recent backups; recovery tested annually; recovery model matches documentation"
                        Remediation    = "Establish and document a backup schedule for all user databases. Test recovery annually."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-001500 (V-271168)"
                        SqlQuery       = $stigSql["V-271168"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271168: $($_.Exception.Message)" }

                # V-271170 — Database Master Key encrypted by Service Master Key (requires review)
                try {
                    $dmkQ   = "SELECT name FROM [master].sys.databases WHERE is_master_key_encrypted_by_server = 1 AND state = 0;"
                    $dmkDbs = @(Invoke-DbaQuery @connSplat -Query $dmkQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271170"
                        CheckName      = "Database Master Key Encryption Review"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($dmkDbs.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271170"]
                        Status         = if ($dmkDbs.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($dmkDbs.Count -eq 0) { "No databases with DMK encrypted by SMK" } else { "DMK encrypted by SMK in: $($dmkDbs.name -join ', ')" }
                        ExpectedValue  = "DMK encrypted by password (not SMK), or SMK encryption is approved with additional audit controls"
                        Remediation    = "Where possible, re-encrypt DMK with a strong password: ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '<pwd>'; then DROP ENCRYPTION BY SERVICE MASTER KEY."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-001700 (V-271170)"
                        SqlQuery       = $stigSql["V-271170"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271170: $($_.Exception.Message)" }

                # V-271188 — EXECUTE AS usage restricted
                try {
                    $execAsQ = @"
SELECT DB_NAME() AS DatabaseName, S.name AS schema_name, O.name AS module_name,
       USER_NAME(CASE M.execute_as_principal_id WHEN -2 THEN COALESCE(O.principal_id, S.principal_id) ELSE M.execute_as_principal_id END) AS execute_as
FROM sys.sql_modules M
JOIN sys.objects O ON M.object_id = O.object_id
JOIN sys.schemas S ON O.schema_id = S.schema_id
WHERE M.execute_as_principal_id IS NOT NULL
  AND O.name NOT IN (
    'fn_sysdac_get_username','sp_send_dbmail','sp_SendMailMessage',
    'sp_syscollector_create_collection_set','sp_syscollector_delete_collection_set',
    'sp_syscollector_enable_collector','sp_syscollector_run_collection_set',
    'sp_syspolicy_add_policy','sp_syspolicy_delete_policy',
    'sp_syspolicy_update_policy','sysmail_help_status_sp'
  );
"@
                    $execAsItems = @()
                    foreach ($db6 in $userDbs6) {
                        $splatQ6 = @{ Database = $db6.Name }
                        $execAsItems += @(Invoke-DbaQuery @connSplat @splatQ6 -Query $execAsQ -WarningAction SilentlyContinue)
                    }
                    $splatCheck = @{
                        CheckId        = "V-271188"
                        CheckName      = "EXECUTE AS Usage Restricted"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($execAsItems.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271188"]
                        Status         = if ($execAsItems.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($execAsItems.Count -eq 0) { "No non-system EXECUTE AS modules found" } else { "$($execAsItems.Count) module(s) with EXECUTE AS" }
                        ExpectedValue  = "No undocumented EXECUTE AS in stored procedures or functions"
                        Remediation    = "Review each EXECUTE AS module. Remove EXECUTE AS from any that are not documented and authorized."
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-002900 (V-271188)"
                        SqlQuery       = $stigSql["V-271188"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271188: $($_.Exception.Message)" }

                # V-271195 — Database owners not in fixed server roles
                try {
                    $dbOwnerQ = @"
SELECT D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name,
       MAX(IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid))) AS is_fixed_role_member
FROM sys.databases D
CROSS JOIN (SELECT name FROM sys.server_principals WHERE is_fixed_role = 1) R
WHERE D.database_id > 4
GROUP BY D.name, D.owner_sid
HAVING MAX(IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid))) = 1;
"@
                    $privOwners = @(Invoke-DbaQuery @connSplat -Query $dbOwnerQ -WarningAction SilentlyContinue)
                    $splatCheck = @{
                        CheckId        = "V-271195"
                        CheckName      = "DB Owners Not in Fixed Server Roles"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($privOwners.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-271195"]
                        Status         = if ($privOwners.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($privOwners.Count -eq 0) { "No user DBs owned by fixed server role members" } else { ($privOwners | ForEach-Object { "$($_.database_name) owned by $($_.owner_name)" }) -join "; " }
                        ExpectedValue  = "User database owners are not members of fixed server roles (sysadmin, securityadmin, etc.)"
                        Remediation    = "ALTER AUTHORIZATION ON DATABASE::[<db>] TO [<non-privileged-login>];"
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-003100 (V-271195)"
                        SqlQuery       = $stigSql["V-271195"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271195: $($_.Exception.Message)" }

                # V-271199 / V-271201 — FIPS and TDE (reference V-271314 and V-271324 results)
                $splatCheck = @{
                    CheckId        = "V-271199"
                    CheckName      = "NSA-Approved Crypto for Classified Data"
                    Category       = "DatabaseLevel"
                    AssessmentType = "Manual"
                    Priority       = $stigPriority["V-271199"]
                    Status         = "Manual"
                    CurrentValue   = "See V-271314 (FIPS) result for registry-level FIPS status"
                    ExpectedValue  = "FIPS enabled; symmetric key algorithms AES_256 or 3DES; see V-271314"
                    Remediation    = "Enable FIPS (see V-271314). Use only AES_256 or Triple DES for symmetric keys: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE key_algorithm NOT IN ('D3','A3');"
                    Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-003200 (V-271199)"
                    SqlQuery       = $stigSql["V-271199"]
                }
                & $emit (New-DakCheckResult @sharedParams @splatCheck)

                try {
                    $tdeDb6 = Get-TdeStatus -ctx $connSplat
                    $splatCheck = @{
                        CheckId        = "V-271201"
                        CheckName      = "Encryption for Data at Rest (DB Level)"
                        Category       = "DatabaseLevel"
                        AssessmentType = "Manual"
                        Priority       = $stigPriority["V-271201"]
                        Status         = "Manual"
                        CurrentValue   = if ($tdeDb6.EncryptedCount -gt 0) { "$($tdeDb6.EncryptedCount) encrypted: $($tdeDb6.EncryptedNames -join ', ')" } else { "No user databases encrypted with TDE" }
                        ExpectedValue  = "Databases containing PII or classified data must be encrypted (TDE or full-disk)"
                        Remediation    = "Enable TDE for each database requiring protection. CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE; ALTER DATABASE [<db>] SET ENCRYPTION ON;"
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-003300 (V-271201)"
                        SqlQuery       = $stigSql["V-271201"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-271201: $($_.Exception.Message)" }

                # V-283667 — No computer accounts (ending with $) in user databases
                try {
                    $compAcctQ = "SELECT DB_NAME() AS DatabaseName, name FROM sys.database_principals WHERE type IN ('U','G') AND name LIKE '%`$';"
                    $compAccts = @()
                    foreach ($db6 in $userDbs6) {
                        $splatQ6 = @{ Database = $db6.Name }
                        $compAccts += @(Invoke-DbaQuery @connSplat @splatQ6 -Query $compAcctQ -WarningAction SilentlyContinue)
                    }
                    $splatCheck = @{
                        CheckId        = "V-283667"
                        CheckName      = "No Computer Accounts in User Databases"
                        Category       = "DatabaseLevel"
                        AssessmentType = if ($compAccts.Count -eq 0) { "Automated" } else { "Manual" }
                        Priority       = $stigPriority["V-283667"]
                        Status         = if ($compAccts.Count -eq 0) { "Pass" } else { "Manual" }
                        CurrentValue   = if ($compAccts.Count -eq 0) { "No computer accounts (ending in `$) found" } else { ($compAccts | ForEach-Object { "$($_.DatabaseName): $($_.name)" }) -join "; " }
                        ExpectedValue  = "No computer account principals in user databases"
                        Remediation    = "Verify each account ending in $ is not a computer account. If it is, remove it: DROP USER [<domain\computer`$>];"
                        Reference      = "DISA STIG SQL Server 2022 Database SQLD-22-004250 (V-283667)"
                        SqlQuery       = $stigSql["V-283667"]
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] V-283667: $($_.Exception.Message)" }
            }
        }
    }
}
