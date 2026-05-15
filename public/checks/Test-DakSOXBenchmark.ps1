function Test-DakSOXBenchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against SOX IT General Controls.

    .DESCRIPTION
        Evaluates SQL Server configuration and operational state against
        Sarbanes-Oxley (SOX) Section 404 IT general control requirements.
        Returns one result object per check per instance (type: DakSqlKit.AuditResult).

        SOX IT general controls assessed:
            §1 — Access & Identity Controls   ( 8 checks: SOX-1.1–1.8)
            §2 — Audit & Logging              ( 6 checks: SOX-2.1–2.6)
            §3 — Change Management            ( 5 checks: SOX-3.1–3.5)
            §4 — Data Integrity & Recovery    ( 8 checks: SOX-4.1–4.8)
            §5 — Encryption                   ( 4 checks: SOX-5.1–5.4)

        AssessmentType on each result:
            Automated — pass/fail determined by the tool
            Manual    — tool collected evidence; a human must determine compliance

        Manual results always have Compliant = $null and a Remediation note with the
        audit procedure the reviewer must perform.

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        SOX sections to run: 1–5, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

    .PARAMETER Quiet
        Suppress console progress output.

    .EXAMPLE
        Test-DakSOXBenchmark -SqlInstance 'SQLPROD01'

    .EXAMPLE
        Test-DakSOXBenchmark -SqlInstance 'SQLPROD01' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Get-DbaRegisteredServer -Group Production | Test-DakSOXBenchmark -Section 1,2
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("1", "2", "3", "4", "5", "All")]
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

        $soxPriority = @{
            "1.1"  = "High"     # Mixed mode bypasses AD — SOX access provisioning becomes unenforceable
            "1.2"  = "High"     # Enabled sa is an always-present privileged target
            "1.3"  = "Medium"   # sa name is universally known; rename reduces targeted attack risk
            "1.4"  = "High"     # BUILTIN groups give all local admins SQL access outside provisioning
            "1.5"  = "Medium"   # Guest bypasses the formal user provisioning process
            "1.6"  = "High"     # Weak password policy undermines SOX access control objectives
            "1.7"  = "High"     # Unexpired privileged passwords are an access control gap
            "1.8"  = "Critical" # Sysadmin = unrestricted change capability; must be formally certified
            "2.1"  = "Critical" # Audit trail is the primary SOX detective control
            "2.2"  = "High"     # Capturing only success hides failed access attempts
            "2.3"  = "Medium"   # Short retention limits the forensic investigation window
            "2.4"  = "Low"      # Default trace provides baseline change evidence
            "2.5"  = "High"     # Role membership changes must be attributable and auditable
            "2.6"  = "High"     # Schema changes to financial objects must be tracked
            "3.1"  = "Medium"   # Ownerless jobs have no change accountability chain
            "3.2"  = "Medium"   # No operator means no notification for critical operational failures
            "3.3"  = "High"     # Severity 19-25 errors indicate data-threatening conditions
            "3.4"  = "Medium"   # I/O errors 823/824/825 indicate potential silent data corruption
            "3.5"  = "Low"      # Database Mail is the delivery mechanism for operator alerts
            "4.1"  = "Critical" # Missing backups means no recovery — SOX availability control failure
            "4.2"  = "High"     # Unvalidated integrity is a SOX data quality risk
            "4.3"  = "High"     # Inaccessible databases mean SOX-scope data is unavailable
            "4.4"  = "High"     # Simple recovery model prevents point-in-time restore
            "4.5"  = "High"     # Long RPO gap defeats the purpose of a full recovery model
            "4.6"  = "Medium"   # CHECKSUM detects page corruption before it causes permanent loss
            "4.7"  = "Low"      # AUTO_CLOSE flushes connections without notice — availability risk
            "4.8"  = "Medium"   # AUTO_SHRINK causes fragmentation and unexpected I/O load
            "5.1"  = "High"     # Unencrypted connections expose financial data in transit
            "5.2"  = "High"     # Unencrypted backups of financial data violate SOX data security
            "5.3"  = "Medium"   # TDE scope is environment-specific; requires manual scope review
            "5.4"  = "Low"      # Weak symmetric key algorithms undermine data protection controls
        }
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) { Write-Host "SOX IT General Controls — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] SOX assessment — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "SOX"
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
                if (-not $Quiet) { Write-Host ("  [{0,-7}] {1,-55} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Manual", "Error") {
                    $r
                }
            }

            # ── §1 Access & Identity Controls ─────────────────────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Access & Identity"

                # SOX-1.1 Windows-only auth — SQL logins bypass Active Directory provisioning controls.
                try {
                    $authMode = Get-DbaInstanceProperty @connSplat -InstanceProperty LoginMode -WarningAction SilentlyContinue | Select-Object -First 1
                    $winOnly  = ($authMode.Value -eq 1)
                    $splatCheck = @{
                        CheckId        = "SOX-1.1"
                        CheckName      = "Windows-Only Authentication"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.1"]
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only (LoginMode = 1)"
                        Remediation    = "Mixed mode allows SQL logins that exist outside AD and bypass de-provisioning. Change to Windows Authentication: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- Restart required."
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Automated via Get-DbaInstanceProperty (SMO LoginMode). T-SQL: SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.1: $($_.Exception.Message)" }

                # SOX-1.2 sa login disabled — SID 0x01 catches renamed sa accounts.
                try {
                    $saLogin12 = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Sid.Length -eq 1 -and $_.Sid[0] -eq 1 } |
                        Select-Object -First 1
                    $enabled = $saLogin12 -and -not $saLogin12.IsDisabled
                    $splatCheck = @{
                        CheckId        = "SOX-1.2"
                        CheckName      = "sa Login Disabled"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.2"]
                        Status         = if (-not $enabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($enabled) { "Enabled (name: $($saLogin12.Name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "Disable the sa account: USE [master]; DECLARE @n NVARCHAR(256) = SUSER_NAME(0x01); EXEC ('ALTER LOGIN [' + @n + '] DISABLE');"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Automated via Get-DbaLogin (SID 0x01 lookup). T-SQL: SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.2: $($_.Exception.Message)" }

                # SOX-1.3 sa login renamed — well-known account name is a direct attack target.
                try {
                    $saLogin13 = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Sid.Length -eq 1 -and $_.Sid[0] -eq 1 } |
                        Select-Object -First 1
                    if ($saLogin13) {
                        $splatCheck = @{
                            CheckId        = "SOX-1.3"
                            CheckName      = "sa Login Renamed"
                            Category       = "Access Control"
                            AssessmentType = "Automated"
                            Priority       = $soxPriority["1.3"]
                            Status         = if ($saLogin13.Name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saLogin13.Name
                            ExpectedValue  = "Any name other than 'sa'"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "SOX §404 — Logical Access Controls"
                            SqlQuery       = "-- Automated via Get-DbaLogin (SID 0x01 lookup). T-SQL: SELECT name FROM sys.server_principals WHERE sid = 0x01;  -- Name should not be 'sa'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOX-1.3: $($_.Exception.Message)" }

                # SOX-1.4 No BUILTIN groups — membership outside SQL Server control violates SOX provisioning.
                try {
                    $builtins = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -like "BUILTIN\*" }
                    $count = if ($builtins) { @($builtins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-1.4"
                        CheckName      = "BUILTIN Groups Absent"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.4"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtins.Name -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "BUILTIN groups grant SQL access to all local admins outside SQL Server's provisioning process. Confirm domain group equivalents exist, then: USE [master]; DROP LOGIN [BUILTIN\Administrators];"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Automated via Get-DbaLogin. T-SQL: SELECT name FROM sys.server_principals WHERE name LIKE 'BUILTIN%';  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.4: $($_.Exception.Message)" }

                # SOX-1.5 Guest CONNECT revoked — bypasses formal user provisioning.
                try {
                    $guestDbs = Get-DbaDbUser @connSplat -ExcludeDatabase master, msdb, tempdb -User "guest" -WarningAction SilentlyContinue |
                        Where-Object { $_.HasDbAccess -eq $true }
                    $count = if ($guestDbs) { @($guestDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-1.5"
                        CheckName      = "Guest Access Revoked"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.5"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "Revoked in all user databases" } else { "Active in: $($guestDbs.Database -join ', ')" }
                        ExpectedValue  = "CONNECT revoked in all user databases"
                        Remediation    = "USE [<database>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Automated via Get-DbaDbUser. T-SQL per user DB: SELECT permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.5: $($_.Exception.Message)" }

                # SOX-1.6 SQL logins enforce password policy — weak passwords undermine access controls.
                try {
                    $noPolicy = Get-DbaLogin @connSplat -Type SQL -WarningAction SilentlyContinue |
                        Where-Object { -not $_.PasswordPolicyEnforced }
                    $count = if ($noPolicy) { @($noPolicy).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-1.6"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.6"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count logins without CHECK_POLICY" }
                        ExpectedValue  = "CHECK_POLICY = ON for all SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON;  -- Enumerate: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Automated via Get-DbaLogin (PasswordPolicyEnforced). T-SQL: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.6: $($_.Exception.Message)" }

                # SOX-1.7 Privileged SQL logins enforce password expiration.
                # No dbatools equivalent for the sysadmin+CONTROL SERVER UNION — using Invoke-DbaQuery.
                try {
                    $expQuery = @"
SELECT l.name, 'sysadmin' AS Reason
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin', l.name) = 1
  AND l.is_expiration_checked = 0 AND l.is_disabled = 0
UNION ALL
SELECT l.name, 'CONTROL SERVER' AS Reason
FROM sys.sql_logins AS l
JOIN sys.server_permissions p ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL' AND p.state IN ('G','W')
  AND l.is_expiration_checked = 0 AND l.is_disabled = 0;
"@
                    $expRows = Invoke-DbaQuery @connSplat -Query $expQuery -WarningAction SilentlyContinue
                    $count   = if ($expRows) { @($expRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-1.7"
                        CheckName      = "Privileged Login Password Expiration"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["1.7"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count privileged logins without CHECK_EXPIRATION" }
                        ExpectedValue  = "CHECK_EXPIRATION = ON for all privileged SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = $expQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.7: $($_.Exception.Message)" }

                # SOX-1.8 Sysadmin membership — Manual: auditors must review and formally certify the list.
                try {
                    $builtinFilter = @('NT SERVICE\SQLWriter','NT SERVICE\Winmgmt','NT SERVICE\MSSQLSERVER','NT SERVICE\SQLSERVERAGENT')
                    $sysadmins = Get-DbaServerRoleMember @connSplat -ServerRole sysadmin -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -notin $builtinFilter -and $_.Name -notlike '##*' }
                    $count = if ($sysadmins) { @($sysadmins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-1.8"
                        CheckName      = "Sysadmin Membership Review"
                        Category       = "Access Control"
                        AssessmentType = "Manual"
                        Priority       = $soxPriority["1.8"]
                        Status         = "Manual"
                        CurrentValue   = "$count non-system accounts with sysadmin"
                        ExpectedValue  = "Each account documented, justified, and recertified at least annually"
                        Remediation    = "Review all members: SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%'. Remove any not formally approved: ALTER SERVER ROLE sysadmin DROP MEMBER [<account>];"
                        Reference      = "SOX §404 — Privileged Access Review"
                        SqlQuery       = "-- Automated via Get-DbaServerRoleMember. T-SQL: SELECT DISTINCT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-1.8: $($_.Exception.Message)" }
            }

            # ── §2 Audit & Logging ────────────────────────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Audit & Logging"

                # SOX-2.1 SQL Server Audit — required action groups for SOX detective controls.
                try {
                    $auditQuery = @"
SELECT SAD.audit_action_name, S.is_state_enabled AS AuditEnabled, SA.is_state_enabled AS SpecEnabled
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('LGFL','LGSD','ADDP','ADSP','CNAU');
"@
                    $auditRows   = Invoke-DbaQuery @connSplat -Query $auditQuery -WarningAction SilentlyContinue
                    $required    = @(
                        "FAILED_LOGIN_GROUP",
                        "SUCCESSFUL_LOGIN_GROUP",
                        "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
                        "SERVER_ROLE_MEMBER_CHANGE_GROUP",
                        "AUDIT_CHANGE_GROUP"
                    )
                    $foundGroups = if ($auditRows) {
                        @($auditRows | Where-Object { $_.AuditEnabled -and $_.SpecEnabled } |
                            Select-Object -ExpandProperty audit_action_name -Unique)
                    } else { @() }
                    $missing   = $required | Where-Object { $_ -notin $foundGroups }
                    $compliant = $missing.Count -eq 0
                    $splatCheck = @{
                        CheckId        = "SOX-2.1"
                        CheckName      = "SQL Server Audit — SOX Action Groups"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["2.1"]
                        Status         = if ($compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($foundGroups.Count -eq 0) { "No enabled audit" } else { "$($foundGroups.Count) of $($required.Count) required groups captured" }
                        ExpectedValue  = "All 5 SOX action groups enabled in an active audit and specification"
                        Remediation    = if ($compliant) { $null } else { "Missing groups: $($missing -join ', '). Create a SERVER AUDIT targeted to a protected file path and a SERVER AUDIT SPECIFICATION covering these action groups. See: CREATE SERVER AUDIT / CREATE SERVER AUDIT SPECIFICATION." }
                        Reference      = "SOX §404 — Audit Trail"
                        SqlQuery       = $auditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-2.1: $($_.Exception.Message)" }

                # SOX-2.2 Login audit level — failure events are the minimum for SOX detective controls.
                try {
                    $auditLevel = Invoke-DbaQuery @connSplat -Query "EXEC xp_loginconfig 'audit level';" -WarningAction SilentlyContinue
                    $rawLevel   = if ($auditLevel -and $auditLevel[0]) { $auditLevel[0].config_value } else { $null }
                    $level      = if ($null -ne $rawLevel) { $rawLevel.Trim() } else { "none" }
                    $splatCheck = @{
                        CheckId        = "SOX-2.2"
                        CheckName      = "Login Audit Level"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["2.2"]
                        Status         = if ($level -in "all", "failure") { "Pass" } else { "Fail" }
                        CurrentValue   = $level
                        ExpectedValue  = "failure or all"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 2  -- 2 = failure, 3 = all. SQL Server service restart required."
                        Reference      = "SOX §404 — Audit Trail"
                        SqlQuery       = "EXEC xp_loginconfig 'audit level';  -- config_value should be 'failure' or 'all'"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-2.2: $($_.Exception.Message)" }

                # SOX-2.3 Error log retention >= 12 — SOX audit windows commonly require 12 months.
                try {
                    $logCfg  = Get-DbaErrorLogConfig @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    $rawCount = if ($logCfg) { $logCfg.LogCount } else { -1 }
                    $count    = if ($rawCount -lt 0) { 6 } else { $rawCount }
                    $display  = if ($rawCount -lt 0) { "default (6) — registry key absent" } else { $count.ToString() }
                    $splatCheck = @{
                        CheckId        = "SOX-2.3"
                        CheckName      = "Error Log Retention"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["2.3"]
                        Status         = if ($count -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $display
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12"
                        Reference      = "SOX §404 — Audit Trail Retention"
                        SqlQuery       = "-- Automated via Get-DbaErrorLogConfig. T-SQL: DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, 6) AS NumberOfLogFiles;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-2.3: $($_.Exception.Message)" }

                # SOX-2.4 Default trace enabled — baseline change and security event evidence.
                try {
                    $defTrace = Get-DbaSpConfigure @connSplat -Name "DefaultTraceEnabled" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($defTrace) {
                        $splatCheck = @{
                            CheckId        = "SOX-2.4"
                            CheckName      = "Default Trace Enabled"
                            Category       = "Audit"
                            AssessmentType = "Automated"
                            Priority       = $soxPriority["2.4"]
                            Status         = if ($defTrace.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $defTrace.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "SOX §404 — Audit Trail"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'default trace enabled';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOX-2.4: $($_.Exception.Message)" }

                # SOX-2.5 Audit captures server and database role membership changes.
                try {
                    $roleAuditQuery = @"
SELECT COUNT(*) AS Found
FROM sys.server_audit_specification_details SAD
JOIN sys.server_audit_specifications SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('ADSP','ADDP')
  AND S.is_state_enabled = 1 AND SA.is_state_enabled = 1;
"@
                    $roleAudit = Invoke-DbaQuery @connSplat -Query $roleAuditQuery -WarningAction SilentlyContinue
                    $found     = $roleAudit -and $roleAudit.Found -gt 0
                    $splatCheck = @{
                        CheckId        = "SOX-2.5"
                        CheckName      = "Audit — Role Membership Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["2.5"]
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP captured"
                        Remediation    = "Add SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP to your active server audit specification."
                        Reference      = "SOX §404 — Change Accountability"
                        SqlQuery       = $roleAuditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-2.5: $($_.Exception.Message)" }

                # SOX-2.6 Audit captures DDL and schema changes to financial database objects.
                try {
                    $ddlAuditQuery = @"
SELECT COUNT(*) AS Found
FROM sys.server_audit_specification_details SAD
JOIN sys.server_audit_specifications SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('DAUC','CDBR','SCHM')
  AND S.is_state_enabled = 1 AND SA.is_state_enabled = 1;
"@
                    $ddlAudit = Invoke-DbaQuery @connSplat -Query $ddlAuditQuery -WarningAction SilentlyContinue
                    $found    = $ddlAudit -and $ddlAudit.Found -gt 0
                    $splatCheck = @{
                        CheckId        = "SOX-2.6"
                        CheckName      = "Audit — DDL / Schema Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["2.6"]
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP or DATABASE_CHANGE_GROUP captured"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to your active server audit specification. For database-level coverage: CREATE DATABASE AUDIT SPECIFICATION covering SCHEMA_OBJECT_CHANGE_GROUP on each financial database."
                        Reference      = "SOX §404 — Change Management"
                        SqlQuery       = $ddlAuditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-2.6: $($_.Exception.Message)" }
            }

            # ── §3 Change Management ──────────────────────────────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 Change Management"

                # SOX-3.1 Agent jobs have owners — ownerless jobs have no accountability chain.
                try {
                    $ownerlessJobs = Get-DbaAgentJob @connSplat -WarningAction SilentlyContinue |
                        Where-Object { [string]::IsNullOrWhiteSpace($_.OwnerLoginName) }
                    $count = if ($ownerlessJobs) { @($ownerlessJobs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-3.1"
                        CheckName      = "Agent Job Ownership"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["3.1"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All jobs have owners" } else { "$count jobs without an owner" }
                        ExpectedValue  = "All jobs have a named owner login"
                        Remediation    = "EXEC msdb.dbo.sp_update_job @job_name = N'<jobname>', @owner_login_name = N'<login>';"
                        Reference      = "SOX §404 — Change Accountability"
                        SqlQuery       = "-- Automated via Get-DbaAgentJob. T-SQL: SELECT name, owner_sid FROM msdb.dbo.sysjobs WHERE owner_sid IS NULL;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-3.1: $($_.Exception.Message)" }

                # SOX-3.2 SQL Agent operator configured — no operator means no alert delivery path.
                try {
                    $operators = Get-DbaAgentOperator @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($_.EmailAddress) }
                    $count = if ($operators) { @($operators).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-3.2"
                        CheckName      = "SQL Agent Operator Configured"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["3.2"]
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count enabled operator(s) with email address"
                        ExpectedValue  = "At least 1 enabled operator with an email address"
                        Remediation    = "EXEC msdb.dbo.sp_add_operator @name = N'DBA Team', @enabled = 1, @email_address = N'dba@company.com';"
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Automated via Get-DbaAgentOperator. T-SQL: SELECT name, enabled, email_address FROM msdb.dbo.sysoperators WHERE enabled = 1 AND email_address IS NOT NULL AND email_address <> '';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-3.2: $($_.Exception.Message)" }

                # SOX-3.3 Alerts for severity 19–25 — data-threatening SQL Server errors.
                try {
                    $sevAlerts = Get-DbaAgentAlert @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.IsEnabled -and $_.Severity -ge 19 -and $_.Severity -le 25 }
                    $missingSev = 19..25 | Where-Object {
                        $sev = $_
                        -not ($sevAlerts | Where-Object { $_.Severity -eq $sev })
                    }
                    $splatCheck = @{
                        CheckId        = "SOX-3.3"
                        CheckName      = "Alerts — Severity 19-25"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["3.3"]
                        Status         = if ($missingSev.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingSev.Count -eq 0) { "All severity levels covered" } else { "Missing alerts for severity: $($missingSev -join ', ')" }
                        ExpectedValue  = "Enabled alert for each severity level 19–25"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Severity 019', @message_id = 0, @severity = 19, @enabled = 1, @notification_message = N'Severity 19 error.';  -- Repeat for each missing severity."
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Automated via Get-DbaAgentAlert. T-SQL: SELECT severity, name, enabled FROM msdb.dbo.sysalerts WHERE severity BETWEEN 19 AND 25 AND enabled = 1 ORDER BY severity;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-3.3: $($_.Exception.Message)" }

                # SOX-3.4 Alerts for errors 823, 824, 825 — I/O errors indicating potential data corruption.
                try {
                    $ioAlerts = Get-DbaAgentAlert @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.IsEnabled -and $_.MessageId -in 823, 824, 825 }
                    $missingIo = @(823, 824, 825) | Where-Object {
                        $mid = $_
                        -not ($ioAlerts | Where-Object { $_.MessageId -eq $mid })
                    }
                    $splatCheck = @{
                        CheckId        = "SOX-3.4"
                        CheckName      = "Alerts — I/O Errors 823/824/825"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["3.4"]
                        Status         = if ($missingIo.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingIo.Count -eq 0) { "All three I/O error alerts configured" } else { "Missing alert for error(s): $($missingIo -join ', ')" }
                        ExpectedValue  = "Enabled alert for error numbers 823, 824, and 825"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Error 823', @message_id = 823, @severity = 0, @enabled = 1;  -- Repeat for 824 and 825. Assign to an operator."
                        Reference      = "SOX §404 — Data Integrity Monitoring"
                        SqlQuery       = "-- Automated via Get-DbaAgentAlert. T-SQL: SELECT message_id, name, enabled FROM msdb.dbo.sysalerts WHERE message_id IN (823,824,825) AND enabled = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-3.4: $($_.Exception.Message)" }

                # SOX-3.5 Database Mail configured — delivery path for operational alerts.
                try {
                    $mailProfiles = Get-DbaDbMailProfile @connSplat -WarningAction SilentlyContinue
                    $count = if ($mailProfiles) { @($mailProfiles).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-3.5"
                        CheckName      = "Database Mail Configured"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["3.5"]
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count mail profile(s) configured"
                        ExpectedValue  = "At least 1 Database Mail profile"
                        Remediation    = "Configure Database Mail in SSMS > Management > Database Mail > Configure Database Mail wizard. Verify: EXEC msdb.dbo.sysmail_help_profile_sp;"
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Automated via Get-DbaDbMailProfile. T-SQL: SELECT name, description FROM msdb.dbo.sysmail_profile;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-3.5: $($_.Exception.Message)" }
            }

            # ── §4 Data Integrity & Recovery ──────────────────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Data Integrity & Recovery"

                # SOX-4.1 All user databases have a full backup within 24 hours.
                try {
                    $userDbs     = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $staleBackup = @()
                    foreach ($db in @($userDbs)) {
                        $lastFull = Get-DbaDbBackupHistory @connSplat -Database $db.Name -LastFull -WarningAction SilentlyContinue |
                            Select-Object -First 1
                        if (-not $lastFull -or $lastFull.End -lt (Get-Date).AddHours(-24)) {
                            $staleBackup += $db.Name
                        }
                    }
                    $count = $staleBackup.Count
                    $splatCheck = @{
                        CheckId        = "SOX-4.1"
                        CheckName      = "Full Backup Within 24 Hours"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.1"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases backed up within 24h" } else { "$count databases missing recent backup: $($staleBackup -join ', ')" }
                        ExpectedValue  = "Full backup within 24 hours for every user database"
                        Remediation    = "Investigate backup job failures. Check agent job history: Get-DbaAgentJobHistory -SqlInstance $instance | Where-Object { `$_.JobName -like '*backup*' -and `$_.Status -ne 'Succeeded' }"
                        Reference      = "SOX §404 — Business Continuity"
                        SqlQuery       = "-- Automated via Get-DbaDbBackupHistory -LastFull. T-SQL: SELECT database_name, MAX(backup_finish_date) AS LastFullBackup FROM msdb.dbo.backupset WHERE type = 'D' GROUP BY database_name;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.1: $($_.Exception.Message)" }

                # SOX-4.2 DBCC CHECKDB within 7 days on all user databases.
                try {
                    $checkdbInfo  = Get-DbaLastGoodCheckDb @connSplat -ExcludeDatabase tempdb -WarningAction SilentlyContinue
                    $staleCheckdb = @($checkdbInfo | Where-Object {
                        $null -eq $_.LastGoodCheckDb -or $_.LastGoodCheckDb -lt (Get-Date).AddDays(-7)
                    })
                    $count = $staleCheckdb.Count
                    $splatCheck = @{
                        CheckId        = "SOX-4.2"
                        CheckName      = "DBCC CHECKDB Within 7 Days"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All databases checked within 7 days" } else { "$count databases overdue: $($staleCheckdb.Database -join ', ')" }
                        ExpectedValue  = "DBCC CHECKDB completed within 7 days on all databases"
                        Remediation    = "Schedule integrity checks: Invoke-DbaDbIntegrityCheck -SqlInstance $instance -Database <db>  -- or use Ola Hallengren's DatabaseIntegrityCheck job."
                        Reference      = "SOX §404 — Data Integrity"
                        SqlQuery       = "-- Automated via Get-DbaLastGoodCheckDb. T-SQL reference: DBCC DBINFO() WITH TABLERESULTS;  -- Look for dbi_dbccLastKnownGood."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.2: $($_.Exception.Message)" }

                # SOX-4.3 No inaccessible user databases.
                try {
                    $problemDbs = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { -not $_.IsAccessible }
                    $count = if ($problemDbs) { @($problemDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-4.3"
                        CheckName      = "All User Databases Accessible"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases accessible" } else { "$count inaccessible: $($problemDbs.Name -join ', ')" }
                        ExpectedValue  = "All user databases in an accessible state"
                        Remediation    = "Investigate inaccessible databases in the SQL Server error log. Databases in Suspect/Recovery_Pending state may indicate corruption."
                        Reference      = "SOX §404 — Availability"
                        SqlQuery       = "-- Automated via Get-DbaDatabase (IsAccessible). T-SQL: SELECT name, state_desc FROM sys.databases WHERE database_id > 4 AND state <> 0;  -- state 0 = ONLINE"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.3: $($_.Exception.Message)" }

                # SOX-4.4 Full recovery model — Simple recovery prevents point-in-time restore.
                try {
                    $simpleRecovery = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.RecoveryModel -eq "Simple" }
                    $count = if ($simpleRecovery) { @($simpleRecovery).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-4.4"
                        CheckName      = "Full Recovery Model"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.4"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($count -eq 0) { "All user databases in Full or Bulk-Logged" } else { "$count in Simple recovery: $($simpleRecovery.Name -join ', ')" }
                        ExpectedValue  = "Full recovery model for all databases in SOX scope"
                        Remediation    = "ALTER DATABASE [<dbname>] SET RECOVERY FULL;  -- Immediately take a full backup to start the log chain, then schedule regular log backups."
                        Reference      = "SOX §404 — Recovery Point Objectives"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name, recovery_model_desc FROM sys.databases WHERE database_id > 4 AND recovery_model_desc = 'SIMPLE';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.4: $($_.Exception.Message)" }

                # SOX-4.5 Transaction log backed up within 4 hours for Full/BulkLogged databases.
                try {
                    $fullRecovDbs = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.RecoveryModel -in "Full", "BulkLogged" }
                    $staleLog = @()
                    foreach ($db in @($fullRecovDbs)) {
                        $lastLog = Get-DbaDbBackupHistory @connSplat -Database $db.Name -LastLog -WarningAction SilentlyContinue |
                            Select-Object -First 1
                        if (-not $lastLog -or $lastLog.End -lt (Get-Date).AddHours(-4)) {
                            $staleLog += $db.Name
                        }
                    }
                    $count = $staleLog.Count
                    $splatCheck = @{
                        CheckId        = "SOX-4.5"
                        CheckName      = "Log Backup Within 4 Hours"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.5"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All Full/BulkLogged databases have recent log backups" } else { "$count databases missing log backup: $($staleLog -join ', ')" }
                        ExpectedValue  = "Log backup within 4 hours for all Full and BulkLogged databases"
                        Remediation    = "Schedule log backup jobs. Full recovery without log backups grows the log indefinitely: BACKUP LOG [<db>] TO DISK = N'<path>';"
                        Reference      = "SOX §404 — Recovery Point Objectives"
                        SqlQuery       = "-- Automated via Get-DbaDbBackupHistory -LastLog. T-SQL: SELECT database_name, MAX(backup_finish_date) AS LastLogBackup FROM msdb.dbo.backupset WHERE type = 'L' GROUP BY database_name;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.5: $($_.Exception.Message)" }

                # SOX-4.6 Page verify CHECKSUM — detects I/O corruption before it becomes permanent.
                try {
                    $noCksum = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.PageVerify -ne "Checksum" }
                    $count = if ($noCksum) { @($noCksum).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-4.6"
                        CheckName      = "Page Verify CHECKSUM"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.6"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases use CHECKSUM" } else { "$count databases without CHECKSUM: $($noCksum.Name -join ', ')" }
                        ExpectedValue  = "PAGE_VERIFY = CHECKSUM for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "SOX §404 — Data Integrity"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name, page_verify_option_desc FROM sys.databases WHERE database_id > 4 AND page_verify_option_desc <> 'CHECKSUM';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.6: $($_.Exception.Message)" }

                # SOX-4.7 AUTO_CLOSE disabled — unexpected connection flush is an availability risk.
                try {
                    $autoClose = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.AutoClose -eq $true }
                    $count = if ($autoClose) { @($autoClose).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-4.7"
                        CheckName      = "AUTO_CLOSE Disabled"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.7"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count databases with AUTO_CLOSE ON: $($autoClose.Name -join ', ')" }
                        ExpectedValue  = "AUTO_CLOSE OFF for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_CLOSE OFF;"
                        Reference      = "SOX §404 — Availability"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name FROM sys.databases WHERE database_id > 4 AND is_auto_close_on = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.7: $($_.Exception.Message)" }

                # SOX-4.8 AUTO_SHRINK disabled — causes fragmentation and unexpected I/O spikes.
                try {
                    $autoShrink = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.AutoShrink -eq $true }
                    $count = if ($autoShrink) { @($autoShrink).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-4.8"
                        CheckName      = "AUTO_SHRINK Disabled"
                        Category       = "Data Integrity"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["4.8"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count databases with AUTO_SHRINK ON: $($autoShrink.Name -join ', ')" }
                        ExpectedValue  = "AUTO_SHRINK OFF for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_SHRINK OFF;"
                        Reference      = "SOX §404 — Data Integrity / Performance"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name FROM sys.databases WHERE database_id > 4 AND is_auto_shrink_on = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-4.8: $($_.Exception.Message)" }
            }

            # ── §5 Encryption ─────────────────────────────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Encryption"

                # SOX-5.1 Network encryption — unencrypted connections expose financial data in transit.
                try {
                    $q5_1 = @"
SELECT DISTINCT encrypt_option
FROM sys.dm_exec_connections c
WHERE net_transport <> 'Shared memory'
  AND c.endpoint_id NOT IN (
      SELECT endpoint_id FROM sys.database_mirroring_endpoints
      WHERE encryption_algorithm IS NOT NULL
  );
"@
                    $r5_1  = Invoke-DbaQuery @connSplat -Query $q5_1 -WarningAction SilentlyContinue
                    $unenc = if ($r5_1) { @($r5_1 | Where-Object { $_.encrypt_option -ne "TRUE" }).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-5.1"
                        CheckName      = "Network Encryption Enforced"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["5.1"]
                        Status         = if ($unenc -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unenc -eq 0) { "All non-shared-memory connections encrypted" } else { "$unenc unencrypted connection type(s) detected" }
                        ExpectedValue  = "All non-shared-memory connections encrypted"
                        Remediation    = "Enable Force Encryption in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties > Force Encryption = Yes. A trusted certificate is required."
                        Reference      = "SOX §404 — Data Protection in Transit"
                        SqlQuery       = $q5_1
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-5.1: $($_.Exception.Message)" }

                # SOX-5.2 Backup encryption — unencrypted backups of financial data violate SOX data security.
                try {
                    $q5_2 = @"
SELECT COUNT(*) AS UnencBackups
FROM msdb.dbo.backupset b
JOIN sys.databases d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL
  AND b.encryptor_type IS NULL
  AND d.is_encrypted = 0
  AND b.backup_finish_date >= DATEADD(DAY, -30, GETDATE());
"@
                    $r5_2 = Invoke-DbaQuery @connSplat -Query $q5_2 -WarningAction SilentlyContinue
                    $count = if ($r5_2) { $r5_2.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-5.2"
                        CheckName      = "Backup Encryption"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["5.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup records in the past 30 days"
                        ExpectedValue  = "0 — all backups encrypted or database encrypted via TDE"
                        Remediation    = "Enable backup encryption via the WITH ENCRYPTION clause on BACKUP DATABASE, or enable TDE (TDE-encrypted databases produce automatically encrypted backups)."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = $q5_2
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-5.2: $($_.Exception.Message)" }

                # SOX-5.3 TDE scope review — Manual: which databases hold financial data is environment-specific.
                try {
                    $unencDbs = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { -not $_.EncryptionEnabled }
                    $count = if ($unencDbs) { @($unencDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "SOX-5.3"
                        CheckName      = "TDE Scope Review"
                        Category       = "Encryption"
                        AssessmentType = "Manual"
                        Priority       = $soxPriority["5.3"]
                        Status         = "Manual"
                        CurrentValue   = "$count user database(s) without TDE"
                        ExpectedValue  = "TDE enabled on all databases that contain SOX financial reporting data"
                        Remediation    = "Identify databases in SOX scope. For each: Enable-DbaDatabaseEncryption -SqlInstance $instance -Database <dbname>  -- Requires a database master key and certificate on [master]."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted = 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-5.3: $($_.Exception.Message)" }

                # SOX-5.4 Symmetric keys use AES — weak algorithms undermine SOX data protection controls.
                try {
                    $q5_4     = "SELECT COUNT(*) AS WeakKeys FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND DB_ID() > 4;"
                    $userDbs5 = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $weakKeys = 0
                    foreach ($db in @($userDbs5)) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $q5_4 -WarningAction SilentlyContinue
                        if ($r) { $weakKeys += $r.WeakKeys }
                    }
                    $splatCheck = @{
                        CheckId        = "SOX-5.4"
                        CheckName      = "Symmetric Key Algorithms"
                        Category       = "Encryption"
                        AssessmentType = "Automated"
                        Priority       = $soxPriority["5.4"]
                        Status         = if ($weakKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeys non-AES symmetric key(s)"
                        ExpectedValue  = "0 — all symmetric keys use AES_128, AES_192, or AES_256"
                        Remediation    = "Recreate non-AES symmetric keys using a supported algorithm. Per-database: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = $q5_4
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOX-5.4: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] SOX assessment complete"
        }
    }

    end {}
}
