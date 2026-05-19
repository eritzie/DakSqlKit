Get-ChildItem "$PSScriptRoot\Private\*.ps1" | ForEach-Object { . $_.FullName }

function Test-DakSOC2Benchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against database-relevant SOC 2 Trust Services Criteria.

    .DESCRIPTION
        Evaluates SQL Server configuration and operational state against database-relevant
        AICPA SOC 2 Trust Services Criteria. Returns one result object per check per instance
        (type: DakSqlKit.AuditResult). CheckIds use the TSC control identifier (e.g. SOC2-CC6.1a).

        Criteria assessed (database-relevant controls only):
            §CC1 — Control Environment     ( 1 check:  SOC2-CC1.5)
            §CC4 — Monitoring Activities   ( 1 check:  SOC2-CC4.1)
            §CC5 — Control Activities      ( 4 checks: SOC2-CC5.1a – CC5.2b)
            §CC6 — Logical Access Controls (14 checks: SOC2-CC6.1a – CC6.8)
            §CC7 — System Operations       ( 9 checks: SOC2-CC7.1  – CC7.4c)
            §CC8 — Change Management       ( 1 check:  SOC2-CC8.1)
            §CC9 — Risk Mitigation         ( 1 check:  SOC2-CC9.2)

        AssessmentType on each result:
            Automated — pass/fail determined by the tool
            Manual    — tool collected evidence; a human must determine compliance

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        Criteria sections to run: CC1, CC4, CC5, CC6, CC7, CC8, CC9, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

    .PARAMETER Quiet
        Suppress console progress output.

    .EXAMPLE
        Test-DakSOC2Benchmark -SqlInstance 'SQLPROD01'

    .EXAMPLE
        Test-DakSOC2Benchmark -SqlInstance 'SQLPROD01' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Get-DbaRegisteredServer -Group Production | Test-DakSOC2Benchmark -Section CC6,CC7
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("CC1","CC4","CC5","CC6","CC7","CC8","CC9","All")]
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
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) {
                Write-Host "SOC 2 Trust Services Criteria — $instance  ($($runDate.ToString('yyyy-MM-dd HH:mm:ss')))" -ForegroundColor White
            }
            Write-Verbose "[$instance] SOC 2 assessment — $($runDate.ToString('yyyy-MM-dd HH:mm:ss')) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "SOC2"
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
                if (-not $Quiet) {
                    Write-Host ("  [{0,-14}] {1,-55} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color
                }
                if (-not $FailedOnly -or $r.Status -in "Fail","Warning","Manual","Error") { $r }
            }

            # ── §CC1 Control Environment ──────────────────────────────────────────
            if (ShouldRun "CC1") {
                Write-Verbose "[$instance] §CC1 Control Environment"

                $authDataCC1 = Get-AuthMode -ctx $connSplat

                # SOC2-CC1.5 Windows-only authentication — CC1.5: enforce individual accountability.
                # SQL logins can be shared and bypass AD lifecycle management; Windows auth ties
                # every connection to a named, auditable AD identity.
                try {
                    $winOnly = ($authDataCC1.LoginMode -eq 1)
                    $splatCheck = @{
                        CheckId        = "CC1.5"
                        CheckName      = "Windows-Only Authentication"
                        Category       = "Control Environment"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only (LoginMode = 1)"
                        Remediation    = "Mixed mode allows SQL logins that cannot be individually attributed and bypass AD deprovisioning. Change to Windows Authentication only: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- SQL Server service restart required."
                        Reference      = "SOC 2 TSC CC1.5 — Enforces Accountability"
                        SqlQuery       = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC1.5: $($_.Exception.Message)" }
            }

            # ── §CC4 Monitoring Activities ────────────────────────────────────────
            if (ShouldRun "CC4") {
                Write-Verbose "[$instance] §CC4 Monitoring Activities"

                # SOC2-CC4.1 SQL Server Audit active — CC4.1: perform ongoing evaluations to
                # ascertain whether controls are present and functioning.
                # No dbatools equivalent for sys.server_audits state — using Invoke-DbaQuery.
                try {
                    $qAuditOn = @"
SELECT COUNT(*) AS EnabledAudits
FROM sys.server_audits
WHERE is_state_enabled = 1;
"@
                    $auditOn    = Invoke-DbaQuery @connSplat -Query $qAuditOn -WarningAction SilentlyContinue
                    $enabled    = $auditOn -and $auditOn.EnabledAudits -gt 0
                    $splatCheck = @{
                        CheckId        = "CC4.1"
                        CheckName      = "SQL Server Audit Active"
                        Category       = "Monitoring Activities"
                        AssessmentType = "Automated"
                        Priority       = "Critical"
                        Status         = if ($enabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($enabled) { "$($auditOn.EnabledAudits) enabled server audit(s)" } else { "No enabled server audits" }
                        ExpectedValue  = "At least 1 enabled server audit"
                        Remediation    = "Create and enable a SERVER AUDIT targeting a protected file path, then create a SERVER AUDIT SPECIFICATION covering the required action groups (at minimum: FAILED_LOGIN_GROUP, SUCCESSFUL_LOGIN_GROUP, SERVER_ROLE_MEMBER_CHANGE_GROUP, SCHEMA_OBJECT_CHANGE_GROUP)."
                        Reference      = "SOC 2 TSC CC4.1 — Ongoing Evaluations"
                        SqlQuery       = $qAuditOn
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC4.1: $($_.Exception.Message)" }
            }

            # ── §CC5 Control Activities ───────────────────────────────────────────
            if (ShouldRun "CC5") {
                Write-Verbose "[$instance] §CC5 Control Activities"

                $sacCC5   = Get-SurfaceAreaConfig -ctx $connSplat
                $dbCfgCC5 = Get-DatabaseConfig    -ctx $connSplat

                # SOC2-CC5.1a xp_cmdshell disabled — CC5.1: select and develop preventive controls.
                # xp_cmdshell allows SQL Server to shell out to the OS, bypassing OS-level controls.
                try {
                    $cmdShell = $sacCC5.XpCmdshell
                    if ($cmdShell) {
                        $splatCheck = @{
                            CheckId        = "CC5.1a"
                            CheckName      = "xp_cmdshell Disabled"
                            Category       = "Control Activities"
                            AssessmentType = "Automated"
                            Priority       = "High"
                            Status         = if ($cmdShell.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $cmdShell.RunningValue.ToString()
                            ExpectedValue  = "0 (disabled)"
                            Remediation    = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
                            Reference      = "SOC 2 TSC CC5.1 — Preventive Controls"
                            SqlQuery       = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOC2-CC5.1a: $($_.Exception.Message)" }

                # SOC2-CC5.1b OLE Automation Procedures disabled — CC5.1: preventive control
                # against COM object execution from within T-SQL.
                try {
                    $oleAuto = $sacCC5.OleAutomation
                    if ($oleAuto) {
                        $splatCheck = @{
                            CheckId        = "CC5.1b"
                            CheckName      = "OLE Automation Procedures Disabled"
                            Category       = "Control Activities"
                            AssessmentType = "Automated"
                            Priority       = "Medium"
                            Status         = if ($oleAuto.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $oleAuto.RunningValue.ToString()
                            ExpectedValue  = "0 (disabled)"
                            Remediation    = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;"
                            Reference      = "SOC 2 TSC CC5.1 — Preventive Controls"
                            SqlQuery       = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOC2-CC5.1b: $($_.Exception.Message)" }

                # SOC2-CC5.2a Page Verify CHECKSUM — CC5.2: select and develop technology controls.
                # CHECKSUM detects I/O-path corruption before it becomes unrecoverable data loss.
                try {
                    $noCksumCC5 = $dbCfgCC5.NoChecksum
                    $count      = $noCksumCC5.Count
                    $splatCheck = @{
                        CheckId        = "CC5.2a"
                        CheckName      = "Page Verify CHECKSUM"
                        Category       = "Control Activities"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases use CHECKSUM" } else { "$count database(s) without CHECKSUM: $($noCksumCC5.Name -join ', ')" }
                        ExpectedValue  = "PAGE_VERIFY = CHECKSUM for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "SOC 2 TSC CC5.2 — Technology Controls"
                        SqlQuery       = "SELECT name, page_verify_option_desc FROM sys.databases WHERE database_id > 4 AND page_verify_option_desc <> 'CHECKSUM';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC5.2a: $($_.Exception.Message)" }

                # SOC2-CC5.2b AUTO_SHRINK disabled — CC5.2: technology controls for data integrity.
                # AUTO_SHRINK causes index fragmentation, unexpected I/O, and recurrent file growth.
                try {
                    $autoShrinkCC5 = $dbCfgCC5.AutoShrink
                    $count         = $autoShrinkCC5.Count
                    $splatCheck = @{
                        CheckId        = "CC5.2b"
                        CheckName      = "AUTO_SHRINK Disabled"
                        Category       = "Control Activities"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count database(s) with AUTO_SHRINK ON: $($autoShrinkCC5.Name -join ', ')" }
                        ExpectedValue  = "AUTO_SHRINK OFF for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_SHRINK OFF;"
                        Reference      = "SOC 2 TSC CC5.2 — Technology Controls"
                        SqlQuery       = "SELECT name FROM sys.databases WHERE database_id > 4 AND is_auto_shrink_on = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC5.2b: $($_.Exception.Message)" }
            }

            # ── §CC6 Logical Access Controls ──────────────────────────────────────
            if (ShouldRun "CC6") {
                Write-Verbose "[$instance] §CC6 Logical Access Controls"

                $saDataCC6      = Get-SaLogin           -ctx $connSplat
                $builtinDataCC6 = Get-BuiltinGroups      -ctx $connSplat
                $guestDataCC6   = Get-GuestAccess        -ctx $connSplat
                $permDataCC6    = Get-PublicRolePerms     -ctx $connSplat
                $sqlDataCC6     = Get-SqlAuthLogins       -ctx $connSplat
                $orphanDataCC6  = Get-OrphanedUsers       -ctx $connSplat
                $sysDataCC6     = Get-SysadminLogins      -ctx $connSplat
                $netEncCC6      = Get-NetworkEncryption   -ctx $connSplat
                $tdeCC6         = Get-TdeStatus           -ctx $connSplat
                $symDataCC6     = Get-SymmetricKeys        -ctx $connSplat
                $clrCC6         = Get-ClrAssemblies        -ctx $connSplat
                $saLogin        = $saDataCC6.Login

                # SOC2-CC6.1a BUILTIN groups absent — CC6.1: restrict logical access to authorized users.
                # BUILTIN groups grant SQL Server access to all local admins outside the provisioning process.
                try {
                    $count = $builtinDataCC6.Count
                    $splatCheck = @{
                        CheckId        = "CC6.1a"
                        CheckName      = "BUILTIN Groups Absent"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtinDataCC6.Names -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "Confirm domain group equivalents exist for any legitimate need, then: USE [master]; DROP LOGIN [BUILTIN\Administrators];"
                        Reference      = "SOC 2 TSC CC6.1 — Logical Access Restrictions"
                        SqlQuery       = "SELECT name FROM sys.server_principals WHERE name LIKE 'BUILTIN%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1a: $($_.Exception.Message)" }

                # SOC2-CC6.1b Guest access revoked — CC6.1: no access without explicit provisioning.
                try {
                    $count = $guestDataCC6.Count
                    $splatCheck = @{
                        CheckId        = "CC6.1b"
                        CheckName      = "Guest Access Revoked"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "Revoked in all user databases" } else { "Active in: $($guestDataCC6.DatabaseNames -join ', ')" }
                        ExpectedValue  = "CONNECT revoked in all user databases"
                        Remediation    = "USE [<database>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "SOC 2 TSC CC6.1 — Logical Access Restrictions"
                        SqlQuery       = "SELECT permission_name FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1b: $($_.Exception.Message)" }

                # SOC2-CC6.1c Public role — no excess server permissions — CC6.1: least privilege.
                try {
                    $count = $permDataCC6.Count
                    $splatCheck = @{
                        CheckId        = "CC6.1c"
                        CheckName      = "Public Role — No Excess Server Permissions"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count non-standard permission(s) granted to public"
                        ExpectedValue  = "0 — only CONNECT SQL is standard for the public server role"
                        Remediation    = "Identify: SELECT type_desc, permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = 2 AND state IN ('G','W'). Then: REVOKE <permission> FROM [public];"
                        Reference      = "SOC 2 TSC CC6.1 — Least Privilege"
                        SqlQuery       = $permDataCC6.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1c: $($_.Exception.Message)" }

                # SOC2-CC6.1d SQL login password policy — CC6.1: enforce authentication controls.
                try {
                    $noPolicyCC6 = @($sqlDataCC6.Logins | Where-Object { -not $_.PasswordPolicyEnforced })
                    $count       = $noPolicyCC6.Count
                    $splatCheck = @{
                        CheckId        = "CC6.1d"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count login(s) without CHECK_POLICY" }
                        ExpectedValue  = "CHECK_POLICY = ON for all SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON;  -- Find violations: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;"
                        Reference      = "SOC 2 TSC CC6.1 — Authentication Controls"
                        SqlQuery       = "SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1d: $($_.Exception.Message)" }

                # SOC2-CC6.1e Privileged login password expiration — CC6.1: credential rotation.
                # No dbatools equivalent for the sysadmin + CONTROL SERVER union — using Invoke-DbaQuery.
                try {
                    $qExpiry = @"
SELECT l.name, 'sysadmin' AS Reason
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin', l.name) = 1
  AND l.is_expiration_checked = 0
  AND l.is_disabled = 0
UNION ALL
SELECT l.name, 'CONTROL SERVER' AS Reason
FROM sys.sql_logins AS l
JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL'
  AND p.state IN ('G','W')
  AND l.is_expiration_checked = 0
  AND l.is_disabled = 0;
"@
                    $expRows = Invoke-DbaQuery @connSplat -Query $qExpiry -WarningAction SilentlyContinue
                    $count   = if ($expRows) { @($expRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "CC6.1e"
                        CheckName      = "Privileged Login Password Expiration"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count privileged login(s) without CHECK_EXPIRATION" }
                        ExpectedValue  = "CHECK_EXPIRATION = ON for all privileged SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "SOC 2 TSC CC6.1 — Credential Management"
                        SqlQuery       = $qExpiry
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1e: $($_.Exception.Message)" }

                # SOC2-CC6.1f sa login disabled — CC6.1: well-known vendor default account
                # must be disabled to prevent unauthorized access.
                try {
                    $saEnabled = $saLogin -and -not $saLogin.IsDisabled
                    $splatCheck = @{
                        CheckId        = "CC6.1f"
                        CheckName      = "sa Login Disabled"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if (-not $saEnabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($saEnabled) { "Enabled (name: $($saLogin.Name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "DECLARE @n NVARCHAR(256) = SUSER_NAME(0x01); EXEC ('ALTER LOGIN [' + @n + '] DISABLE');"
                        Reference      = "SOC 2 TSC CC6.1 — Logical Access Restrictions"
                        SqlQuery       = "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.1f: $($_.Exception.Message)" }

                # SOC2-CC6.1g sa login renamed — CC6.1: well-known account name aids targeted attacks.
                try {
                    if ($saLogin) {
                        $splatCheck = @{
                            CheckId        = "CC6.1g"
                            CheckName      = "sa Login Renamed"
                            Category       = "Logical Access"
                            AssessmentType = "Automated"
                            Priority       = "Medium"
                            Status         = if ($saLogin.Name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saLogin.Name
                            ExpectedValue  = "Any name other than 'sa'"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "SOC 2 TSC CC6.1 — Logical Access Restrictions"
                            SqlQuery       = "SELECT name FROM sys.server_principals WHERE sid = 0x01;"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOC2-CC6.1g: $($_.Exception.Message)" }

                # SOC2-CC6.3a Orphaned database users — CC6.3: modify or remove access based on
                # approved access requests and policy. Orphaned users retain object-level permissions
                # with no corresponding server login.
                try {
                    $count = $orphanDataCC6.Count
                    $splatCheck = @{
                        CheckId        = "CC6.3a"
                        CheckName      = "No Orphaned Database Users"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count orphaned user(s)" }
                        ExpectedValue  = "No orphaned users in any database"
                        Remediation    = "Remove-DbaDbOrphanUser -SqlInstance $instance  -- or remap: USE [<db>]; ALTER USER [<user>] WITH LOGIN = [<login>];"
                        Reference      = "SOC 2 TSC CC6.3 — Logical Access Authorization"
                        SqlQuery       = "SELECT name FROM sys.database_principals WHERE type IN ('S','U','G') AND authentication_type_desc = 'INSTANCE' AND sid NOT IN (SELECT sid FROM sys.server_principals);"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.3a: $($_.Exception.Message)" }

                # SOC2-CC6.3b Sysadmin membership review — Manual: CC6.3 requires formal periodic
                # access review; sysadmin grants unrestricted access to all databases and instance state.
                try {
                    $svcFilter   = @(
                        'NT SERVICE\SQLWriter',
                        'NT SERVICE\Winmgmt',
                        'NT SERVICE\MSSQLSERVER',
                        'NT SERVICE\SQLSERVERAGENT'
                    )
                    $sysadminsCC6 = @($sysDataCC6.Members | Where-Object { $_.Name -notin $svcFilter })
                    $count        = $sysadminsCC6.Count
                    $members      = if ($sysadminsCC6) { ($sysadminsCC6.Name -join ', ') } else { 'None detected' }
                    $splatCheck = @{
                        CheckId        = "CC6.3b"
                        CheckName      = "Sysadmin Membership Review"
                        Category       = "Logical Access"
                        AssessmentType = "Manual"
                        Priority       = "Critical"
                        Status         = "Manual"
                        CurrentValue   = "$count non-system account(s) in sysadmin: $members"
                        ExpectedValue  = "Minimum necessary; each account formally documented and recertified at least annually"
                        Remediation    = "Review all members: SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%'. Remove any not formally approved: ALTER SERVER ROLE sysadmin DROP MEMBER [<account>];"
                        Reference      = "SOC 2 TSC CC6.3 — Logical Access Authorization"
                        SqlQuery       = "SELECT DISTINCT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.3b: $($_.Exception.Message)" }

                # SOC2-CC6.6 Network encryption enforced — CC6.6: logical access security measures
                # against threats from outside the system boundary include transmission encryption.
                try {
                    $unencCC6 = $netEncCC6.UnencryptedCount
                    $splatCheck = @{
                        CheckId        = "CC6.6"
                        CheckName      = "Network Encryption Enforced"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($unencCC6 -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unencCC6 -eq 0) { "All non-shared-memory connections encrypted" } else { "$unencCC6 unencrypted connection type(s) detected" }
                        ExpectedValue  = "All connections use encryption"
                        Remediation    = "Enable Force Encryption in SQL Server Configuration Manager: SQL Server Network Configuration > Protocols > Properties > Force Encryption = Yes. A trusted certificate is required."
                        Reference      = "SOC 2 TSC CC6.6 — Logical Access Security Measures"
                        SqlQuery       = $netEncCC6.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.6: $($_.Exception.Message)" }

                # SOC2-CC6.7a Backup encryption — CC6.7: restrict transmission and storage of
                # confidential information to authorized users. Unencrypted backups expose data
                # outside the primary access control boundary.
                # No dbatools equivalent — using Invoke-DbaQuery against msdb.dbo.backupset.
                try {
                    $qBackupEnc = @"
SELECT COUNT(*) AS UnencBackups
FROM msdb.dbo.backupset AS b
JOIN sys.databases AS d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL
  AND b.encryptor_type IS NULL
  AND d.is_encrypted = 0
  AND b.backup_finish_date >= DATEADD(DAY, -30, GETDATE());
"@
                    $rBackupEnc = Invoke-DbaQuery @connSplat -Query $qBackupEnc -WarningAction SilentlyContinue
                    $count      = if ($rBackupEnc) { $rBackupEnc.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "CC6.7a"
                        CheckName      = "Backup Encryption"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup record(s) in the past 30 days"
                        ExpectedValue  = "0 — all backups encrypted or covered by TDE"
                        Remediation    = "Use BACKUP DATABASE ... WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = <cert>), or enable TDE (TDE-encrypted databases produce automatically encrypted backups)."
                        Reference      = "SOC 2 TSC CC6.7 — Restriction of Unauthorized Access"
                        SqlQuery       = $qBackupEnc
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.7a: $($_.Exception.Message)" }

                # SOC2-CC6.7b TDE scope review — Manual: CC6.7 requires protecting confidential
                # data at rest; which databases are in scope is environment-specific.
                try {
                    $count = $tdeCC6.UnencryptedCount
                    $splatCheck = @{
                        CheckId        = "CC6.7b"
                        CheckName      = "TDE Scope Review"
                        Category       = "Logical Access"
                        AssessmentType = "Manual"
                        Priority       = "Medium"
                        Status         = "Manual"
                        CurrentValue   = "$count user database(s) without TDE"
                        ExpectedValue  = "TDE enabled on all databases storing confidential information in SOC 2 scope"
                        Remediation    = "Identify in-scope databases per your data classification. For each: Enable-DbaDatabaseEncryption -SqlInstance $instance -Database <dbname>. Requires a database master key and certificate in [master]."
                        Reference      = "SOC 2 TSC CC6.7 — Encryption of Confidential Data"
                        SqlQuery       = "SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted = 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.7b: $($_.Exception.Message)" }

                # SOC2-CC6.7c Symmetric key algorithms — CC6.7: strong cryptography required.
                # Only AES_128, AES_192, or AES_256 are acceptable for protecting confidential data.
                try {
                    $weakKeysCC6 = $symDataCC6.WeakCount
                    $splatCheck = @{
                        CheckId        = "CC6.7c"
                        CheckName      = "Symmetric Key Algorithms — AES Only"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($weakKeysCC6 -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeysCC6 non-AES symmetric key(s) across all user databases"
                        ExpectedValue  = "0 — all symmetric keys use AES_128, AES_192, or AES_256"
                        Remediation    = "Per database: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256'). Recreate using a supported algorithm before dropping old keys."
                        Reference      = "SOC 2 TSC CC6.7 — Strong Cryptography"
                        SqlQuery       = $symDataCC6.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.7c: $($_.Exception.Message)" }

                # SOC2-CC6.8 No UNSAFE CLR assemblies — CC6.8: prevent introduction of unauthorized
                # or malicious software. UNSAFE CLR runs with the SQL Server service account's OS privileges.
                try {
                    $unsafeCountCC6 = $clrCC6.UnsafeCount
                    $splatCheck = @{
                        CheckId        = "CC6.8"
                        CheckName      = "No UNSAFE CLR Assemblies"
                        Category       = "Logical Access"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($unsafeCountCC6 -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unsafeCountCC6 -eq 0) { "None" } else { "$unsafeCountCC6 UNSAFE assembly(s): $($clrCC6.Names -join ', ')" }
                        ExpectedValue  = "0 UNSAFE CLR assemblies in any user database"
                        Remediation    = "Review each UNSAFE assembly. If not required: DROP ASSEMBLY [<name>]. On SQL Server 2017+: EXEC sp_configure 'clr strict security', 1; RECONFIGURE;"
                        Reference      = "SOC 2 TSC CC6.8 — Malicious Software Prevention"
                        SqlQuery       = $clrCC6.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC6.8: $($_.Exception.Message)" }
            }

            # ── §CC7 System Operations ────────────────────────────────────────────
            if (ShouldRun "CC7") {
                Write-Verbose "[$instance] §CC7 System Operations"

                $auditDataCC7 = Get-SqlAudits        -ctx $connSplat
                $traceDataCC7 = Get-DefaultTrace      -ctx $connSplat
                $retDataCC7   = Get-ErrorLogRetention -ctx $connSplat
                $opDataCC7    = Get-AgentOperators    -ctx $connSplat
                $alertDataCC7 = Get-SqlAlerts         -ctx $connSplat
                $mailDataCC7  = Get-DatabaseMail      -ctx $connSplat

                # SOC2-CC7.1 Patch level current — CC7.1: identify and monitor for vulnerabilities
                # that could threaten achievement of service commitments and system requirements.
                try {
                    $splatBuild = @{
                        SqlInstance   = $instance
                        MaxBehind     = "1CU"
                        WarningAction = "SilentlyContinue"
                    }
                    if ($SqlCredential) { $splatBuild.SqlCredential = $SqlCredential }
                    $buildResult = Test-DbaBuild @splatBuild | Select-Object -First 1
                    if ($buildResult) {
                        $splatCheck = @{
                            CheckId        = "CC7.1"
                            CheckName      = "Patch Level Current"
                            Category       = "System Operations"
                            AssessmentType = "Automated"
                            Priority       = "High"
                            Status         = if ($buildResult.Compliant) { "Pass" } else { "Fail" }
                            CurrentValue   = $buildResult.BuildLevel.ToString()
                            ExpectedValue  = $buildResult.BuildTarget.ToString()
                            Remediation    = "Apply the latest Cumulative Update. Run Test-DbaBuild -SqlInstance $instance -MaxBehind '0CU' -Update to refresh the local build reference cache."
                            Reference      = "SOC 2 TSC CC7.1 — Vulnerability Detection"
                            SqlQuery       = "SELECT @@VERSION;  -- Automated via Test-DbaBuild -MaxBehind '1CU'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOC2-CC7.1: $($_.Exception.Message)" }

                # SOC2-CC7.2a Audit captures login events — CC7.2: monitor system components for
                # anomalies that indicate unauthorized acts. Failed logins are the primary indicator
                # of brute-force or unauthorized access attempts.
                try {
                    $found = ($auditDataCC7.EnabledRows | Where-Object { $_.audit_action_id -in 'LGFL', 'LGSD' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "CC7.2a"
                        CheckName      = "Audit — Login Events Captured"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "Critical"
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "FAILED_LOGIN_GROUP and SUCCESSFUL_LOGIN_GROUP active" } else { "Not configured" }
                        ExpectedValue  = "FAILED_LOGIN_GROUP and SUCCESSFUL_LOGIN_GROUP in an active audit specification"
                        Remediation    = "Add FAILED_LOGIN_GROUP and SUCCESSFUL_LOGIN_GROUP to your active SERVER AUDIT SPECIFICATION."
                        Reference      = "SOC 2 TSC CC7.2 — Anomaly Detection"
                        SqlQuery       = $auditDataCC7.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.2a: $($_.Exception.Message)" }

                # SOC2-CC7.2b Default trace enabled — CC7.2: baseline change and security
                # event evidence captured to the SQL Server error log folder.
                try {
                    $defTraceCC7 = $traceDataCC7.Config
                    if ($defTraceCC7) {
                        $splatCheck = @{
                            CheckId        = "CC7.2b"
                            CheckName      = "Default Trace Enabled"
                            Category       = "System Operations"
                            AssessmentType = "Automated"
                            Priority       = "Low"
                            Status         = if ($defTraceCC7.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $defTraceCC7.RunningValue.ToString()
                            ExpectedValue  = "1 (enabled)"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "SOC 2 TSC CC7.2 — Detection Infrastructure"
                            SqlQuery       = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'default trace enabled';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] SOC2-CC7.2b: $($_.Exception.Message)" }

                # SOC2-CC7.3a Error log retention — CC7.3: evaluate and communicate security events.
                # Too few log files limits the forensic window available during an audit period.
                try {
                    $countCC7a   = $retDataCC7.Count
                    $displayCC7a = $retDataCC7.Display
                    $splatCheck = @{
                        CheckId        = "CC7.3a"
                        CheckName      = "Error Log Retention"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($countCC7a -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $displayCC7a
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12"
                        Reference      = "SOC 2 TSC CC7.3 — Security Event Evaluation"
                        SqlQuery       = "DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, 6) AS NumberOfLogFiles;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.3a: $($_.Exception.Message)" }

                # SOC2-CC7.3b Audit captures role membership changes — CC7.3: changes to privilege
                # assignments are security events that must be evaluated and attributed.
                try {
                    $found = ($auditDataCC7.EnabledRows | Where-Object { $_.audit_action_id -in 'ADSP', 'ADDP' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "CC7.3b"
                        CheckName      = "Audit — Role Membership Changes"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP captured"
                        Remediation    = "Add SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP to your active SERVER AUDIT SPECIFICATION."
                        Reference      = "SOC 2 TSC CC7.3 — Security Event Evaluation"
                        SqlQuery       = $auditDataCC7.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.3b: $($_.Exception.Message)" }

                # SOC2-CC7.3c Audit captures DDL/schema changes — CC7.3: object creation and
                # modification are security events that must be attributed to authorized requests.
                try {
                    $found = ($auditDataCC7.EnabledRows | Where-Object { $_.audit_action_id -in 'SCHM', 'DAUC', 'CDBR' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "CC7.3c"
                        CheckName      = "Audit — DDL / Schema Changes"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP or DATABASE_CHANGE_GROUP captured"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to your active SERVER AUDIT SPECIFICATION."
                        Reference      = "SOC 2 TSC CC7.3 — Change Accountability"
                        SqlQuery       = $auditDataCC7.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.3c: $($_.Exception.Message)" }

                # SOC2-CC7.4a SQL Agent operator configured — CC7.4: respond to identified security
                # events. A named recipient must exist to receive failure and alert notifications.
                try {
                    $count = $opDataCC7.Count
                    $splatCheck = @{
                        CheckId        = "CC7.4a"
                        CheckName      = "SQL Agent Operator Configured"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count enabled operator(s) with email address"
                        ExpectedValue  = "At least 1 enabled operator with an email address"
                        Remediation    = "EXEC msdb.dbo.sp_add_operator @name = N'DBA Team', @enabled = 1, @email_address = N'dba@company.com';"
                        Reference      = "SOC 2 TSC CC7.4 — Incident Response"
                        SqlQuery       = "SELECT name, enabled, email_address FROM msdb.dbo.sysoperators WHERE enabled = 1 AND email_address IS NOT NULL AND email_address <> '';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.4a: $($_.Exception.Message)" }

                # SOC2-CC7.4b Severity 19-25 alerts — CC7.4: data-threatening SQL Server errors
                # must generate notifications for timely incident response.
                try {
                    $sevAlertsCC7 = $alertDataCC7.SevAlerts
                    $missingSev   = 19..25 | Where-Object {
                        $sev = $_
                        -not ($sevAlertsCC7 | Where-Object { $_.Severity -eq $sev })
                    }
                    $splatCheck = @{
                        CheckId        = "CC7.4b"
                        CheckName      = "Alerts — Severity 19-25"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($missingSev.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingSev.Count -eq 0) { "All severity levels covered" } else { "Missing alerts for severity: $($missingSev -join ', ')" }
                        ExpectedValue  = "Enabled alert for each severity level 19-25"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Severity 019', @message_id = 0, @severity = 19, @enabled = 1;  -- Repeat for each missing severity and assign to an operator."
                        Reference      = "SOC 2 TSC CC7.4 — Incident Detection"
                        SqlQuery       = "SELECT severity, name, enabled FROM msdb.dbo.sysalerts WHERE severity BETWEEN 19 AND 25 AND enabled = 1 ORDER BY severity;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.4b: $($_.Exception.Message)" }

                # SOC2-CC7.4c Database Mail configured — CC7.4: delivery mechanism required for
                # all operational and security alert notifications.
                try {
                    $count = $mailDataCC7.Count
                    $splatCheck = @{
                        CheckId        = "CC7.4c"
                        CheckName      = "Database Mail Configured"
                        Category       = "System Operations"
                        AssessmentType = "Automated"
                        Priority       = "Low"
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count mail profile(s) configured"
                        ExpectedValue  = "At least 1 Database Mail profile"
                        Remediation    = "Configure Database Mail via SSMS > Management > Database Mail, or enable with: EXEC sp_configure 'Database Mail XPs', 1; RECONFIGURE;"
                        Reference      = "SOC 2 TSC CC7.4 — Incident Response Notifications"
                        SqlQuery       = "SELECT name FROM msdb.dbo.sysmail_profile;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC7.4c: $($_.Exception.Message)" }
            }

            # ── §CC8 Change Management ────────────────────────────────────────────
            if (ShouldRun "CC8") {
                Write-Verbose "[$instance] §CC8 Change Management"

                $jobDataCC8 = Get-AgentJobOwners -ctx $connSplat

                # SOC2-CC8.1 Agent job ownership — CC8.1: authorize and approve changes before
                # implementation. Ownerless jobs have no accountability chain.
                try {
                    $count = $jobDataCC8.OwnerlessCount
                    $splatCheck = @{
                        CheckId        = "CC8.1"
                        CheckName      = "Agent Job Ownership"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All jobs have owners" } else { "$count job(s) without an owner" }
                        ExpectedValue  = "All SQL Agent jobs have a named owner login"
                        Remediation    = "EXEC msdb.dbo.sp_update_job @job_name = N'<jobname>', @owner_login_name = N'<login>';"
                        Reference      = "SOC 2 TSC CC8.1 — Change Authorization"
                        SqlQuery       = "SELECT name FROM msdb.dbo.sysjobs WHERE owner_sid IS NULL;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC8.1: $($_.Exception.Message)" }
            }

            # ── §CC9 Risk Mitigation ──────────────────────────────────────────────
            if (ShouldRun "CC9") {
                Write-Verbose "[$instance] §CC9 Risk Mitigation"

                # SOC2-CC9.2 Linked server review — Manual: CC9.2 requires assessing and managing
                # risks from vendors and business partners. Linked servers create trust relationships
                # to external systems that require formal risk assessment and documentation.
                # No dbatools equivalent needed beyond Get-DbaLinkedServer.
                try {
                    $linkedServers = Get-DbaLinkedServer @connSplat -WarningAction SilentlyContinue
                    $count         = if ($linkedServers) { @($linkedServers).Count } else { 0 }
                    $splatCheck    = @{
                        CheckId        = "CC9.2"
                        CheckName      = "Linked Server Review"
                        Category       = "Risk Mitigation"
                        AssessmentType = "Manual"
                        Priority       = "High"
                        Status         = "Manual"
                        CurrentValue   = if ($count -eq 0) { "No linked servers configured" } else { "$count linked server(s): $($linkedServers.Name -join ', ')" }
                        ExpectedValue  = "All linked servers documented, business-justified, and using least-privilege credentials"
                        Remediation    = "For each linked server: verify business need is documented, confirm credentials use least-privilege accounts, confirm RPC Out is disabled unless required. Remove unused: DROP SERVER [<name>];"
                        Reference      = "SOC 2 TSC CC9.2 — Vendor and Business Partner Risk"
                        SqlQuery       = "SELECT name, product, provider, data_source, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] SOC2-CC9.2: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] SOC 2 assessment complete"
        }
    }

    end {}
}
