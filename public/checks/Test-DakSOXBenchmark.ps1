Get-ChildItem "$PSScriptRoot\Private\*.ps1" | ForEach-Object { . $_.FullName }

function Test-DakSOXBenchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against SOX IT General Controls (ITGC).

    .DESCRIPTION
        Evaluates SQL Server configuration and operational state against
        Sarbanes-Oxley (SOX) Section 404 IT general control requirements.
        Returns one result object per check per instance (type: DakSqlKit.AuditResult).

        SOX ITGC controls assessed:
            §AC — Access Controls          (13 checks: ITGC-AC-01 – ITGC-AC-11)
            §CM — Change Management        ( 1 check : ITGC-CM-05)
            §OP — Computer Operations      ( 6 checks: ITGC-OP-01 – ITGC-OP-05)
            §BA — Backup and Recovery      ( 6 checks: ITGC-BA-01 – ITGC-BA-05)
            §LS — Logical Security/Config  ( 7 checks: ITGC-LS-01 – ITGC-LS-05)
            §AL — Audit Logging            ( 7 checks: ITGC-AL-01 – ITGC-AL-04)

        AssessmentType on each result:
            Automated — pass/fail determined by the tool
            Review    — tool collected evidence; a human must sign off on the finding
            Manual    — tool collected evidence; a human must determine compliance

        Review results have Compliant = $null. Status is Review unless a hard
        violation was detected, in which case Status may be Fail.

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        ITGC categories to run: AC, CM, OP, BA, LS, AL, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, Review, and Manual results.

    .PARAMETER Quiet
        Suppress console progress output.

    .EXAMPLE
        Test-DakSOXBenchmark -SqlInstance 'SQLPROD01'

    .EXAMPLE
        Test-DakSOXBenchmark -SqlInstance 'SQLPROD01' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Get-DbaRegisteredServer -Group Production | Test-DakSOXBenchmark -Section AC,AL
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$SqlInstance,

        [Parameter()]
        [PSCredential]$SqlCredential,

        [Parameter()]
        [ValidateSet("AC", "CM", "OP", "BA", "LS", "AL", "All")]
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

            if (-not $Quiet) { Write-Host "SOX IT General Controls — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] SOX ITGC assessment — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

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
                    "Pass"    { "Green"   }
                    "Fail"    { "Red"     }
                    "Warning" { "Yellow"  }
                    "Manual"  { "Cyan"    }
                    "Review"  { "Magenta" }
                    default   { "Gray"    }
                }
                if (-not $Quiet) { Write-Host ("  [{0,-14}] {1,-50} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Manual", "Review", "Error") {
                    $r
                }
            }

            # ── §AC Access Controls ───────────────────────────────────────────────
            if (ShouldRun "AC") {
                Write-Verbose "[$instance] §AC Access Controls"

                # ITGC-AC-01 User provisioning evidence — new server principals in the past 90 days.
                try {
                    $newData  = Get-NewPrincipals -ctx $connSplat
                    $count    = $newData.Count
                    $nameList = if ($count -gt 0) {
                        ($newData.Principals | ForEach-Object { "$($_.name) ($($_.type_desc))" }) -join ', '
                    } else { $null }
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-01"
                        CheckName      = "User Provisioning Evidence"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Review" }
                        CurrentValue   = if ($count -eq 0) { "No new principals in the past 90 days" } else { "$count new principal(s): $nameList" }
                        ExpectedValue  = "Each new principal has an approved access request on file"
                        Remediation    = if ($count -gt 0) { "Verify that each principal listed has a corresponding approved access request. Remove any accounts that cannot be justified." } else { $null }
                        Reference      = "SOX §404 — User Provisioning and Access Controls"
                        SqlQuery       = $newData.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-01: $($_.Exception.Message)" }

                # ITGC-AC-03 Orphaned database users — user accounts with no corresponding login.
                try {
                    $orphanData = Get-OrphanedUsers -ctx $connSplat
                    $count      = $orphanData.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-03"
                        CheckName      = "Orphaned Database Users"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count orphaned user(s)" }
                        ExpectedValue  = "0 orphaned database users"
                        Remediation    = "Repair-DbaDbOrphanUser -SqlInstance $instance  -- or DROP USER [<name>] in each affected database after verifying no active session dependency."
                        Reference      = "SOX §404 — Access Termination"
                        SqlQuery       = "-- Via Get-OrphanedUsers / Get-DbaDbOrphanUser. T-SQL: SELECT dp.name, dp.type_desc FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE dp.type IN ('S','U','G') AND dp.sid IS NOT NULL AND sp.sid IS NULL AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys');"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-03: $($_.Exception.Message)" }

                # ITGC-AC-04 Privileged access inventory — sysadmin and CONTROL SERVER principals.
                try {
                    $sysData4  = Get-SysadminLogins -ctx $connSplat
                    $sqlData4  = Get-SqlAuthLogins -ctx $connSplat
                    $qCtlSvr   = "SELECT sp.name FROM sys.server_principals sp JOIN sys.server_permissions p ON sp.principal_id = p.grantee_principal_id WHERE p.type = 'CL' AND p.state IN ('G','W') AND sp.name NOT LIKE '##%';"
                    $ctlRows   = Invoke-DbaQuery @connSplat -Query $qCtlSvr -WarningAction SilentlyContinue
                    $ctlNames  = if ($ctlRows) { @($ctlRows | Select-Object -ExpandProperty name) } else { @() }

                    $sysNames    = $sysData4.Names
                    $allPriv     = ($sysNames + $ctlNames) | Select-Object -Unique | Sort-Object
                    $privEntries = foreach ($n in $allPriv) {
                        $src      = @()
                        if ($n -in $sysNames) { $src += 'sysadmin' }
                        if ($n -in $ctlNames) { $src += 'CONTROL SERVER' }
                        $authType = if ($n -in $sqlData4.Names) { 'SQL auth' } else { 'Windows auth' }
                        "$n [$authType, $($src -join '+')]"
                    }
                    $count = $allPriv.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-04"
                        CheckName      = "Privileged Access Inventory"
                        Category       = "Access Control"
                        AssessmentType = "Review"
                        Priority       = "Critical"
                        Status         = "Review"
                        CurrentValue   = if ($count -eq 0) { "No sysadmin or CONTROL SERVER accounts found" } else { "$count account(s): $($privEntries -join '; ')" }
                        ExpectedValue  = "All privileged accounts documented, justified, and formally approved"
                        Remediation    = "Review each account listed. Remove any not formally approved: ALTER SERVER ROLE [sysadmin] DROP MEMBER [<account>];"
                        Reference      = "SOX §404 — Privileged Access Controls"
                        SqlQuery       = $qCtlSvr
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-04: $($_.Exception.Message)" }

                # ITGC-AC-05 Sysadmin membership formal review — Fail if unapproved SQL auth accounts present.
                try {
                    $exceptions = @('DYNAMICS_SVC')
                    $sysData5   = Get-SysadminLogins -ctx $connSplat
                    $sqlData5   = Get-SqlAuthLogins -ctx $connSplat
                    $sysNames5  = $sysData5.Names
                    $sqlAuthSys = @($sysNames5 | Where-Object { $_ -in $sqlData5.Names })
                    $winAuthSys = @($sysNames5 | Where-Object { $_ -notin $sqlData5.Names })
                    $excepted   = @($sqlAuthSys | Where-Object { $_ -in $exceptions })
                    $violations = @($sqlAuthSys | Where-Object { $_ -notin $exceptions })
                    $status     = if ($violations.Count -gt 0) { "Fail" } else { "Review" }
                    $finding    = if ($violations.Count -gt 0) {
                        "Unapproved SQL auth sysadmin(s): $($violations -join ', ')"
                    } else {
                        "All SQL auth sysadmins are in the approved exceptions list"
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-05"
                        CheckName      = "Sysadmin Membership Review"
                        Category       = "Access Control"
                        AssessmentType = "Review"
                        Priority       = "Critical"
                        Status         = $status
                        CurrentValue   = "Total: $($sysNames5.Count) | Windows auth: $($winAuthSys.Count) | SQL auth: $($sqlAuthSys.Count) (excepted: $($excepted.Count), violations: $($violations.Count)) — $finding"
                        ExpectedValue  = "All SQL auth sysadmin logins are in the approved exceptions list; all members recertified at least annually"
                        Remediation    = if ($status -eq "Fail") {
                            "Remove unapproved SQL auth sysadmin account(s): $($violations -join ', '). To approve a legitimate SQL auth sysadmin, add its name to the exceptions list in ITGC-AC-05."
                        } else {
                            "Confirm continued business need for all $($sysNames5.Count) sysadmin member(s) and document the recertification."
                        }
                        Reference      = "SOX §404 — Privileged Access Review"
                        SqlQuery       = "-- Via Get-SysadminLogins + Get-SqlAuthLogins. T-SQL: SELECT DISTINCT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-05: $($_.Exception.Message)" }

                # ITGC-AC-06 Periodic access recertification — orphans = Fail, otherwise Review.
                try {
                    $userData6   = Get-DatabaseUsers -ctx $connSplat
                    $orphanData6 = Get-OrphanedUsers -ctx $connSplat
                    $ownerData6  = Get-DbOwnerMembers -ctx $connSplat
                    $allDbUsers  = $userData6.Users
                    $orphans6    = $orphanData6.Orphans
                    $dbOwners    = $ownerData6.Members

                    $userCount   = $userData6.Count
                    $ownerCount  = $ownerData6.Count
                    $orphanCount = $orphanData6.Count

                    $status6 = if ($orphanCount -gt 0) { "Fail" } else { "Review" }
                    $finding6 = if ($orphanCount -gt 0) {
                        "Orphaned users (no matching login): $((@($orphans6) | ForEach-Object { "$($_.UserName) in $($_.Database)" }) -join ', ')"
                    } else {
                        "$ownerCount db_owner member(s) require recertification evidence"
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-06"
                        CheckName      = "Periodic Access Recertification"
                        Category       = "Access Control"
                        AssessmentType = "Review"
                        Priority       = "High"
                        Status         = $status6
                        CurrentValue   = "Total DB users: $userCount | db_owner members: $ownerCount | Orphaned: $orphanCount — $finding6"
                        ExpectedValue  = "All database user accounts recertified by a data owner at least annually; 0 orphaned users"
                        Remediation    = "Present the user list to database owners for formal recertification. $(if ($orphanCount -gt 0) { "Remove orphaned users: Repair-DbaDbOrphanUser -SqlInstance $instance" })"
                        Reference      = "SOX §404 — Periodic Access Review"
                        SqlQuery       = "-- Via Get-DatabaseUsers, Get-DbOwnerMembers, Get-OrphanedUsers."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-06: $($_.Exception.Message)" }

                # ITGC-AC-08a sa login disabled — SID 0x01 catches renamed sa accounts.
                try {
                    $saData  = Get-SaLogin -ctx $connSplat
                    $saLogin = $saData.Login
                    $enabled = $saLogin -and -not $saLogin.IsDisabled
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-08a"
                        CheckName      = "sa Login Disabled"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if (-not $enabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($enabled) { "Enabled (name: $($saLogin.Name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "Disable the sa account: USE [master]; DECLARE @n NVARCHAR(256) = SUSER_NAME(0x01); EXEC ('ALTER LOGIN [' + @n + '] DISABLE');"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Via Get-SaLogin (SID 0x01). T-SQL: SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-08a: $($_.Exception.Message)" }

                # ITGC-AC-08b sa login renamed — well-known name is a direct attack target.
                try {
                    $saData  = Get-SaLogin -ctx $connSplat
                    $saLogin = $saData.Login
                    if ($saLogin) {
                        $splatCheck = @{
                            CheckId        = "ITGC-AC-08b"
                            CheckName      = "sa Login Renamed"
                            Category       = "Access Control"
                            AssessmentType = "Automated"
                            Priority       = "Medium"
                            Status         = if ($saLogin.Name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saLogin.Name
                            ExpectedValue  = "Any name other than 'sa'"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "SOX §404 — Logical Access Controls"
                            SqlQuery       = "-- Via Get-SaLogin (SID 0x01). T-SQL: SELECT name FROM sys.server_principals WHERE sid = 0x01;  -- Name should not be 'sa'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] ITGC-AC-08b: $($_.Exception.Message)" }

                # ITGC-AC-08c No BUILTIN groups — local admin membership outside SQL Server provisioning.
                try {
                    $builtinData = Get-BuiltinGroups -ctx $connSplat
                    $count       = $builtinData.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-08c"
                        CheckName      = "BUILTIN Groups Absent"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtinData.Names -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "BUILTIN groups grant SQL access to all local admins outside SQL Server's provisioning process. Confirm domain group equivalents exist, then: USE [master]; DROP LOGIN [BUILTIN\Administrators];"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Via Get-BuiltinGroups / Get-DbaLogin. T-SQL: SELECT name FROM sys.server_principals WHERE name LIKE 'BUILTIN%';  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-08c: $($_.Exception.Message)" }

                # ITGC-AC-08d Guest CONNECT revoked — bypasses formal user provisioning.
                try {
                    $guestData = Get-GuestAccess -ctx $connSplat
                    $count     = $guestData.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-08d"
                        CheckName      = "Guest Access Revoked"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "Revoked in all user databases" } else { "Active in: $($guestData.DatabaseNames -join ', ')" }
                        ExpectedValue  = "CONNECT revoked in all user databases"
                        Remediation    = "USE [<database>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Via Get-GuestAccess / Get-DbaDbUser. T-SQL per user DB: SELECT permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-08d: $($_.Exception.Message)" }

                # ITGC-AC-09 Service account inventory — Fail if unclassified SQL auth logins exist.
                try {
                    $svcPattern = '^(svc[_\-]|service[_\-]|app[_\-]|etl[_\-]|batch[_\-]|report|ssrs|ssis|agent|sa$)'
                    $sqlData9   = Get-SqlAuthLogins -ctx $connSplat
                    $sqlLogins9 = $sqlData9.Logins
                    $totalCount9   = $sqlData9.Count
                    $matched9      = @($sqlLogins9 | Where-Object { $_.Name -match $svcPattern })
                    $unclassified9 = @($sqlLogins9 | Where-Object { $_.Name -notmatch $svcPattern })
                    $status9       = if ($unclassified9.Count -gt 0) { "Fail" } else { "Review" }
                    $finding9      = if ($unclassified9.Count -gt 0) {
                        "Unclassified SQL auth login(s): $($unclassified9.Name -join ', ')"
                    } else {
                        "All $totalCount9 SQL auth login(s) match known service account naming patterns"
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-09"
                        CheckName      = "Service Account Inventory"
                        Category       = "Access Control"
                        AssessmentType = "Review"
                        Priority       = "Medium"
                        Status         = $status9
                        CurrentValue   = "Total SQL auth: $totalCount9 | Pattern-matched: $($matched9.Count) | Unclassified: $($unclassified9.Count) — $finding9"
                        ExpectedValue  = "All SQL auth logins documented as approved service accounts; no shared or generic accounts"
                        Remediation    = if ($status9 -eq "Fail") {
                            "Investigate unclassified SQL auth login(s): $($unclassified9.Name -join ', '). Each SQL login must have a documented owner and business justification. Disable or remove accounts that cannot be justified."
                        } else {
                            "Verify that each matched account has a named owner and formal service account registration on file."
                        }
                        Reference      = "SOX §404 — Service Account Management"
                        SqlQuery       = "-- Via Get-SqlAuthLogins / Get-DbaLogin -Type SQL. T-SQL: SELECT name, is_disabled, create_date FROM sys.sql_logins WHERE name NOT LIKE '##%' ORDER BY name;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-09: $($_.Exception.Message)" }

                # ITGC-AC-10a SQL logins enforce password policy.
                try {
                    $sqlData10a = Get-SqlAuthLogins -ctx $connSplat
                    $noPolicy   = @($sqlData10a.Logins | Where-Object { -not $_.PasswordPolicyEnforced })
                    $count      = $noPolicy.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-10a"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count logins without CHECK_POLICY" }
                        ExpectedValue  = "CHECK_POLICY = ON for all SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON;  -- Enumerate: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Via Get-SqlAuthLogins / Get-DbaLogin. T-SQL: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-10a: $($_.Exception.Message)" }

                # ITGC-AC-10b Privileged SQL logins enforce password expiration.
                try {
                    $qAC10b = @"
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
                    $expRows = Invoke-DbaQuery @connSplat -Query $qAC10b -WarningAction SilentlyContinue
                    $count   = if ($expRows) { @($expRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-10b"
                        CheckName      = "Privileged Login Password Expiration"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count privileged logins without CHECK_EXPIRATION" }
                        ExpectedValue  = "CHECK_EXPIRATION = ON for all privileged SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = $qAC10b
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-10b: $($_.Exception.Message)" }

                # ITGC-AC-11 Windows-only auth — SQL logins bypass Active Directory provisioning.
                try {
                    $authData = Get-AuthMode -ctx $connSplat
                    $winOnly  = ($authData.LoginMode -eq 1)
                    $splatCheck = @{
                        CheckId        = "ITGC-AC-11"
                        CheckName      = "Windows-Only Authentication"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only (LoginMode = 1)"
                        Remediation    = "Mixed mode allows SQL logins that exist outside AD and bypass de-provisioning. Change to Windows Authentication: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- Restart required."
                        Reference      = "SOX §404 — Logical Access Controls"
                        SqlQuery       = "-- Via Get-AuthMode / Get-DbaInstanceProperty. T-SQL: SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AC-11: $($_.Exception.Message)" }
            }

            # ── §CM Change Management ─────────────────────────────────────────────
            if (ShouldRun "CM") {
                Write-Verbose "[$instance] §CM Change Management"

                # ITGC-CM-05 Agent jobs have owners — ownerless jobs have no accountability chain.
                try {
                    $jobData = Get-AgentJobOwners -ctx $connSplat
                    $count   = $jobData.OwnerlessCount
                    $splatCheck = @{
                        CheckId        = "ITGC-CM-05"
                        CheckName      = "Agent Job Ownership"
                        Category       = "Change Management"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All jobs have owners" } else { "$count jobs without an owner" }
                        ExpectedValue  = "All jobs have a named owner login"
                        Remediation    = "EXEC msdb.dbo.sp_update_job @job_name = N'<jobname>', @owner_login_name = N'<login>';"
                        Reference      = "SOX §404 — Change Accountability"
                        SqlQuery       = "-- Via Get-AgentJobOwners / Get-DbaAgentJob. T-SQL: SELECT name, owner_sid FROM msdb.dbo.sysjobs WHERE owner_sid IS NULL;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-CM-05: $($_.Exception.Message)" }
            }

            # ── §OP Computer Operations ───────────────────────────────────────────
            if (ShouldRun "OP") {
                Write-Verbose "[$instance] §OP Computer Operations"

                # ITGC-OP-01a SQL Agent operator configured — no operator means no alert delivery path.
                try {
                    $opData = Get-AgentOperators -ctx $connSplat
                    $count  = $opData.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-01a"
                        CheckName      = "SQL Agent Operator Configured"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count enabled operator(s) with email address"
                        ExpectedValue  = "At least 1 enabled operator with an email address"
                        Remediation    = "EXEC msdb.dbo.sp_add_operator @name = N'DBA Team', @enabled = 1, @email_address = N'dba@company.com';"
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Via Get-AgentOperators / Get-DbaAgentOperator. T-SQL: SELECT name, enabled, email_address FROM msdb.dbo.sysoperators WHERE enabled = 1 AND email_address IS NOT NULL AND email_address <> '';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-01a: $($_.Exception.Message)" }

                # ITGC-OP-01b Alerts for severity 19–25 — data-threatening SQL Server errors.
                try {
                    $alertData  = Get-SqlAlerts -ctx $connSplat
                    $missingSev = 19..25 | Where-Object {
                        $sev = $_
                        -not ($alertData.SevAlerts | Where-Object { $_.Severity -eq $sev })
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-01b"
                        CheckName      = "Alerts — Severity 19-25"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($missingSev.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingSev.Count -eq 0) { "All severity levels covered" } else { "Missing alerts for severity: $($missingSev -join ', ')" }
                        ExpectedValue  = "Enabled alert for each severity level 19–25"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Severity 019', @message_id = 0, @severity = 19, @enabled = 1;  -- Repeat for each missing severity."
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Via Get-SqlAlerts / Get-DbaAgentAlert. T-SQL: SELECT severity, name, enabled FROM msdb.dbo.sysalerts WHERE severity BETWEEN 19 AND 25 AND enabled = 1 ORDER BY severity;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-01b: $($_.Exception.Message)" }

                # ITGC-OP-01c Database Mail configured — delivery path for operational alerts.
                try {
                    $mailData = Get-DatabaseMail -ctx $connSplat
                    $count    = $mailData.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-01c"
                        CheckName      = "Database Mail Configured"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "Low"
                        Status         = if ($count -gt 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count mail profile(s) configured"
                        ExpectedValue  = "At least 1 Database Mail profile"
                        Remediation    = "Configure Database Mail in SSMS > Management > Database Mail. Verify: EXEC msdb.dbo.sysmail_help_profile_sp;"
                        Reference      = "SOX §404 — Operational Monitoring"
                        SqlQuery       = "-- Via Get-DatabaseMail / Get-DbaDbMailProfile. T-SQL: SELECT name, description FROM msdb.dbo.sysmail_profile;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-01c: $($_.Exception.Message)" }

                # ITGC-OP-02 Alerts for I/O errors 823, 824, 825 — potential silent data corruption.
                try {
                    $alertData  = Get-SqlAlerts -ctx $connSplat
                    $missingIo  = @(823, 824, 825) | Where-Object {
                        $mid = $_
                        -not ($alertData.IoAlerts | Where-Object { $_.MessageId -eq $mid })
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-02"
                        CheckName      = "Alerts — I/O Errors 823/824/825"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($missingIo.Count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($missingIo.Count -eq 0) { "All three I/O error alerts configured" } else { "Missing alert for error(s): $($missingIo -join ', ')" }
                        ExpectedValue  = "Enabled alert for error numbers 823, 824, and 825"
                        Remediation    = "EXEC msdb.dbo.sp_add_alert @name = N'Error 823', @message_id = 823, @severity = 0, @enabled = 1;  -- Repeat for 824 and 825."
                        Reference      = "SOX §404 — Data Integrity Monitoring"
                        SqlQuery       = "-- Via Get-SqlAlerts / Get-DbaAgentAlert. T-SQL: SELECT message_id, name, enabled FROM msdb.dbo.sysalerts WHERE message_id IN (823,824,825) AND enabled = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-02: $($_.Exception.Message)" }

                # ITGC-OP-04 Capacity management — Fail if max server memory is at the SQL Server default.
                try {
                    $memData   = Get-MaxMemory -ctx $connSplat
                    $maxMemCfg = $memData.Config
                    $qOP04     = "SELECT physical_memory_in_use_kb / 1024 AS MemoryInUseMB FROM sys.dm_os_process_memory;"
                    $memInfo   = Invoke-DbaQuery @connSplat -Query $qOP04 -WarningAction SilentlyContinue | Select-Object -First 1

                    $maxValue    = if ($maxMemCfg) { $maxMemCfg.MaxValue }   else { -1 }
                    $totalRam    = if ($maxMemCfg) { "$($maxMemCfg.Total) MB" }       else { "Unknown" }
                    $recommended = if ($maxMemCfg) { "$($maxMemCfg.Recommended) MB" } else { "Unknown" }
                    $memInUse    = if ($memInfo)   { "$($memInfo.MemoryInUseMB) MB" } else { "Unknown" }
                    $maxDisplay  = if ($maxValue -ge 0) { "$maxValue MB" }             else { "Unknown" }

                    $isDefault = $maxValue -eq 2147483647
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-04"
                        CheckName      = "Capacity Management"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($isDefault) { "Fail" } else { "Pass" }
                        CurrentValue   = "Max Server Memory: $maxDisplay | Total RAM: $totalRam | Recommended: $recommended | SQL Process Memory In Use: $memInUse"
                        ExpectedValue  = "Max Server Memory explicitly configured (not at default 2147483647)"
                        Remediation    = if ($isDefault) { "Configure Max Server Memory: Set-DbaMaxMemory -SqlInstance $instance -MaxMB <value>  -- Recommended value: $recommended" } else { $null }
                        Reference      = "SOX §404 — Operational Controls"
                        SqlQuery       = $qOP04
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-04: $($_.Exception.Message)" }

                # ITGC-OP-05 No inaccessible user databases.
                try {
                    $dbStatus = Get-DatabaseStatus -ctx $connSplat
                    $count    = $dbStatus.Inaccessible.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-OP-05"
                        CheckName      = "All User Databases Accessible"
                        Category       = "Computer Operations"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases accessible" } else { "$count inaccessible: $($dbStatus.Inaccessible.Name -join ', ')" }
                        ExpectedValue  = "All user databases in an accessible state"
                        Remediation    = "Investigate inaccessible databases in the SQL Server error log. Databases in Suspect/Recovery_Pending state may indicate corruption."
                        Reference      = "SOX §404 — Availability"
                        SqlQuery       = "-- Via Get-DatabaseStatus / Get-DbaDatabase. T-SQL: SELECT name, state_desc FROM sys.databases WHERE database_id > 4 AND state <> 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-OP-05: $($_.Exception.Message)" }
            }

            # ── §BA Backup and Recovery ───────────────────────────────────────────
            if (ShouldRun "BA") {
                Write-Verbose "[$instance] §BA Backup and Recovery"

                # ITGC-BA-01a All user databases have a full backup within 24 hours.
                try {
                    $dbCfg       = Get-DatabaseConfig -ctx $connSplat
                    $staleBackup = @()
                    foreach ($db in $dbCfg.Databases) {
                        $lastFull = Get-DbaDbBackupHistory @connSplat -Database $db.Name -LastFull -WarningAction SilentlyContinue |
                            Select-Object -First 1
                        if (-not $lastFull -or $lastFull.End -lt (Get-Date).AddHours(-24)) {
                            $staleBackup += $db.Name
                        }
                    }
                    $count = $staleBackup.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-01a"
                        CheckName      = "Full Backup Within 24 Hours"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Automated"
                        Priority       = "Critical"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases backed up within 24h" } else { "$count databases missing recent backup: $($staleBackup -join ', ')" }
                        ExpectedValue  = "Full backup within 24 hours for every user database"
                        Remediation    = "Investigate backup job failures: Get-DbaAgentJobHistory -SqlInstance $instance | Where-Object { `$_.JobName -like '*backup*' -and `$_.Status -ne 'Succeeded' }"
                        Reference      = "SOX §404 — Business Continuity"
                        SqlQuery       = "-- Via Get-DatabaseConfig + Get-DbaDbBackupHistory -LastFull."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-01a: $($_.Exception.Message)" }

                # ITGC-BA-01b Transaction log backed up within 4 hours for Full/BulkLogged databases.
                try {
                    $dbCfg    = Get-DatabaseConfig -ctx $connSplat
                    $staleLog = @()
                    foreach ($db in $dbCfg.FullBulkRecovery) {
                        $lastLog = Get-DbaDbBackupHistory @connSplat -Database $db.Name -LastLog -WarningAction SilentlyContinue |
                            Select-Object -First 1
                        if (-not $lastLog -or $lastLog.End -lt (Get-Date).AddHours(-4)) {
                            $staleLog += $db.Name
                        }
                    }
                    $count = $staleLog.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-01b"
                        CheckName      = "Log Backup Within 4 Hours"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All Full/BulkLogged databases have recent log backups" } else { "$count databases missing log backup: $($staleLog -join ', ')" }
                        ExpectedValue  = "Log backup within 4 hours for all Full and BulkLogged databases"
                        Remediation    = "Schedule log backup jobs: BACKUP LOG [<db>] TO DISK = N'<path>';"
                        Reference      = "SOX §404 — Recovery Point Objectives"
                        SqlQuery       = "-- Via Get-DatabaseConfig + Get-DbaDbBackupHistory -LastLog."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-01b: $($_.Exception.Message)" }

                # ITGC-BA-01c Full recovery model — Simple recovery prevents point-in-time restore.
                try {
                    $dbCfg         = Get-DatabaseConfig -ctx $connSplat
                    $simpleRecovery = $dbCfg.SimpleRecovery
                    $count          = $simpleRecovery.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-01c"
                        CheckName      = "Full Recovery Model"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($count -eq 0) { "All user databases in Full or Bulk-Logged" } else { "$count in Simple recovery: $($simpleRecovery.Name -join ', ')" }
                        ExpectedValue  = "Full recovery model for all databases in SOX scope"
                        Remediation    = "ALTER DATABASE [<dbname>] SET RECOVERY FULL;  -- Take a full backup immediately to start the log chain, then schedule regular log backups."
                        Reference      = "SOX §404 — Recovery Point Objectives"
                        SqlQuery       = "-- Via Get-DatabaseConfig / Get-DbaDatabase. T-SQL: SELECT name, recovery_model_desc FROM sys.databases WHERE database_id > 4 AND recovery_model_desc = 'SIMPLE';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-01c: $($_.Exception.Message)" }

                # ITGC-BA-02 DBCC CHECKDB within 7 days on all user databases.
                try {
                    $checkData = Get-CheckDbHistory -ctx $connSplat
                    $count     = $checkData.StaleCount
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-02"
                        CheckName      = "DBCC CHECKDB Within 7 Days"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All databases checked within 7 days" } else { "$count databases overdue: $($checkData.Stale.Database -join ', ')" }
                        ExpectedValue  = "DBCC CHECKDB completed within 7 days on all databases"
                        Remediation    = "Schedule integrity checks: Invoke-DbaDbIntegrityCheck -SqlInstance $instance -Database <db>"
                        Reference      = "SOX §404 — Data Integrity"
                        SqlQuery       = "-- Via Get-CheckDbHistory / Get-DbaLastGoodCheckDb."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-02: $($_.Exception.Message)" }

                # ITGC-BA-03 Backup encryption — unencrypted backups violate SOX data security.
                try {
                    $qBA03 = @"
SELECT COUNT(*) AS UnencBackups
FROM msdb.dbo.backupset b
JOIN sys.databases d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL
  AND b.encryptor_type IS NULL
  AND d.is_encrypted = 0
  AND b.backup_finish_date >= DATEADD(DAY, -30, GETDATE());
"@
                    $r     = Invoke-DbaQuery @connSplat -Query $qBA03 -WarningAction SilentlyContinue
                    $count = if ($r) { $r.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-03"
                        CheckName      = "Backup Encryption"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup records in the past 30 days"
                        ExpectedValue  = "0 — all backups encrypted or database encrypted via TDE"
                        Remediation    = "Enable backup encryption via WITH ENCRYPTION on BACKUP DATABASE, or enable TDE (TDE databases produce automatically encrypted backups)."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = $qBA03
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-03: $($_.Exception.Message)" }

                # ITGC-BA-05 Backup retention policy — oldest full backup age as retention evidence.
                try {
                    $backupData  = Get-BackupHistory -ctx $connSplat
                    $fullBackups = $backupData.History
                    $dbCount     = 0
                    $oldestDays  = 0
                    if ($fullBackups) {
                        $grouped    = $fullBackups | Group-Object -Property Database
                        $dbCount    = $grouped.Count
                        $oldestDate = ($fullBackups | Measure-Object -Property Start -Minimum).Minimum
                        $oldestDays = if ($oldestDate) { [int]((Get-Date) - $oldestDate).TotalDays } else { 0 }
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-BA-05"
                        CheckName      = "Backup Retention Policy"
                        Category       = "Backup and Recovery"
                        AssessmentType = "Review"
                        Priority       = "Medium"
                        Status         = "Review"
                        CurrentValue   = "$dbCount database(s) with full backup history | Oldest full backup: $oldestDays day(s) ago"
                        ExpectedValue  = "Backup retention policy documented and enforced; SOX-scope backups retained per policy (typically 7 years for financial records)"
                        Remediation    = "Review the oldest backup age above. Verify that the backup retention policy is documented, approved, and matches the schedule applied by your backup solution."
                        Reference      = "SOX §404 — Data Retention"
                        SqlQuery       = "-- Via Get-BackupHistory / Get-DbaDbBackupHistory -Type Full."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-BA-05: $($_.Exception.Message)" }
            }

            # ── §LS Logical Security / Configuration ──────────────────────────────
            if (ShouldRun "LS") {
                Write-Verbose "[$instance] §LS Logical Security / Configuration"

                # ITGC-LS-01a Page verify CHECKSUM — detects I/O corruption before it becomes permanent.
                try {
                    $dbCfg   = Get-DatabaseConfig -ctx $connSplat
                    $noCksum = $dbCfg.NoChecksum
                    $count   = $noCksum.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-01a"
                        CheckName      = "Page Verify CHECKSUM"
                        Category       = "Logical Security"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases use CHECKSUM" } else { "$count databases without CHECKSUM: $($noCksum.Name -join ', ')" }
                        ExpectedValue  = "PAGE_VERIFY = CHECKSUM for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "SOX §404 — Data Integrity"
                        SqlQuery       = "-- Via Get-DatabaseConfig / Get-DbaDatabase. T-SQL: SELECT name, page_verify_option_desc FROM sys.databases WHERE database_id > 4 AND page_verify_option_desc <> 'CHECKSUM';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-01a: $($_.Exception.Message)" }

                # ITGC-LS-01b AUTO_CLOSE disabled — unexpected connection flush is an availability risk.
                try {
                    $dbCfg     = Get-DatabaseConfig -ctx $connSplat
                    $autoClose = $dbCfg.AutoClose
                    $count     = $autoClose.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-01b"
                        CheckName      = "AUTO_CLOSE Disabled"
                        Category       = "Logical Security"
                        AssessmentType = "Automated"
                        Priority       = "Low"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count databases with AUTO_CLOSE ON: $($autoClose.Name -join ', ')" }
                        ExpectedValue  = "AUTO_CLOSE OFF for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_CLOSE OFF;"
                        Reference      = "SOX §404 — Availability"
                        SqlQuery       = "-- Via Get-DatabaseConfig / Get-DbaDatabase. T-SQL: SELECT name FROM sys.databases WHERE database_id > 4 AND is_auto_close_on = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-01b: $($_.Exception.Message)" }

                # ITGC-LS-01c AUTO_SHRINK disabled — causes fragmentation and unexpected I/O spikes.
                try {
                    $dbCfg      = Get-DatabaseConfig -ctx $connSplat
                    $autoShrink = $dbCfg.AutoShrink
                    $count      = $autoShrink.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-01c"
                        CheckName      = "AUTO_SHRINK Disabled"
                        Category       = "Logical Security"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count databases with AUTO_SHRINK ON: $($autoShrink.Name -join ', ')" }
                        ExpectedValue  = "AUTO_SHRINK OFF for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET AUTO_SHRINK OFF;"
                        Reference      = "SOX §404 — Data Integrity / Performance"
                        SqlQuery       = "-- Via Get-DatabaseConfig / Get-DbaDatabase. T-SQL: SELECT name FROM sys.databases WHERE database_id > 4 AND is_auto_shrink_on = 1;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-01c: $($_.Exception.Message)" }

                # ITGC-LS-01d TDE scope review — list databases without TDE; scoping is a business decision.
                try {
                    $tde      = Get-TdeStatus -ctx $connSplat
                    $nameList = if ($tde.UnencryptedCount -gt 0) {
                        "Unencrypted: $($tde.UnencryptedNames -join ', ')"
                    } else {
                        "All $($tde.TotalCount) user database(s) are TDE-encrypted"
                    }
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-01d"
                        CheckName      = "TDE Scope Review"
                        Category       = "Logical Security"
                        AssessmentType = "Review"
                        Priority       = "Medium"
                        Status         = "Review"
                        CurrentValue   = "Encrypted: $($tde.EncryptedCount) | Unencrypted: $($tde.UnencryptedCount) — $nameList"
                        ExpectedValue  = "TDE enabled on all databases that contain SOX financial reporting data"
                        Remediation    = "Identify databases in SOX scope from the list above. For each in-scope database: Enable-DbaDatabaseEncryption -SqlInstance $instance -Database <dbname>  -- Requires a database master key and certificate on [master]."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = "-- Via Get-TdeStatus / Get-DbaDatabase. T-SQL: SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted = 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-01d: $($_.Exception.Message)" }

                # ITGC-LS-01e Symmetric keys use AES — weak algorithms undermine data protection.
                try {
                    $symData  = Get-SymmetricKeys -ctx $connSplat
                    $weakKeys = $symData.WeakCount
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-01e"
                        CheckName      = "Symmetric Key Algorithms"
                        Category       = "Logical Security"
                        AssessmentType = "Automated"
                        Priority       = "Low"
                        Status         = if ($weakKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeys non-AES symmetric key(s)"
                        ExpectedValue  = "0 — all symmetric keys use AES_128, AES_192, or AES_256"
                        Remediation    = "Recreate non-AES symmetric keys. Per-database: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')."
                        Reference      = "SOX §404 — Data Protection at Rest"
                        SqlQuery       = $symData.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-01e: $($_.Exception.Message)" }

                # ITGC-LS-02 SQL Server patch level — no more than 1 CU behind.
                try {
                    $buildResult = Test-DbaBuild @connSplat -MaxBehind "1CU" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($buildResult) {
                        $splatCheck = @{
                            CheckId        = "ITGC-LS-02"
                            CheckName      = "SQL Server Patch Level"
                            Category       = "Logical Security"
                            AssessmentType = "Automated"
                            Priority       = "High"
                            Status         = if ($buildResult.Compliant) { "Pass" } else { "Fail" }
                            CurrentValue   = "$($buildResult.Build) — $($buildResult.BuildLevel)"
                            ExpectedValue  = "Within 1 Cumulative Update of the latest release for this SQL Server version"
                            Remediation    = "Apply the latest Cumulative Update: https://docs.microsoft.com/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"
                            Reference      = "SOX §404 — Vulnerability Management / Patch Controls"
                            SqlQuery       = "SELECT @@VERSION;  -- Via Test-DbaBuild -MaxBehind '1CU'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] ITGC-LS-02: $($_.Exception.Message)" }

                # ITGC-LS-05 Network encryption — unencrypted connections expose financial data in transit.
                try {
                    $netEnc = Get-NetworkEncryption -ctx $connSplat
                    $unenc  = $netEnc.UnencryptedCount
                    $splatCheck = @{
                        CheckId        = "ITGC-LS-05"
                        CheckName      = "Network Encryption Enforced"
                        Category       = "Logical Security"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($unenc -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unenc -eq 0) { "All non-shared-memory connections encrypted" } else { "$unenc unencrypted connection type(s) detected" }
                        ExpectedValue  = "All non-shared-memory connections encrypted"
                        Remediation    = "Enable Force Encryption in SQL Server Configuration Manager > Protocols > Properties > Force Encryption = Yes. A trusted certificate is required."
                        Reference      = "SOX §404 — Data Protection in Transit"
                        SqlQuery       = $netEnc.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-LS-05: $($_.Exception.Message)" }
            }

            # ── §AL Audit Logging ─────────────────────────────────────────────────
            if (ShouldRun "AL") {
                Write-Verbose "[$instance] §AL Audit Logging"

                # ITGC-AL-01a SQL Server Audit — required action groups for SOX detective controls.
                try {
                    $auditData   = Get-SqlAudits -ctx $connSplat
                    $required    = @(
                        "FAILED_LOGIN_GROUP",
                        "SUCCESSFUL_LOGIN_GROUP",
                        "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
                        "SERVER_ROLE_MEMBER_CHANGE_GROUP",
                        "AUDIT_CHANGE_GROUP"
                    )
                    $foundGroups = $auditData.ActionNames | Where-Object { $_ -in $required }
                    $missing     = $required | Where-Object { $_ -notin $auditData.ActionNames }
                    $compliant   = $missing.Count -eq 0
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-01a"
                        CheckName      = "SQL Server Audit — SOX Action Groups"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "Critical"
                        Status         = if ($compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($auditData.ActionNames.Count -eq 0) { "No enabled audit" } else { "$(@($foundGroups).Count) of $($required.Count) required groups captured" }
                        ExpectedValue  = "All 5 SOX action groups enabled in an active audit and specification"
                        Remediation    = if ($compliant) { $null } else { "Missing groups: $($missing -join ', '). Create a SERVER AUDIT and SERVER AUDIT SPECIFICATION covering these action groups." }
                        Reference      = "SOX §404 — Audit Trail"
                        SqlQuery       = $auditData.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-01a: $($_.Exception.Message)" }

                # ITGC-AL-01b Login audit level — failure events are the minimum for SOX detective controls.
                try {
                    $auditLevel = Get-LoginAuditLevel -ctx $connSplat
                    $level      = $auditLevel.Level
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-01b"
                        CheckName      = "Login Audit Level"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($level -in "all", "failure") { "Pass" } else { "Fail" }
                        CurrentValue   = $level
                        ExpectedValue  = "failure or all"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 2  -- SQL Server service restart required."
                        Reference      = "SOX §404 — Audit Trail"
                        SqlQuery       = "EXEC xp_loginconfig 'audit level';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-01b: $($_.Exception.Message)" }

                # ITGC-AL-01c Default trace enabled — baseline change and security event evidence.
                try {
                    $traceData = Get-DefaultTrace -ctx $connSplat
                    if ($traceData.Config) {
                        $splatCheck = @{
                            CheckId        = "ITGC-AL-01c"
                            CheckName      = "Default Trace Enabled"
                            Category       = "Audit Logging"
                            AssessmentType = "Automated"
                            Priority       = "Low"
                            Status         = if ($traceData.Enabled) { "Pass" } else { "Fail" }
                            CurrentValue   = $traceData.Config.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "SOX §404 — Audit Trail"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'default trace enabled';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] ITGC-AL-01c: $($_.Exception.Message)" }

                # ITGC-AL-01d Audit captures server and database role membership changes.
                try {
                    $auditData = Get-SqlAudits -ctx $connSplat
                    $found     = ($auditData.EnabledRows | Where-Object { $_.audit_action_id -in 'ADSP', 'ADDP' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-01d"
                        CheckName      = "Audit — Role Membership Changes"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP captured"
                        Remediation    = "Add SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP to your active server audit specification."
                        Reference      = "SOX §404 — Change Accountability"
                        SqlQuery       = $auditData.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-01d: $($_.Exception.Message)" }

                # ITGC-AL-01e Audit captures DDL and schema changes to financial database objects.
                try {
                    $auditData = Get-SqlAudits -ctx $connSplat
                    $found     = ($auditData.EnabledRows | Where-Object { $_.audit_action_id -in 'DAUC', 'CDBR', 'SCHM' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-01e"
                        CheckName      = "Audit — DDL / Schema Changes"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP or DATABASE_CHANGE_GROUP captured"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to your active server audit specification. For database-level coverage: CREATE DATABASE AUDIT SPECIFICATION covering SCHEMA_OBJECT_CHANGE_GROUP on each financial database."
                        Reference      = "SOX §404 — Change Management"
                        SqlQuery       = $auditData.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-01e: $($_.Exception.Message)" }

                # ITGC-AL-02 Audit failure mode — no enabled audit should silently continue on failure.
                try {
                    $auditData = Get-SqlAudits -ctx $connSplat
                    $count     = $auditData.ContinueAudits.Count
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-02"
                        CheckName      = "Audit Failure Mode"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "High"
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "No audits configured to silently continue on failure" } else { "$count audit(s) set to CONTINUE on failure: $($auditData.ContinueAudits.name -join ', ')" }
                        ExpectedValue  = "All enabled audits configured to FAIL_OPERATION or SHUTDOWN on failure"
                        Remediation    = "ALTER SERVER AUDIT [<name>] WITH (ON_FAILURE = FAIL_OPERATION);  -- Ensures audit gaps cannot occur silently."
                        Reference      = "SOX §404 — Audit Trail Integrity"
                        SqlQuery       = $auditData.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-02: $($_.Exception.Message)" }

                # ITGC-AL-04 Error log retention >= 12 — SOX audit windows commonly require 12 months.
                try {
                    $retData = Get-ErrorLogRetention -ctx $connSplat
                    $splatCheck = @{
                        CheckId        = "ITGC-AL-04"
                        CheckName      = "Error Log Retention"
                        Category       = "Audit Logging"
                        AssessmentType = "Automated"
                        Priority       = "Medium"
                        Status         = if ($retData.Count -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $retData.Display
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12"
                        Reference      = "SOX §404 — Audit Trail Retention"
                        SqlQuery       = "-- Via Get-ErrorLogRetention / Get-DbaErrorLogConfig. T-SQL: DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, 6) AS NumberOfLogFiles;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] ITGC-AL-04: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] SOX ITGC assessment complete"
        }
    }

    end {}
}
