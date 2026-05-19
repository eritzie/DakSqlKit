Get-ChildItem "$PSScriptRoot\Private\*.ps1" | ForEach-Object { . $_.FullName }

function Test-DakPCIBenchmark {
    <#
    .SYNOPSIS
        Tests SQL Server instances against PCI DSS v4.0.1 controls.

    .DESCRIPTION
        Evaluates SQL Server configuration and operational state against
        Payment Card Industry Data Security Standard v4.0.1 requirements
        relevant to SQL Server database infrastructure.
        Returns one result object per check per instance (type: DakSqlKit.AuditResult).

        PCI DSS requirements assessed:
            §1 — Secure Configuration     ( 9 checks | Req 1, 2, 6, 8)
            §2 — Access Control           ( 9 checks | Req 7, 8)
            §3 — Data Protection          ( 5 checks | Req 3, 4)
            §4 — Audit & Logging          ( 6 checks | Req 10)
            §5 — Vulnerability Management ( 5 checks | Req 6)

        AssessmentType on each result:
            Automated — pass/fail determined by the tool
            Review    — tool collected evidence; a human must sign off on the finding
            Manual    — tool collected evidence; a human must determine compliance

        Review results have Compliant = $null. Status is Review unless a hard
        violation was detected, in which case Status may be Fail.
        Manual results always have Compliant = $null and a Remediation note with the
        audit procedure the reviewer must perform.

    .PARAMETER SqlInstance
        One or more SQL Server instances. Accepts pipeline input by value and by
        property name (compatible with Get-DbaRegisteredServer).

    .PARAMETER SqlCredential
        SQL Server auth credential. Omit for Windows auth.

    .PARAMETER Section
        PCI DSS sections to run: 1–5, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, Review, and Manual results.

    .PARAMETER Quiet
        Suppress console progress output.

    .EXAMPLE
        Test-DakPCIBenchmark -SqlInstance 'SQLPROD01'

    .EXAMPLE
        Test-DakPCIBenchmark -SqlInstance 'SQLPROD01' -FailedOnly | Format-Table -AutoSize

    .EXAMPLE
        Get-DbaRegisteredServer -Group Production | Test-DakPCIBenchmark -Section 3,4
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

        $pciPriority = @{
            "8.6.1"     = "High"      # Enabled sa is a known privileged target; vendor default account
            "8.6.1a"    = "Medium"    # Well-known account name aids brute-force
            "2.2.1a"    = "Critical"  # xp_cmdshell enables OS-level command execution from SQL
            "2.2.1b"    = "High"      # OLE Automation executes arbitrary COM objects
            "2.2.1c"    = "Medium"    # Ad hoc distributed queries open data exfiltration paths
            "6.2.4"     = "High"      # CLR without strict security allows UNSAFE .NET code
            "2.2.1d"    = "Medium"    # SQL Browser exposes instance names to network scanners
            "1.2.6"     = "Low"       # Default port 1433 is a primary scan target
            "2.2.2"     = "Low"       # Hide instance reduces instance discovery surface
            "8.2.1"     = "High"      # SQL auth bypasses AD provisioning and MFA enforcement
            "8.2.3"     = "High"      # BUILTIN groups grant SQL access outside provisioning
            "7.2.1"     = "Medium"    # Guest bypasses formal user provisioning
            "7.2.1a"    = "High"      # Public role excess permissions violate least privilege
            "8.3.6"     = "Medium"    # Orphaned users retain access to database objects
            "8.3.6a"    = "High"      # CHECK_POLICY off permits weak passwords
            "8.3.9"     = "High"      # Unexpired privileged passwords violate access control
            "8.3.6b"    = "Low"       # MUST_CHANGE logins may indicate stale provisioned accounts
            "7.2.2"     = "Critical"  # Sysadmin = unrestricted access to all cardholder data
            "3.5.1"     = "Critical"  # PAN must be rendered unreadable at rest
            "3.6.1a"    = "High"      # Weak symmetric key algorithms compromise data protection
            "3.6.1b"    = "Medium"    # Short asymmetric keys can be factored
            "4.2.1"     = "High"      # Unencrypted connections expose PAN in transit
            "3.5.1a"    = "High"      # Unencrypted backups expose PAN at rest outside the DB
            "10.2.1"    = "Critical"  # Audit trail is the primary PCI detective control
            "10.2.1.4"  = "High"      # Failure-only audit captures brute-force attempts
            "10.7.1"    = "Critical"  # PCI DSS Req 10.7.1 mandates 12-month log retention
            "10.2.1a"   = "Low"       # Default trace provides baseline change evidence
            "10.2.1.5"  = "High"      # Role membership changes must be attributable
            "10.2.1.2"  = "High"      # Schema changes to PAN tables must be tracked
            "6.3.3"     = "High"      # Critical patches required within 1 month
            "6.3.3a"    = "Medium"    # DBCC CHECKDB validates structural integrity
            "6.3.3b"    = "High"      # Inaccessible databases mean PAN is unavailable
            "6.3.3c"    = "Medium"    # CHECKSUM detects page corruption before permanent loss
            "6.2.4a"    = "High"      # UNSAFE CLR assemblies allow arbitrary code execution
        }
    }

    process {
        foreach ($instance in $SqlInstance) {
            $connSplat    = @{ SqlInstance = $instance }
            if ($SqlCredential) { $connSplat.SqlCredential = $SqlCredential }
            $computerName = ($instance -split "\\")[0].Split(",")[0]

            if (-not $Quiet) { Write-Host "PCI DSS v4.0.1 — $instance  ($($runDate.ToString("yyyy-MM-dd HH:mm:ss")))" -ForegroundColor White }
            Write-Verbose "[$instance] PCI assessment — $($runDate.ToString("yyyy-MM-dd HH:mm:ss")) — $runBy"

            $sharedParams = @{
                ComputerName = $computerName
                SqlInstance  = $instance
                Framework    = "PCI"
                RunDate      = $runDate
                RunBy        = $runBy
            }

            $emit = {
                param ([PSCustomObject]$r)
                $color = switch ($r.Status) {
                    "Pass"    { "Green"   }
                    "Fail"    { "Red"     }
                    "Warning" { "Yellow"  }
                    "Review"  { "Magenta" }
                    "Manual"  { "Cyan"    }
                    default   { "Gray"    }
                }
                if (-not $Quiet) { Write-Host ("  [{0,-9}] {1,-55} {2}" -f $r.CheckId, $r.CheckName, $r.Status.ToUpper()) -ForegroundColor $color }
                if (-not $FailedOnly -or $r.Status -in "Fail", "Warning", "Review", "Manual", "Error") {
                    $r
                }
            }

            # ── §1 Secure Configuration (Req 1, 2, 6, 8) ─────────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Secure Configuration"

                $saData1  = Get-SaLogin           -ctx $connSplat
                $sac      = Get-SurfaceAreaConfig  -ctx $connSplat
                $svcData1 = Get-SqlServices        -ctx $connSplat
                $netCfg1  = Get-NetworkConfig      -ctx $connSplat
                $saLogin1 = $saData1.Login

                # 8.6.1 sa disabled — Req 8.6.1: shared/generic accounts must not be used for system/admin functions.
                try {
                    $saEnabled = $saLogin1 -and -not $saLogin1.IsDisabled
                    $splatCheck = @{
                        CheckId        = "8.6.1"
                        CheckName      = "sa Login Disabled"
                        Category       = "Secure Configuration"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.6.1"]
                        Status         = if (-not $saEnabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($saEnabled) { "Enabled (name: $($saLogin1.Name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "Disable the sa account: USE [master]; DECLARE @n NVARCHAR(256) = SUSER_NAME(0x01); EXEC ('ALTER LOGIN [' + @n + '] DISABLE');"
                        Reference      = "PCI DSS v4.0.1 Req 8.6.1"
                        SqlQuery       = "-- Automated via Get-SaLogin (Private). T-SQL: SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.6.1: $($_.Exception.Message)" }

                # 8.6.1a sa renamed — Req 8.6.1: well-known account name aids targeted attacks.
                try {
                    if ($saLogin1) {
                        $splatCheck = @{
                            CheckId        = "8.6.1a"
                            CheckName      = "sa Login Renamed"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["8.6.1a"]
                            Status         = if ($saLogin1.Name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saLogin1.Name
                            ExpectedValue  = "Any name other than 'sa'"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "PCI DSS v4.0.1 Req 8.6.1"
                            SqlQuery       = "-- Automated via Get-SaLogin (Private). T-SQL: SELECT name FROM sys.server_principals WHERE sid = 0x01;  -- Name should not be 'sa'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 8.6.1a: $($_.Exception.Message)" }

                # 2.2.1a xp_cmdshell disabled — Req 2.2.1: disable unnecessary OS command execution.
                try {
                    $cmdShell = $sac.XpCmdshell
                    if ($cmdShell) {
                        $splatCheck = @{
                            CheckId        = "2.2.1a"
                            CheckName      = "xp_cmdshell Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["2.2.1a"]
                            Status         = if ($cmdShell.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $cmdShell.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.1"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'xp_cmdshell';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.2.1a: $($_.Exception.Message)" }

                # 2.2.1b OLE Automation disabled — Req 2.2.1: disable unnecessary COM object execution.
                try {
                    $oleAuto = $sac.OleAutomation
                    if ($oleAuto) {
                        $splatCheck = @{
                            CheckId        = "2.2.1b"
                            CheckName      = "OLE Automation Procedures Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["2.2.1b"]
                            Status         = if ($oleAuto.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $oleAuto.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.1"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.2.1b: $($_.Exception.Message)" }

                # 2.2.1c Ad hoc distributed queries disabled — Req 2.2.1: no OPENROWSET data exfiltration path.
                try {
                    $adHoc = $sac.AdHocDistributed
                    if ($adHoc) {
                        $splatCheck = @{
                            CheckId        = "2.2.1c"
                            CheckName      = "Ad Hoc Distributed Queries Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["2.2.1c"]
                            Status         = if ($adHoc.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $adHoc.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.1"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.2.1c: $($_.Exception.Message)" }

                # 6.2.4 CLR strict security — Req 6.2.4: prevent UNSAFE CLR assembly execution.
                # On SQL 2017+: clr strict security must be 1 if CLR is enabled.
                # On pre-2017: CLR should be disabled; if enabled, emit Manual.
                try {
                    $clrEnabled = $sac.ClrEnabled
                    $clrStrict  = $sac.ClrStrictSecurity
                    $clrOn      = $clrEnabled -and $clrEnabled.RunningValue -eq 1
                    $strictOn   = $clrStrict  -and $clrStrict.RunningValue  -eq 1

                    if (-not $clrOn) {
                        $status  = "Pass"
                        $current = "CLR disabled"
                        $remText = $null
                        $aType   = "Automated"
                    } elseif ($strictOn) {
                        $status  = "Pass"
                        $current = "CLR enabled with strict security ON"
                        $remText = $null
                        $aType   = "Automated"
                    } elseif ($clrStrict) {
                        $status  = "Fail"
                        $current = "CLR enabled; clr strict security = 0"
                        $remText = "EXEC sp_configure 'clr strict security', 1; RECONFIGURE;  -- Prevents loading of UNSAFE or EXTERNAL_ACCESS assemblies without explicit permission."
                        $aType   = "Automated"
                    } else {
                        $status  = "Manual"
                        $current = "CLR enabled (pre-SQL 2017 — clr strict security not available)"
                        $remText = "Review all CLR assemblies: SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1. UNSAFE or EXTERNAL_ACCESS assemblies violate PCI Req 6.2.4. Disable CLR if not required: EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"
                        $aType   = "Manual"
                    }

                    $splatCheck = @{
                        CheckId        = "6.2.4"
                        CheckName      = "CLR Strict Security"
                        Category       = "Secure Configuration"
                        AssessmentType = $aType
                        Priority       = $pciPriority["6.2.4"]
                        Status         = $status
                        CurrentValue   = $current
                        ExpectedValue  = "CLR disabled, or CLR strict security = 1 (SQL 2017+)"
                        Remediation    = $remText
                        Reference      = "PCI DSS v4.0.1 Req 6.2.4"
                        SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name IN ('clr enabled','clr strict security');"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.2.4: $($_.Exception.Message)" }

                # 2.2.1d SQL Browser service — Req 2.2.1: disable unnecessary services.
                # SQL Browser exposes instance/port enumeration to network scanners.
                # A Warning (not Fail) is issued because named instances may need Browser for dynamic port resolution.
                try {
                    $browserSvc = $svcData1.Browser
                    if ($browserSvc) {
                        $running = $browserSvc.State -eq "Running"
                        $splatCheck = @{
                            CheckId        = "2.2.1d"
                            CheckName      = "SQL Browser Service Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["2.2.1d"]
                            Status         = if ($running) { "Warning" } else { "Pass" }
                            CurrentValue   = "State: $($browserSvc.State); StartMode: $($browserSvc.StartMode)"
                            ExpectedValue  = "State: Stopped; StartMode: Disabled"
                            Remediation    = "If using a named instance with a fixed TCP port, SQL Browser is not required. Disable in SQL Server Configuration Manager or: Set-DbaService -ComputerName $computerName -Type SqlBrowser -StartupType Disabled. Named instances using dynamic ports require SQL Browser for port resolution — consider switching to a fixed port first (1.2.6)."
                            Reference      = "PCI DSS v4.0.1 Req 2.2.1"
                            SqlQuery       = "-- Automated via Get-SqlServices (Private). No T-SQL equivalent — service state is OS-level."
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 2.2.1d: $($_.Exception.Message)" }

                # 1.2.6 Non-standard TCP port — Req 1.2.6: use non-default ports to reduce scan exposure.
                # Default port 1433 is the primary SQL Server scan target.
                try {
                    $port = $netCfg1.TcpPort
                    if ($port -ne -1) {
                        $splatCheck = @{
                            CheckId        = "1.2.6"
                            CheckName      = "Non-Standard TCP Port"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.2.6"]
                            Status         = if ($port -ne 1433) { "Pass" } else { "Fail" }
                            CurrentValue   = $port.ToString()
                            ExpectedValue  = "Any port other than 1433"
                            Remediation    = "Change the TCP port in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > TCP/IP > IP Addresses > IPAll > TCP Port. Restart the SQL Server service to apply."
                            Reference      = "PCI DSS v4.0.1 Req 1.2.6"
                            SqlQuery       = "-- Automated via Get-NetworkConfig (Private). T-SQL: SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID;"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 1.2.6: $($_.Exception.Message)" }

                # 2.2.2 Hide instance — Req 2.2.2: use unique default settings on all system components.
                try {
                    $hidden = $netCfg1.Hidden
                    $splatCheck = @{
                        CheckId        = "2.2.2"
                        CheckName      = "Hide Instance Enabled"
                        Category       = "Secure Configuration"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.2.2"]
                        Status         = if ($hidden) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($hidden) { "1 (hidden)" } else { "0 (visible)" }
                        ExpectedValue  = "1 (instance hidden from SQL Browser enumeration)"
                        Remediation    = "Enable in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > Properties > Hide Instance = Yes."
                        Reference      = "PCI DSS v4.0.1 Req 2.2.2"
                        SqlQuery       = $netCfg1.HideQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 2.2.2: $($_.Exception.Message)" }
            }

            # ── §2 Access Control (Req 7–8) ───────────────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Access Control"

                $authData2    = Get-AuthMode       -ctx $connSplat
                $builtinData2 = Get-BuiltinGroups  -ctx $connSplat
                $guestData2   = Get-GuestAccess    -ctx $connSplat
                $permData2    = Get-PublicRolePerms -ctx $connSplat
                $orphanData2  = Get-OrphanedUsers  -ctx $connSplat
                $sqlData2     = Get-SqlAuthLogins  -ctx $connSplat
                $sysData2     = Get-SysadminLogins -ctx $connSplat

                # 8.2.1 Windows-only auth — Req 8.2.1: unique IDs; SQL logins bypass AD MFA controls.
                try {
                    $winOnly = ($authData2.LoginMode -eq 1)
                    $splatCheck = @{
                        CheckId        = "8.2.1"
                        CheckName      = "Windows-Only Authentication"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.2.1"]
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only (LoginMode = 1)"
                        Remediation    = "Mixed mode allows SQL logins that exist outside AD, cannot be centrally deprovisioned, and bypass MFA requirements. Change to Windows Authentication: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- Restart required."
                        Reference      = "PCI DSS v4.0.1 Req 8.2.1"
                        SqlQuery       = "-- Automated via Get-AuthMode (Private). T-SQL: SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.2.1: $($_.Exception.Message)" }

                # 8.2.3 BUILTIN groups absent — Req 8.2.3: shared accounts prohibited; local admins bypass provisioning.
                try {
                    $count = $builtinData2.Count
                    $splatCheck = @{
                        CheckId        = "8.2.3"
                        CheckName      = "BUILTIN Groups Absent"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.2.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtinData2.Names -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "BUILTIN groups grant SQL access to every local administrator outside SQL Server's provisioning process. Confirm domain group equivalents exist, then: USE [master]; DROP LOGIN [BUILTIN\Administrators];"
                        Reference      = "PCI DSS v4.0.1 Req 8.2.3"
                        SqlQuery       = "-- Automated via Get-BuiltinGroups (Private). T-SQL: SELECT name FROM sys.server_principals WHERE name LIKE 'BUILTIN%';  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.2.3: $($_.Exception.Message)" }

                # 7.2.1 Guest access revoked — Req 7.2.1: access based on need-to-know; no implicit provisioning.
                try {
                    $count = $guestData2.Count
                    $splatCheck = @{
                        CheckId        = "7.2.1"
                        CheckName      = "Guest Access Revoked"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["7.2.1"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "Revoked in all user databases" } else { "Active in: $($guestData2.DatabaseNames -join ', ')" }
                        ExpectedValue  = "CONNECT revoked in all user databases"
                        Remediation    = "USE [<database>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2.1"
                        SqlQuery       = "-- Automated via Get-GuestAccess (Private). T-SQL per user DB: SELECT permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.2.1: $($_.Exception.Message)" }

                # 7.2.1a Public role excess permissions — Req 7.2.1: least privilege; public = all principals.
                try {
                    $count = $permData2.Count
                    $splatCheck = @{
                        CheckId        = "7.2.1a"
                        CheckName      = "Public Role — No Excess Server Permissions"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["7.2.1a"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count non-standard permission(s) granted to public"
                        ExpectedValue  = "0 — only CONNECT SQL is standard for the public role"
                        Remediation    = "Review and revoke: SELECT type_desc, permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = 2 AND state IN ('G','W'); Then: REVOKE <permission> FROM [public];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2.1"
                        SqlQuery       = $permData2.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.2.1a: $($_.Exception.Message)" }

                # 8.3.6 Orphaned users — Req 8.3.6: accounts must be removed or disabled when no longer needed.
                try {
                    $count = $orphanData2.Count
                    $splatCheck = @{
                        CheckId        = "8.3.6"
                        CheckName      = "No Orphaned Database Users"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.3.6"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count orphaned user(s): $($orphanData2.Orphans.User -join ', ')" }
                        ExpectedValue  = "No orphaned users in any database"
                        Remediation    = "Remove orphaned users: Remove-DbaDbOrphanUser -SqlInstance $instance  -- or map to a login: USE [<db>]; ALTER USER [<user>] WITH LOGIN = [<login>];"
                        Reference      = "PCI DSS v4.0.1 Req 8.3.6"
                        SqlQuery       = "-- Automated via Get-OrphanedUsers (Private). T-SQL per DB: SELECT name FROM sys.database_principals WHERE type IN ('S','U','G') AND authentication_type_desc = 'INSTANCE' AND sid NOT IN (SELECT sid FROM sys.server_principals);"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.3.6: $($_.Exception.Message)" }

                # 8.3.6a SQL logins enforce password policy — Req 8.3.6: password complexity requirements.
                try {
                    $noPolicy2 = @($sqlData2.Logins | Where-Object { -not $_.PasswordPolicyEnforced })
                    $count     = $noPolicy2.Count
                    $splatCheck = @{
                        CheckId        = "8.3.6a"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.3.6a"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count login(s) without CHECK_POLICY" }
                        ExpectedValue  = "CHECK_POLICY = ON for all SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON;  -- Enumerate: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;"
                        Reference      = "PCI DSS v4.0.1 Req 8.3.6"
                        SqlQuery       = "-- Automated via Get-SqlAuthLogins (Private). T-SQL: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.3.6a: $($_.Exception.Message)" }

                # 8.3.9 CHECK_EXPIRATION on privileged SQL logins — Req 8.3.9: periodic password changes.
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
                        CheckId        = "8.3.9"
                        CheckName      = "Privileged Login Password Expiration"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.3.9"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count privileged login(s) without CHECK_EXPIRATION" }
                        ExpectedValue  = "CHECK_EXPIRATION = ON for all privileged SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "PCI DSS v4.0.1 Req 8.3.9"
                        SqlQuery       = $expQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.3.9: $($_.Exception.Message)" }

                # 8.3.6b MUST_CHANGE logins — Req 8.3.6: accounts with MUST_CHANGE pending may indicate
                # provisioned-but-never-used accounts that bypassed the onboarding process.
                # No dbatools equivalent — using Invoke-DbaQuery.
                try {
                    $mcQuery = @"
SELECT name
FROM sys.sql_logins
WHERE is_must_change = 1 AND is_disabled = 0;
"@
                    $mcRows = Invoke-DbaQuery @connSplat -Query $mcQuery -WarningAction SilentlyContinue
                    $count  = if ($mcRows) { @($mcRows).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "8.3.6b"
                        CheckName      = "MUST_CHANGE Logins"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["8.3.6b"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count login(s) with MUST_CHANGE pending" }
                        ExpectedValue  = "0 — no active logins with a pending forced password change"
                        Remediation    = "Investigate whether these accounts have never been used (provision-and-forget pattern). If the account is legitimate and the user has connected, this clears automatically. Disable unused accounts."
                        Reference      = "PCI DSS v4.0.1 Req 8.3.6"
                        SqlQuery       = $mcQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 8.3.6b: $($_.Exception.Message)" }

                # 7.2.2 Sysadmin membership — Review: Req 7.2.2 requires least-privilege access documented
                # and reviewed. Sysadmin bypasses all permission checks and can read all cardholder data.
                try {
                    $exceptions2 = @('DYNAMICS_SVC')
                    $sysNames2   = $sysData2.Names
                    $sqlAuthSys2 = @($sysNames2 | Where-Object { $_ -in $sqlData2.Names })
                    $winAuthSys2 = @($sysNames2 | Where-Object { $_ -notin $sqlData2.Names })
                    $excepted2   = @($sqlAuthSys2 | Where-Object { $_ -in $exceptions2 })
                    $violations2 = @($sqlAuthSys2 | Where-Object { $_ -notin $exceptions2 })
                    $finding2    = if ($violations2.Count -gt 0) { "SQL auth violations: $($violations2 -join ', ')" } else { "No SQL auth violations" }
                    $splatCheck = @{
                        CheckId        = "7.2.2"
                        CheckName      = "Sysadmin Membership Review"
                        Category       = "Access Control"
                        AssessmentType = "Review"
                        Priority       = $pciPriority["7.2.2"]
                        Status         = if ($violations2.Count -gt 0) { "Fail" } else { "Review" }
                        CurrentValue   = "Total: $($sysData2.Count) | Windows auth: $($winAuthSys2.Count) | SQL auth: $($sqlAuthSys2.Count) (excepted: $($excepted2.Count), violations: $($violations2.Count)) — $finding2"
                        ExpectedValue  = "Minimum necessary; each account documented and recertified at least every 6 months (PCI DSS Req 7.2.2)"
                        Remediation    = "Review all members: SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%'. Remove any not formally approved: ALTER SERVER ROLE sysadmin DROP MEMBER [<account>];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2.2"
                        SqlQuery       = "-- Automated via Get-SysadminLogins + Get-SqlAuthLogins (Private). T-SQL: SELECT DISTINCT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 7.2.2: $($_.Exception.Message)" }
            }

            # ── §3 Data Protection (Req 3–4) ─────────────────────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 Data Protection"

                $tde3     = Get-TdeStatus         -ctx $connSplat
                $symData3 = Get-SymmetricKeys      -ctx $connSplat
                $asymData3 = Get-AsymmetricKeys    -ctx $connSplat
                $netEnc3  = Get-NetworkEncryption  -ctx $connSplat

                # 3.5.1 TDE scope — Review: Req 3.5.1 requires PAN rendered unreadable at rest.
                # Tool collects evidence; auditor determines which databases are in PAN scope.
                try {
                    $nameList3 = if ($tde3.UnencryptedCount -gt 0) { "Unencrypted: $($tde3.UnencryptedNames -join ', ')" } else { "All $($tde3.TotalCount) user database(s) are TDE-encrypted" }
                    $splatCheck = @{
                        CheckId        = "3.5.1"
                        CheckName      = "TDE Scope Review"
                        Category       = "Data Protection"
                        AssessmentType = "Review"
                        Priority       = $pciPriority["3.5.1"]
                        Status         = "Review"
                        CurrentValue   = "Encrypted: $($tde3.EncryptedCount) | Unencrypted: $($tde3.UnencryptedCount) — $nameList3"
                        ExpectedValue  = "TDE enabled on all databases storing PAN or sensitive authentication data"
                        Remediation    = "Identify databases in PCI scope. For each: Enable-DbaDatabaseEncryption -SqlInstance $instance -Database <dbname>  -- Requires a database master key and certificate on master."
                        Reference      = "PCI DSS v4.0.1 Req 3.5.1"
                        SqlQuery       = "-- Automated via Get-TdeStatus (Private). T-SQL: SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.5.1: $($_.Exception.Message)" }

                # 3.6.1a Symmetric key algorithms — Req 3.6.1: strong cryptography; AES only.
                try {
                    $weakKeys = $symData3.WeakCount
                    $splatCheck = @{
                        CheckId        = "3.6.1a"
                        CheckName      = "Symmetric Key Algorithms — AES Only"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.6.1a"]
                        Status         = if ($weakKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeys non-AES symmetric key(s) across all user databases"
                        ExpectedValue  = "0 — all symmetric keys use AES_128, AES_192, or AES_256"
                        Remediation    = "Per database: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256'). Recreate non-AES keys using a supported algorithm before dropping the old ones."
                        Reference      = "PCI DSS v4.0.1 Req 3.6.1"
                        SqlQuery       = $symData3.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.6.1a: $($_.Exception.Message)" }

                # 3.6.1b Asymmetric key size — Req 3.6.1: RSA keys must be at least 2048-bit.
                try {
                    $shortKeys = $asymData3.ShortCount
                    $splatCheck = @{
                        CheckId        = "3.6.1b"
                        CheckName      = "Asymmetric Key Size — Min 2048-bit"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.6.1b"]
                        Status         = if ($shortKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$shortKeys asymmetric key(s) shorter than 2048-bit"
                        ExpectedValue  = "0 — all asymmetric keys at least 2048-bit"
                        Remediation    = "Per database: SELECT name, key_length FROM sys.asymmetric_keys WHERE key_length < 2048. Recreate undersized keys with a 2048-bit or 4096-bit RSA key."
                        Reference      = "PCI DSS v4.0.1 Req 3.6.1"
                        SqlQuery       = $asymData3.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.6.1b: $($_.Exception.Message)" }

                # 4.2.1 Network encryption — Req 4.2.1: strong cryptography for all data in transit.
                try {
                    $unenc3 = $netEnc3.UnencryptedCount
                    $splatCheck = @{
                        CheckId        = "4.2.1"
                        CheckName      = "Network Encryption Enforced"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.2.1"]
                        Status         = if ($unenc3 -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unenc3 -eq 0) { "All non-shared-memory connections encrypted" } else { "$unenc3 unencrypted connection type(s) detected" }
                        ExpectedValue  = "All non-shared-memory connections encrypted"
                        Remediation    = "Enable Force Encryption in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties > Force Encryption = Yes. A trusted certificate is required."
                        Reference      = "PCI DSS v4.0.1 Req 4.2.1"
                        SqlQuery       = $netEnc3.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 4.2.1: $($_.Exception.Message)" }

                # 3.5.1a Backup encryption — Req 3.5.1: PAN must be unreadable wherever stored, including backups.
                # No dbatools equivalent — using Invoke-DbaQuery against msdb.dbo.backupset.
                try {
                    $q3_5_1a = @"
SELECT COUNT(*) AS UnencBackups
FROM msdb.dbo.backupset b
JOIN sys.databases d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL
  AND b.encryptor_type IS NULL
  AND d.is_encrypted = 0
  AND b.backup_finish_date >= DATEADD(DAY, -30, GETDATE());
"@
                    $r3_5_1a = Invoke-DbaQuery @connSplat -Query $q3_5_1a -WarningAction SilentlyContinue
                    $count   = if ($r3_5_1a) { $r3_5_1a.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "3.5.1a"
                        CheckName      = "Backup Encryption"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.5.1a"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup record(s) in the past 30 days"
                        ExpectedValue  = "0 — all backups encrypted or database encrypted via TDE"
                        Remediation    = "Enable backup encryption via the WITH ENCRYPTION clause on BACKUP DATABASE, or enable TDE on PAN-scope databases (TDE-encrypted databases produce automatically encrypted backups)."
                        Reference      = "PCI DSS v4.0.1 Req 3.5.1"
                        SqlQuery       = $q3_5_1a
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 3.5.1a: $($_.Exception.Message)" }
            }

            # ── §4 Audit & Logging (Req 10) ───────────────────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Audit & Logging"

                $auditData4  = Get-SqlAudits        -ctx $connSplat
                $auditLevel4 = Get-LoginAuditLevel  -ctx $connSplat
                $retData4    = Get-ErrorLogRetention -ctx $connSplat
                $traceData4  = Get-DefaultTrace      -ctx $connSplat

                # 10.2.1 SQL Server Audit — Req 10.2.1: capture all required event categories.
                # PCI requires 6 action groups (adds SCHEMA_OBJECT_CHANGE_GROUP vs SOX 5).
                try {
                    $required4 = @(
                        "FAILED_LOGIN_GROUP",
                        "SUCCESSFUL_LOGIN_GROUP",
                        "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
                        "SERVER_ROLE_MEMBER_CHANGE_GROUP",
                        "AUDIT_CHANGE_GROUP",
                        "SCHEMA_OBJECT_CHANGE_GROUP"
                    )
                    $foundGroups4 = @($auditData4.ActionNames | Where-Object { $_ -in $required4 })
                    $missing4     = $required4 | Where-Object { $_ -notin $foundGroups4 }
                    $compliant4   = $missing4.Count -eq 0
                    $splatCheck = @{
                        CheckId        = "10.2.1"
                        CheckName      = "SQL Server Audit — PCI Action Groups"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["10.2.1"]
                        Status         = if ($compliant4) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($foundGroups4.Count -eq 0) { "No enabled audit" } else { "$($foundGroups4.Count) of $($required4.Count) required groups captured" }
                        ExpectedValue  = "All 6 PCI action groups enabled in an active audit and specification"
                        Remediation    = if ($compliant4) { $null } else { "Missing groups: $($missing4 -join ', '). Create a SERVER AUDIT targeted to a protected file path with 90-day retention and a SERVER AUDIT SPECIFICATION covering all 6 action groups." }
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1"
                        SqlQuery       = $auditData4.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 10.2.1: $($_.Exception.Message)" }

                # 10.2.1.4 Login audit level — Req 10.2.1.4: log all invalid logical access attempts.
                try {
                    $level4 = $auditLevel4.Level
                    $splatCheck = @{
                        CheckId        = "10.2.1.4"
                        CheckName      = "Login Audit Level"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["10.2.1.4"]
                        Status         = if ($level4 -in "all", "failure") { "Pass" } else { "Fail" }
                        CurrentValue   = $level4
                        ExpectedValue  = "failure or all"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 2  -- 2 = failure, 3 = all. SQL Server service restart required."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.4"
                        SqlQuery       = "EXEC xp_loginconfig 'audit level';  -- config_value should be 'failure' or 'all'"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 10.2.1.4: $($_.Exception.Message)" }

                # 10.7.1 Error log retention >= 12 — Req 10.7.1: retain audit logs for at least 12 months.
                try {
                    $count4   = $retData4.Count
                    $display4 = $retData4.Display
                    $splatCheck = @{
                        CheckId        = "10.7.1"
                        CheckName      = "Error Log Retention — Min 12"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["10.7.1"]
                        Status         = if ($count4 -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $display4
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12  -- Note: SQL Server error log recycling is not a substitute for a dedicated audit trail. PCI Req 10.7.1 requires a separate audit log solution with 12-month retention and 3-month online availability."
                        Reference      = "PCI DSS v4.0.1 Req 10.7.1"
                        SqlQuery       = "-- Automated via Get-ErrorLogRetention (Private). T-SQL: DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, 6) AS NumberOfLogFiles;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 10.7.1: $($_.Exception.Message)" }

                # 10.2.1a Default trace enabled — Req 10.2.1: baseline change and security event evidence.
                try {
                    $defTrace4 = $traceData4.Config
                    if ($defTrace4) {
                        $splatCheck = @{
                            CheckId        = "10.2.1a"
                            CheckName      = "Default Trace Enabled"
                            Category       = "Audit"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["10.2.1a"]
                            Status         = if ($defTrace4.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $defTrace4.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 10.2.1"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'default trace enabled';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 10.2.1a: $($_.Exception.Message)" }

                # 10.2.1.5 Audit captures role membership changes — Req 10.2.1.5: changes to
                # identification and authentication mechanisms must be logged.
                try {
                    $found4_5 = ($auditData4.EnabledRows | Where-Object { $_.audit_action_id -in 'ADSP', 'ADDP' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "10.2.1.5"
                        CheckName      = "Audit — Role Membership Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["10.2.1.5"]
                        Status         = if ($found4_5) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found4_5) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP captured"
                        Remediation    = "Add SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP to your active server audit specification."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.5"
                        SqlQuery       = $auditData4.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 10.2.1.5: $($_.Exception.Message)" }

                # 10.2.1.2 Audit captures DDL/schema changes — Req 10.2.1.2: object-level access to
                # cardholder data and schema changes must be recorded.
                try {
                    $found4_2 = ($auditData4.EnabledRows | Where-Object { $_.audit_action_id -in 'SCHM', 'DAUC', 'CDBR' }).Count -gt 0
                    $splatCheck = @{
                        CheckId        = "10.2.1.2"
                        CheckName      = "Audit — DDL / Schema Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["10.2.1.2"]
                        Status         = if ($found4_2) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found4_2) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP or DATABASE_CHANGE_GROUP captured"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to your active server audit specification. For database-level coverage on PCI-scope databases: CREATE DATABASE AUDIT SPECIFICATION covering SCHEMA_OBJECT_CHANGE_GROUP."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.2"
                        SqlQuery       = $auditData4.SpecQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 10.2.1.2: $($_.Exception.Message)" }
            }

            # ── §5 Vulnerability Management (Req 6) ──────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Vulnerability Management"

                $checkData5 = Get-CheckDbHistory -ctx $connSplat
                $dbStatus5  = Get-DatabaseStatus -ctx $connSplat
                $dbCfg5     = Get-DatabaseConfig -ctx $connSplat
                $clrData5   = Get-ClrAssemblies  -ctx $connSplat

                # 6.3.3 Patch level — Req 6.3.3: critical security patches within 1 month.
                # Test-DbaBuild -Latest -Update returns Compliant, BuildLevel, BuildTarget, and CUTarget.
                try {
                    $build = Test-DbaBuild @connSplat -Latest -Update -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($build) {
                        $splatCheck = @{
                            CheckId        = "6.3.3"
                            CheckName      = "Patch Level — Req 6.3.3"
                            Category       = "Vulnerability Management"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["6.3.3"]
                            Status         = if ($build.Compliant) { "Pass" } else { "Fail" }
                            CurrentValue   = $build.BuildLevel.ToString()
                            ExpectedValue  = $build.BuildTarget.ToString()
                            Remediation    = if ($build.Compliant) { $null } else { "Apply the latest SQL Server CU: $($build.CUTarget)" }
                            Reference      = "PCI DSS v4.0.1 Req 6.3.3"
                            SqlQuery       = "SELECT SERVERPROPERTY('ProductVersion') AS Build, SERVERPROPERTY('ProductLevel') AS SPLevel, SERVERPROPERTY('ProductUpdateLevel') AS CULevel, SERVERPROPERTY('Edition') AS Edition;"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] 6.3.3: $($_.Exception.Message)" }

                # 6.3.3a DBCC CHECKDB within 7 days — structural integrity is a pre-condition for data reliability.
                try {
                    $count5a = $checkData5.StaleCount
                    $splatCheck = @{
                        CheckId        = "6.3.3a"
                        CheckName      = "DBCC CHECKDB Within 7 Days"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["6.3.3a"]
                        Status         = if ($count5a -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count5a -eq 0) { "All databases checked within 7 days" } else { "$count5a database(s) overdue: $($checkData5.Stale.Database -join ', ')" }
                        ExpectedValue  = "DBCC CHECKDB completed within 7 days on all databases"
                        Remediation    = "Schedule integrity checks: Invoke-DbaDbIntegrityCheck -SqlInstance $instance -Database <db>  -- or use Ola Hallengren's DatabaseIntegrityCheck job."
                        Reference      = "PCI DSS v4.0.1 Req 6.3.3"
                        SqlQuery       = "-- Automated via Get-CheckDbHistory (Private). T-SQL reference: DBCC DBINFO() WITH TABLERESULTS;  -- Look for dbi_dbccLastKnownGood."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.3.3a: $($_.Exception.Message)" }

                # 6.3.3b All user databases accessible — inaccessible databases indicate a potential breach or failure.
                try {
                    $inacc5  = $dbStatus5.Inaccessible
                    $count5b = $inacc5.Count
                    $splatCheck = @{
                        CheckId        = "6.3.3b"
                        CheckName      = "All User Databases Accessible"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["6.3.3b"]
                        Status         = if ($count5b -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count5b -eq 0) { "All user databases accessible" } else { "$count5b inaccessible: $($inacc5.Name -join ', ')" }
                        ExpectedValue  = "All user databases in an accessible state"
                        Remediation    = "Investigate inaccessible databases in the SQL Server error log. Databases in Suspect or Recovery_Pending state may indicate corruption or an incomplete restore."
                        Reference      = "PCI DSS v4.0.1 Req 6.3.3"
                        SqlQuery       = "-- Automated via Get-DatabaseStatus (Private). T-SQL: SELECT name, state_desc FROM sys.databases WHERE database_id > 4 AND state <> 0;  -- state 0 = ONLINE"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.3.3b: $($_.Exception.Message)" }

                # 6.3.3c Page verify CHECKSUM — detects I/O-layer corruption before it silently spreads.
                try {
                    $noCksum5 = $dbCfg5.NoChecksum
                    $count5c  = $noCksum5.Count
                    $splatCheck = @{
                        CheckId        = "6.3.3c"
                        CheckName      = "Page Verify CHECKSUM"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["6.3.3c"]
                        Status         = if ($count5c -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count5c -eq 0) { "All user databases use CHECKSUM" } else { "$count5c database(s) without CHECKSUM: $($noCksum5.Name -join ', ')" }
                        ExpectedValue  = "PAGE_VERIFY = CHECKSUM for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "PCI DSS v4.0.1 Req 6.3.3"
                        SqlQuery       = "-- Automated via Get-DatabaseConfig (Private). T-SQL: SELECT name, page_verify_option_desc FROM sys.databases WHERE database_id > 4 AND page_verify_option_desc <> 'CHECKSUM';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.3.3c: $($_.Exception.Message)" }

                # 6.2.4a UNSAFE CLR assemblies — Req 6.2.4: identify and address security vulnerabilities.
                # UNSAFE assemblies can call arbitrary Win32 APIs and read/write the file system.
                try {
                    $unsafeCount5 = $clrData5.UnsafeCount
                    $splatCheck = @{
                        CheckId        = "6.2.4a"
                        CheckName      = "No UNSAFE CLR Assemblies"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["6.2.4a"]
                        Status         = if ($unsafeCount5 -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$unsafeCount5 UNSAFE CLR assembly/assemblies across all user databases"
                        ExpectedValue  = "0 — no user-defined assemblies with UNSAFE_ACCESS permission set"
                        Remediation    = "Per database: SELECT name, permission_set_desc FROM sys.assemblies WHERE permission_set_desc = 'UNSAFE_ACCESS' AND is_user_defined = 1. Review each assembly for necessity. Recreate with SAFE or EXTERNAL_ACCESS where possible; drop if not required."
                        Reference      = "PCI DSS v4.0.1 Req 6.2.4"
                        SqlQuery       = $clrData5.Query
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] 6.2.4a: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] PCI assessment complete"
        }
    }

    end {}
}
