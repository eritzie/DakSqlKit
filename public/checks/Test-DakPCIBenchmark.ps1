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
            §1 — Secure Configuration     ( 9 checks: PCI-1.1–1.9  | Req 2)
            §2 — Access Control           ( 9 checks: PCI-2.1–2.9  | Req 7–8)
            §3 — Data Protection          ( 5 checks: PCI-3.1–3.5  | Req 3–4)
            §4 — Audit & Logging          ( 6 checks: PCI-4.1–4.6  | Req 10)
            §5 — Vulnerability Management ( 5 checks: PCI-5.1–5.5  | Req 6)

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
        PCI DSS sections to run: 1–5, or All. Default: All.

    .PARAMETER FailedOnly
        Return only Fail, Warning, and Manual results.

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
            "1.1" = "High"      # Enabled sa is a known privileged target; Req 2.2.2 vendor defaults
            "1.2" = "Medium"    # Well-known account name aids brute-force; Req 2.2.2
            "1.3" = "Critical"  # xp_cmdshell enables OS-level command execution from SQL; Req 2.2.4
            "1.4" = "High"      # OLE Automation executes arbitrary COM objects; Req 2.2.4
            "1.5" = "Medium"    # Ad hoc distributed queries open data exfiltration paths; Req 2.2.4
            "1.6" = "High"      # CLR without strict security allows UNSAFE .NET code; Req 2.2.4
            "1.7" = "Medium"    # SQL Browser exposes instance names to network scanners; Req 2.2.4
            "1.8" = "Low"       # Default port 1433 is a primary scan target; Req 2.2.7
            "1.9" = "Low"       # Hide instance reduces instance discovery surface; Req 2.2.4
            "2.1" = "High"      # SQL auth bypasses AD provisioning and MFA enforcement; Req 8.2.1
            "2.2" = "High"      # BUILTIN groups grant SQL access outside provisioning; Req 7.2
            "2.3" = "Medium"    # Guest bypasses formal user provisioning; Req 7.2
            "2.4" = "High"      # Public role excess permissions violate least privilege; Req 7.2
            "2.5" = "Medium"    # Orphaned users retain access to database objects; Req 7.2
            "2.6" = "High"      # CHECK_POLICY off permits weak passwords; Req 8.3.6
            "2.7" = "High"      # Unexpired privileged passwords violate access control; Req 8.3.9
            "2.8" = "Low"       # MUST_CHANGE logins may indicate stale provisioned accounts; Req 8.2
            "2.9" = "Critical"  # Sysadmin = unrestricted access to all cardholder data; Req 7.2.2
            "3.1" = "Critical"  # PAN must be rendered unreadable at rest; Req 3.5.1
            "3.2" = "High"      # Weak symmetric key algorithms compromise data protection; Req 3.6.1
            "3.3" = "Medium"    # Short asymmetric keys can be factored; Req 3.7.1
            "3.4" = "High"      # Unencrypted connections expose PAN in transit; Req 4.2.1
            "3.5" = "High"      # Unencrypted backups expose PAN at rest outside the DB; Req 3.5.1
            "4.1" = "Critical"  # Audit trail is the primary PCI detective control; Req 10.2.1
            "4.2" = "High"      # Failure-only audit captures brute-force attempts; Req 10.2.1.4
            "4.3" = "Critical"  # PCI DSS Req 10.5.1 mandates 12-month log retention
            "4.4" = "Low"       # Default trace provides baseline change evidence; Req 10.2
            "4.5" = "High"      # Role membership changes must be attributable; Req 10.2.1.5
            "4.6" = "High"      # Schema changes to PAN tables must be tracked; Req 10.2.1.2
            "5.1" = "High"      # Critical patches required within 1 month; Req 6.3.3
            "5.2" = "Medium"    # DBCC CHECKDB validates structural integrity; Req 6
            "5.3" = "High"      # Inaccessible databases mean PAN is unavailable; Req 6
            "5.4" = "Medium"    # CHECKSUM detects page corruption before permanent loss; Req 6
            "5.5" = "High"      # UNSAFE CLR assemblies allow arbitrary code execution; Req 6.3.2
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

            # ── §1 Secure Configuration (Req 2) ───────────────────────────────────
            if (ShouldRun "1") {
                Write-Verbose "[$instance] §1 Secure Configuration"

                # Pre-fetch sa login once for PCI-1.1 and PCI-1.2 (SID 0x01 finds renamed sa).
                $saLogin1 = $null
                try {
                    $saLogin1 = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Sid.Length -eq 1 -and $_.Sid[0] -eq 1 } |
                        Select-Object -First 1
                } catch { Write-Verbose "[$instance] sa pre-fetch failed: $($_.Exception.Message)" }

                # PCI-1.1 sa disabled — Req 2.2.2: change vendor-supplied default credentials.
                try {
                    $saEnabled = $saLogin1 -and -not $saLogin1.IsDisabled
                    $splatCheck = @{
                        CheckId        = "PCI-1.1"
                        CheckName      = "sa Login Disabled"
                        Category       = "Secure Configuration"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["1.1"]
                        Status         = if (-not $saEnabled) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($saEnabled) { "Enabled (name: $($saLogin1.Name))" } else { "Disabled" }
                        ExpectedValue  = "Disabled"
                        Remediation    = "Disable the sa account: USE [master]; DECLARE @n NVARCHAR(256) = SUSER_NAME(0x01); EXEC ('ALTER LOGIN [' + @n + '] DISABLE');"
                        Reference      = "PCI DSS v4.0.1 Req 2.2.2"
                        SqlQuery       = "-- Automated via Get-DbaLogin (SID 0x01 lookup). T-SQL: SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-1.1: $($_.Exception.Message)" }

                # PCI-1.2 sa renamed — Req 2.2.2: change vendor-supplied default account names.
                try {
                    if ($saLogin1) {
                        $splatCheck = @{
                            CheckId        = "PCI-1.2"
                            CheckName      = "sa Login Renamed"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.2"]
                            Status         = if ($saLogin1.Name -ne "sa") { "Pass" } else { "Fail" }
                            CurrentValue   = $saLogin1.Name
                            ExpectedValue  = "Any name other than 'sa'"
                            Remediation    = "ALTER LOGIN [sa] WITH NAME = [sa_disabled];"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.2"
                            SqlQuery       = "-- Automated via Get-DbaLogin (SID 0x01 lookup). T-SQL: SELECT name FROM sys.server_principals WHERE sid = 0x01;  -- Name should not be 'sa'"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.2: $($_.Exception.Message)" }

                # PCI-1.3 xp_cmdshell disabled — Req 2.2.4: disable unnecessary OS command execution.
                try {
                    $cmdShell = Get-DbaSpConfigure @connSplat -Name "xp_cmdshell" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($cmdShell) {
                        $splatCheck = @{
                            CheckId        = "PCI-1.3"
                            CheckName      = "xp_cmdshell Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.3"]
                            Status         = if ($cmdShell.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $cmdShell.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'xp_cmdshell';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.3: $($_.Exception.Message)" }

                # PCI-1.4 OLE Automation disabled — Req 2.2.4: disable unnecessary COM object execution.
                try {
                    $oleAuto = Get-DbaSpConfigure @connSplat -Name "Ole Automation Procedures" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($oleAuto) {
                        $splatCheck = @{
                            CheckId        = "PCI-1.4"
                            CheckName      = "OLE Automation Procedures Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.4"]
                            Status         = if ($oleAuto.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $oleAuto.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.4: $($_.Exception.Message)" }

                # PCI-1.5 Ad hoc distributed queries disabled — Req 2.2.4: no OPENROWSET data exfiltration path.
                try {
                    $adHoc = Get-DbaSpConfigure @connSplat -Name "Ad Hoc Distributed Queries" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($adHoc) {
                        $splatCheck = @{
                            CheckId        = "PCI-1.5"
                            CheckName      = "Ad Hoc Distributed Queries Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.5"]
                            Status         = if ($adHoc.RunningValue -eq 0) { "Pass" } else { "Fail" }
                            CurrentValue   = $adHoc.RunningValue.ToString()
                            ExpectedValue  = "0"
                            Remediation    = "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.5: $($_.Exception.Message)" }

                # PCI-1.6 CLR strict security — Req 2.2.4: prevent UNSAFE CLR assembly execution.
                # On SQL 2017+: clr strict security must be 1 if CLR is enabled.
                # On pre-2017: CLR should be disabled; if enabled, emit Manual.
                try {
                    $clrEnabled = Get-DbaSpConfigure @connSplat -Name "clr enabled" -WarningAction SilentlyContinue | Select-Object -First 1
                    $clrStrict  = Get-DbaSpConfigure @connSplat -Name "clr strict security" -WarningAction SilentlyContinue | Select-Object -First 1
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
                        $remText = "Review all CLR assemblies: SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1. UNSAFE or EXTERNAL_ACCESS assemblies violate PCI Req 2.2.4. Disable CLR if not required: EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"
                        $aType   = "Manual"
                    }

                    $splatCheck = @{
                        CheckId        = "PCI-1.6"
                        CheckName      = "CLR Strict Security"
                        Category       = "Secure Configuration"
                        AssessmentType = $aType
                        Priority       = $pciPriority["1.6"]
                        Status         = $status
                        CurrentValue   = $current
                        ExpectedValue  = "CLR disabled, or CLR strict security = 1 (SQL 2017+)"
                        Remediation    = $remText
                        Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                        SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name IN ('clr enabled','clr strict security');"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-1.6: $($_.Exception.Message)" }

                # PCI-1.7 SQL Browser service — Req 2.2.4: disable unnecessary services.
                # SQL Browser exposes instance/port enumeration to network scanners.
                # A Warning (not Fail) is issued because named instances may need Browser for dynamic port resolution.
                try {
                    $browserSvc = Get-DbaService -ComputerName $computerName -Type Browser -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($browserSvc) {
                        $running = $browserSvc.State -eq "Running"
                        $splatCheck = @{
                            CheckId        = "PCI-1.7"
                            CheckName      = "SQL Browser Service Disabled"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.7"]
                            Status         = if ($running) { "Warning" } else { "Pass" }
                            CurrentValue   = "State: $($browserSvc.State); StartMode: $($browserSvc.StartMode)"
                            ExpectedValue  = "State: Stopped; StartMode: Disabled"
                            Remediation    = "If using a named instance with a fixed TCP port, SQL Browser is not required. Disable in SQL Server Configuration Manager or: Set-DbaService -ComputerName $computerName -Type SqlBrowser -StartupType Disabled. Named instances using dynamic ports require SQL Browser for port resolution — consider switching to a fixed port first (PCI-1.8)."
                            Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                            SqlQuery       = "-- Automated via Get-DbaService -Type SqlBrowser. No T-SQL equivalent — service state is OS-level."
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.7: $($_.Exception.Message)" }

                # PCI-1.8 Non-standard TCP port — Req 2.2.7: non-console admin access via encrypted channel.
                # Default port 1433 is the primary SQL Server scan target.
                try {
                    $tcpPort = Get-DbaTcpPort @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    $port    = if ($tcpPort) { $tcpPort.Port } else { -1 }
                    if ($port -ne -1) {
                        $splatCheck = @{
                            CheckId        = "PCI-1.8"
                            CheckName      = "Non-Standard TCP Port"
                            Category       = "Secure Configuration"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["1.8"]
                            Status         = if ($port -ne 1433) { "Pass" } else { "Fail" }
                            CurrentValue   = $port.ToString()
                            ExpectedValue  = "Any port other than 1433"
                            Remediation    = "Change the TCP port in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > TCP/IP > IP Addresses > IPAll > TCP Port. Restart the SQL Server service to apply."
                            Reference      = "PCI DSS v4.0.1 Req 2.2.7"
                            SqlQuery       = "-- Automated via Get-DbaTcpPort. T-SQL: SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID;"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-1.8: $($_.Exception.Message)" }

                # PCI-1.9 Hide instance — Req 2.2.4: reduce instance discovery surface area.
                # No dbatools equivalent — querying sys.dm_server_registry.
                try {
                    $hideQuery = @"
SELECT CAST(value_data AS INT) AS HideInstance
FROM sys.dm_server_registry
WHERE registry_key LIKE N'%SuperSocketNetLib%'
  AND value_name = N'HideInstance';
"@
                    $hideResult = Invoke-DbaQuery @connSplat -Query $hideQuery -WarningAction SilentlyContinue
                    $hidden     = $hideResult -and @($hideResult)[0].HideInstance -eq 1
                    $splatCheck = @{
                        CheckId        = "PCI-1.9"
                        CheckName      = "Hide Instance Enabled"
                        Category       = "Secure Configuration"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["1.9"]
                        Status         = if ($hidden) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($hidden) { "1 (hidden)" } else { "0 (visible)" }
                        ExpectedValue  = "1 (instance hidden from SQL Browser enumeration)"
                        Remediation    = "Enable in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > Properties > Hide Instance = Yes."
                        Reference      = "PCI DSS v4.0.1 Req 2.2.4"
                        SqlQuery       = $hideQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-1.9: $($_.Exception.Message)" }
            }

            # ── §2 Access Control (Req 7–8) ───────────────────────────────────────
            if (ShouldRun "2") {
                Write-Verbose "[$instance] §2 Access Control"

                # PCI-2.1 Windows-only auth — Req 8.2.1: unique IDs; SQL logins bypass AD MFA controls.
                try {
                    $authMode = Get-DbaInstanceProperty @connSplat -InstanceProperty LoginMode -WarningAction SilentlyContinue | Select-Object -First 1
                    $winOnly  = ($authMode.Value -eq 1)
                    $splatCheck = @{
                        CheckId        = "PCI-2.1"
                        CheckName      = "Windows-Only Authentication"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.1"]
                        Status         = if ($winOnly) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($winOnly) { "Windows Only" } else { "Mixed Mode" }
                        ExpectedValue  = "Windows Only (LoginMode = 1)"
                        Remediation    = "Mixed mode allows SQL logins that exist outside AD, cannot be centrally deprovisioned, and bypass MFA requirements. Change to Windows Authentication: EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1  -- Restart required."
                        Reference      = "PCI DSS v4.0.1 Req 8.2.1"
                        SqlQuery       = "-- Automated via Get-DbaInstanceProperty (SMO LoginMode). T-SQL: SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;  -- 1 = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.1: $($_.Exception.Message)" }

                # PCI-2.2 BUILTIN groups absent — Req 7.2: access based on job function; local admins bypass provisioning.
                try {
                    $builtins = Get-DbaLogin @connSplat -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -like "BUILTIN\*" }
                    $count = if ($builtins) { @($builtins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.2"
                        CheckName      = "BUILTIN Groups Absent"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { ($builtins.Name -join ", ") }
                        ExpectedValue  = "None"
                        Remediation    = "BUILTIN groups grant SQL access to every local administrator outside SQL Server's provisioning process. Confirm domain group equivalents exist, then: USE [master]; DROP LOGIN [BUILTIN\Administrators];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2"
                        SqlQuery       = "-- Automated via Get-DbaLogin. T-SQL: SELECT name FROM sys.server_principals WHERE name LIKE 'BUILTIN%';  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.2: $($_.Exception.Message)" }

                # PCI-2.3 Guest access revoked — Req 7.2: no access without explicit provisioning.
                try {
                    $guestDbs = Get-DbaDbUser @connSplat -ExcludeDatabase master, msdb, tempdb -User "guest" -WarningAction SilentlyContinue |
                        Where-Object { $_.HasDbAccess -eq $true }
                    $count = if ($guestDbs) { @($guestDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.3"
                        CheckName      = "Guest Access Revoked"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "Revoked in all user databases" } else { "Active in: $($guestDbs.Database -join ', ')" }
                        ExpectedValue  = "CONNECT revoked in all user databases"
                        Remediation    = "USE [<database>]; REVOKE CONNECT FROM [guest];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2"
                        SqlQuery       = "-- Automated via Get-DbaDbUser. T-SQL per user DB: SELECT permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.3: $($_.Exception.Message)" }

                # PCI-2.4 Public role excess permissions — Req 7.2: least privilege; public = all principals.
                # No dbatools equivalent for server-level public permissions — using Invoke-DbaQuery.
                try {
                    $pubPermQuery = @"
SELECT COUNT(*) AS Count
FROM sys.server_permissions
WHERE grantee_principal_id = 2
  AND state IN ('G','W')
  AND type NOT IN (
      'CO',  -- CONNECT SQL (required for login)
      'VASM' -- VIEW ANY DATABASE (default in some configs)
  );
"@
                    $pubPerms = Invoke-DbaQuery @connSplat -Query $pubPermQuery -WarningAction SilentlyContinue
                    $count    = if ($pubPerms) { $pubPerms.Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.4"
                        CheckName      = "Public Role — No Excess Server Permissions"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.4"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count non-standard permission(s) granted to public"
                        ExpectedValue  = "0 — only CONNECT SQL is standard for the public role"
                        Remediation    = "Review and revoke: SELECT type_desc, permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = 2 AND state IN ('G','W'); Then: REVOKE <permission> FROM [public];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2"
                        SqlQuery       = $pubPermQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.4: $($_.Exception.Message)" }

                # PCI-2.5 Orphaned users — Req 7.2: no residual access from deprovisioned accounts.
                try {
                    $orphaned = Get-DbaDbOrphanUser @connSplat -WarningAction SilentlyContinue
                    $count    = if ($orphaned) { @($orphaned).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.5"
                        CheckName      = "No Orphaned Database Users"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.5"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count orphaned user(s): $($orphaned.User -join ', ')" }
                        ExpectedValue  = "No orphaned users in any database"
                        Remediation    = "Remove orphaned users: Remove-DbaDbOrphanUser -SqlInstance $instance  -- or map to a login: USE [<db>]; ALTER USER [<user>] WITH LOGIN = [<login>];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2"
                        SqlQuery       = "-- Automated via Get-DbaDbOrphanUser. T-SQL per DB: SELECT name FROM sys.database_principals WHERE type IN ('S','U','G') AND authentication_type_desc = 'INSTANCE' AND sid NOT IN (SELECT sid FROM sys.server_principals);"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.5: $($_.Exception.Message)" }

                # PCI-2.6 SQL logins enforce password policy — Req 8.3.6: password complexity requirements.
                try {
                    $noPolicy = Get-DbaLogin @connSplat -Type SQL -WarningAction SilentlyContinue |
                        Where-Object { -not $_.PasswordPolicyEnforced }
                    $count = if ($noPolicy) { @($noPolicy).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.6"
                        CheckName      = "SQL Login Password Policy Enforced"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.6"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count login(s) without CHECK_POLICY" }
                        ExpectedValue  = "CHECK_POLICY = ON for all SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON;  -- Enumerate: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;"
                        Reference      = "PCI DSS v4.0.1 Req 8.3.6"
                        SqlQuery       = "-- Automated via Get-DbaLogin (PasswordPolicyEnforced). T-SQL: SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;  -- No rows = compliant"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.6: $($_.Exception.Message)" }

                # PCI-2.7 CHECK_EXPIRATION on privileged SQL logins — Req 8.3.9: periodic password changes.
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
                        CheckId        = "PCI-2.7"
                        CheckName      = "Privileged Login Password Expiration"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.7"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All compliant" } else { "$count privileged login(s) without CHECK_EXPIRATION" }
                        ExpectedValue  = "CHECK_EXPIRATION = ON for all privileged SQL logins"
                        Remediation    = "ALTER LOGIN [<name>] WITH CHECK_EXPIRATION = ON;"
                        Reference      = "PCI DSS v4.0.1 Req 8.3.9"
                        SqlQuery       = $expQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.7: $($_.Exception.Message)" }

                # PCI-2.8 MUST_CHANGE logins — Req 8.2: accounts with MUST_CHANGE pending may indicate
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
                        CheckId        = "PCI-2.8"
                        CheckName      = "MUST_CHANGE Logins"
                        Category       = "Access Control"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["2.8"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Warning" }
                        CurrentValue   = if ($count -eq 0) { "None" } else { "$count login(s) with MUST_CHANGE pending" }
                        ExpectedValue  = "0 — no active logins with a pending forced password change"
                        Remediation    = "Investigate whether these accounts have never been used (provision-and-forget pattern). If the account is legitimate and the user has connected, this clears automatically. Disable unused accounts."
                        Reference      = "PCI DSS v4.0.1 Req 8.2"
                        SqlQuery       = $mcQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.8: $($_.Exception.Message)" }

                # PCI-2.9 Sysadmin membership — Manual: Req 7.2.2 requires least-privilege access documented
                # and reviewed. Sysadmin bypasses all permission checks and can read all cardholder data.
                try {
                    $builtinFilter = @('NT SERVICE\SQLWriter','NT SERVICE\Winmgmt','NT SERVICE\MSSQLSERVER','NT SERVICE\SQLSERVERAGENT')
                    $sysadmins = Get-DbaServerRoleMember @connSplat -ServerRole sysadmin -WarningAction SilentlyContinue |
                        Where-Object { $_.Name -notin $builtinFilter -and $_.Name -notlike '##*' }
                    $count = if ($sysadmins) { @($sysadmins).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-2.9"
                        CheckName      = "Sysadmin Membership Review"
                        Category       = "Access Control"
                        AssessmentType = "Manual"
                        Priority       = $pciPriority["2.9"]
                        Status         = "Manual"
                        CurrentValue   = "$count non-system account(s) with sysadmin"
                        ExpectedValue  = "Minimum necessary; each account documented and recertified at least every 6 months (PCI DSS Req 7.2.2)"
                        Remediation    = "Review all members: SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%'. Remove any not formally approved: ALTER SERVER ROLE sysadmin DROP MEMBER [<account>];"
                        Reference      = "PCI DSS v4.0.1 Req 7.2.2"
                        SqlQuery       = "-- Automated via Get-DbaServerRoleMember. T-SQL: SELECT DISTINCT name, type_desc FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT LIKE '##%';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-2.9: $($_.Exception.Message)" }
            }

            # ── §3 Data Protection (Req 3–4) ─────────────────────────────────────
            if (ShouldRun "3") {
                Write-Verbose "[$instance] §3 Data Protection"

                # PCI-3.1 TDE scope — Manual: Req 3.5.1 requires PAN rendered unreadable at rest.
                # Tool collects evidence; auditor determines which databases are in PAN scope.
                try {
                    $unencDbs = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { -not $_.EncryptionEnabled }
                    $count = if ($unencDbs) { @($unencDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-3.1"
                        CheckName      = "TDE Scope Review"
                        Category       = "Data Protection"
                        AssessmentType = "Manual"
                        Priority       = $pciPriority["3.1"]
                        Status         = "Manual"
                        CurrentValue   = "$count user database(s) without TDE"
                        ExpectedValue  = "TDE enabled on all databases storing PAN or sensitive authentication data"
                        Remediation    = "Identify databases in PCI scope. For each: Enable-DbaDatabaseEncryption -SqlInstance $instance -Database <dbname>  -- Requires a database master key and certificate on master."
                        Reference      = "PCI DSS v4.0.1 Req 3.5.1"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted = 0;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-3.1: $($_.Exception.Message)" }

                # PCI-3.2 Symmetric key algorithms — Req 3.6.1: strong cryptography; AES only.
                # No dbatools equivalent — using Invoke-DbaQuery per user database.
                try {
                    $symKeyQuery = "SELECT COUNT(*) AS WeakKeys FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256');"
                    $userDbs3    = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $weakKeys    = 0
                    foreach ($db in @($userDbs3)) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $symKeyQuery -WarningAction SilentlyContinue
                        if ($r) { $weakKeys += $r.WeakKeys }
                    }
                    $splatCheck = @{
                        CheckId        = "PCI-3.2"
                        CheckName      = "Symmetric Key Algorithms — AES Only"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.2"]
                        Status         = if ($weakKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$weakKeys non-AES symmetric key(s) across all user databases"
                        ExpectedValue  = "0 — all symmetric keys use AES_128, AES_192, or AES_256"
                        Remediation    = "Per database: SELECT name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256'). Recreate non-AES keys using a supported algorithm before dropping the old ones."
                        Reference      = "PCI DSS v4.0.1 Req 3.6.1"
                        SqlQuery       = $symKeyQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-3.2: $($_.Exception.Message)" }

                # PCI-3.3 Asymmetric key size — Req 3.7.1: RSA keys must be at least 2048-bit.
                # No dbatools equivalent — using Invoke-DbaQuery per user database.
                try {
                    $asymKeyQuery = "SELECT COUNT(*) AS ShortKeys FROM sys.asymmetric_keys WHERE key_length < 2048;"
                    $userDbs3b    = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $shortKeys    = 0
                    foreach ($db in @($userDbs3b)) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $asymKeyQuery -WarningAction SilentlyContinue
                        if ($r) { $shortKeys += $r.ShortKeys }
                    }
                    $splatCheck = @{
                        CheckId        = "PCI-3.3"
                        CheckName      = "Asymmetric Key Size — Min 2048-bit"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.3"]
                        Status         = if ($shortKeys -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$shortKeys asymmetric key(s) shorter than 2048-bit"
                        ExpectedValue  = "0 — all asymmetric keys at least 2048-bit"
                        Remediation    = "Per database: SELECT name, key_length FROM sys.asymmetric_keys WHERE key_length < 2048. Recreate undersized keys with a 2048-bit or 4096-bit RSA key."
                        Reference      = "PCI DSS v4.0.1 Req 3.7.1"
                        SqlQuery       = $asymKeyQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-3.3: $($_.Exception.Message)" }

                # PCI-3.4 Network encryption — Req 4.2.1: strong cryptography for all data in transit.
                # No dbatools equivalent — using Invoke-DbaQuery against sys.dm_exec_connections.
                try {
                    $q3_4 = @"
SELECT DISTINCT encrypt_option
FROM sys.dm_exec_connections c
WHERE net_transport <> 'Shared memory'
  AND c.endpoint_id NOT IN (
      SELECT endpoint_id FROM sys.database_mirroring_endpoints
      WHERE encryption_algorithm IS NOT NULL
  );
"@
                    $r3_4  = Invoke-DbaQuery @connSplat -Query $q3_4 -WarningAction SilentlyContinue
                    $unenc = if ($r3_4) { @($r3_4 | Where-Object { $_.encrypt_option -ne "TRUE" }).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-3.4"
                        CheckName      = "Network Encryption Enforced"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.4"]
                        Status         = if ($unenc -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($unenc -eq 0) { "All non-shared-memory connections encrypted" } else { "$unenc unencrypted connection type(s) detected" }
                        ExpectedValue  = "All non-shared-memory connections encrypted"
                        Remediation    = "Enable Force Encryption in SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties > Force Encryption = Yes. A trusted certificate is required."
                        Reference      = "PCI DSS v4.0.1 Req 4.2.1"
                        SqlQuery       = $q3_4
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-3.4: $($_.Exception.Message)" }

                # PCI-3.5 Backup encryption — Req 3.5.1: PAN must be unreadable wherever stored, including backups.
                # No dbatools equivalent — using Invoke-DbaQuery against msdb.dbo.backupset.
                try {
                    $q3_5 = @"
SELECT COUNT(*) AS UnencBackups
FROM msdb.dbo.backupset b
JOIN sys.databases d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL
  AND b.encryptor_type IS NULL
  AND d.is_encrypted = 0
  AND b.backup_finish_date >= DATEADD(DAY, -30, GETDATE());
"@
                    $r3_5 = Invoke-DbaQuery @connSplat -Query $q3_5 -WarningAction SilentlyContinue
                    $count = if ($r3_5) { $r3_5.UnencBackups } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-3.5"
                        CheckName      = "Backup Encryption"
                        Category       = "Data Protection"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["3.5"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$count unencrypted backup record(s) in the past 30 days"
                        ExpectedValue  = "0 — all backups encrypted or database encrypted via TDE"
                        Remediation    = "Enable backup encryption via the WITH ENCRYPTION clause on BACKUP DATABASE, or enable TDE on PAN-scope databases (TDE-encrypted databases produce automatically encrypted backups)."
                        Reference      = "PCI DSS v4.0.1 Req 3.5.1"
                        SqlQuery       = $q3_5
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-3.5: $($_.Exception.Message)" }
            }

            # ── §4 Audit & Logging (Req 10) ───────────────────────────────────────
            if (ShouldRun "4") {
                Write-Verbose "[$instance] §4 Audit & Logging"

                # PCI-4.1 SQL Server Audit — Req 10.2.1: capture all required event categories.
                # PCI requires 6 action groups (adds SCHEMA_OBJECT_CHANGE_GROUP vs SOX 5).
                # No dbatools equivalent for server audit specification details — using Invoke-DbaQuery.
                try {
                    $auditQuery = @"
SELECT SAD.audit_action_name, S.is_state_enabled AS AuditEnabled, SA.is_state_enabled AS SpecEnabled
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('LGFL','LGSD','ADDP','ADSP','CNAU','SCHM');
"@
                    $auditRows   = Invoke-DbaQuery @connSplat -Query $auditQuery -WarningAction SilentlyContinue
                    $required    = @(
                        "FAILED_LOGIN_GROUP",
                        "SUCCESSFUL_LOGIN_GROUP",
                        "DATABASE_ROLE_MEMBER_CHANGE_GROUP",
                        "SERVER_ROLE_MEMBER_CHANGE_GROUP",
                        "AUDIT_CHANGE_GROUP",
                        "SCHEMA_OBJECT_CHANGE_GROUP"
                    )
                    $foundGroups = if ($auditRows) {
                        @($auditRows | Where-Object { $_.AuditEnabled -and $_.SpecEnabled } |
                            Select-Object -ExpandProperty audit_action_name -Unique)
                    } else { @() }
                    $missing   = $required | Where-Object { $_ -notin $foundGroups }
                    $compliant = $missing.Count -eq 0
                    $splatCheck = @{
                        CheckId        = "PCI-4.1"
                        CheckName      = "SQL Server Audit — PCI Action Groups"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.1"]
                        Status         = if ($compliant) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($foundGroups.Count -eq 0) { "No enabled audit" } else { "$($foundGroups.Count) of $($required.Count) required groups captured" }
                        ExpectedValue  = "All 6 PCI action groups enabled in an active audit and specification"
                        Remediation    = if ($compliant) { $null } else { "Missing groups: $($missing -join ', '). Create a SERVER AUDIT targeted to a protected file path with 90-day retention and a SERVER AUDIT SPECIFICATION covering all 6 action groups." }
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1"
                        SqlQuery       = $auditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-4.1: $($_.Exception.Message)" }

                # PCI-4.2 Login audit level — Req 10.2.1.4: log all invalid logical access attempts.
                # No dbatools equivalent for xp_loginconfig output — using Invoke-DbaQuery.
                try {
                    $auditLevel = Invoke-DbaQuery @connSplat -Query "EXEC xp_loginconfig 'audit level';" -WarningAction SilentlyContinue
                    $rawLevel   = if ($auditLevel -and $auditLevel[0]) { $auditLevel[0].config_value } else { $null }
                    $level      = if ($null -ne $rawLevel) { $rawLevel.Trim() } else { "none" }
                    $splatCheck = @{
                        CheckId        = "PCI-4.2"
                        CheckName      = "Login Audit Level"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.2"]
                        Status         = if ($level -in "all", "failure") { "Pass" } else { "Fail" }
                        CurrentValue   = $level
                        ExpectedValue  = "failure or all"
                        Remediation    = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 2  -- 2 = failure, 3 = all. SQL Server service restart required."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.4"
                        SqlQuery       = "EXEC xp_loginconfig 'audit level';  -- config_value should be 'failure' or 'all'"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-4.2: $($_.Exception.Message)" }

                # PCI-4.3 Error log retention >= 12 — Req 10.5.1: retain audit logs for at least 12 months.
                try {
                    $logCfg   = Get-DbaErrorLogConfig @connSplat -WarningAction SilentlyContinue | Select-Object -First 1
                    $rawCount = if ($logCfg) { $logCfg.LogCount } else { -1 }
                    $count    = if ($rawCount -lt 0) { 6 } else { $rawCount }
                    $display  = if ($rawCount -lt 0) { "default (6) — registry key absent" } else { $count.ToString() }
                    $splatCheck = @{
                        CheckId        = "PCI-4.3"
                        CheckName      = "Error Log Retention — Min 12"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.3"]
                        Status         = if ($count -ge 12) { "Pass" } else { "Fail" }
                        CurrentValue   = $display
                        ExpectedValue  = "12 or more"
                        Remediation    = "Set-DbaErrorLogConfig -SqlInstance $instance -LogCount 12  -- Note: SQL Server error log recycling is not a substitute for a dedicated audit trail. PCI Req 10.5.1 requires a separate audit log solution with 12-month retention and 3-month online availability."
                        Reference      = "PCI DSS v4.0.1 Req 10.5.1"
                        SqlQuery       = "-- Automated via Get-DbaErrorLogConfig. T-SQL: DECLARE @n INT; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @n OUTPUT; SELECT ISNULL(@n, 6) AS NumberOfLogFiles;"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-4.3: $($_.Exception.Message)" }

                # PCI-4.4 Default trace enabled — Req 10.2: baseline change and security event evidence.
                try {
                    $defTrace = Get-DbaSpConfigure @connSplat -Name "DefaultTraceEnabled" -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($defTrace) {
                        $splatCheck = @{
                            CheckId        = "PCI-4.4"
                            CheckName      = "Default Trace Enabled"
                            Category       = "Audit"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["4.4"]
                            Status         = if ($defTrace.RunningValue -eq 1) { "Pass" } else { "Fail" }
                            CurrentValue   = $defTrace.RunningValue.ToString()
                            ExpectedValue  = "1"
                            Remediation    = "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;"
                            Reference      = "PCI DSS v4.0.1 Req 10.2"
                            SqlQuery       = "SELECT name, value_in_use AS RunningValue FROM sys.configurations WHERE name = 'default trace enabled';"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-4.4: $($_.Exception.Message)" }

                # PCI-4.5 Audit captures role membership changes — Req 10.2.1.5: changes to
                # identification and authentication mechanisms must be logged.
                # No dbatools equivalent — using Invoke-DbaQuery.
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
                        CheckId        = "PCI-4.5"
                        CheckName      = "Audit — Role Membership Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.5"]
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP captured"
                        Remediation    = "Add SERVER_ROLE_MEMBER_CHANGE_GROUP and DATABASE_ROLE_MEMBER_CHANGE_GROUP to your active server audit specification."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.5"
                        SqlQuery       = $roleAuditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-4.5: $($_.Exception.Message)" }

                # PCI-4.6 Audit captures DDL/schema changes — Req 10.2.1.2: object-level access to
                # cardholder data and schema changes must be recorded.
                # No dbatools equivalent — using Invoke-DbaQuery.
                try {
                    $ddlAuditQuery = @"
SELECT COUNT(*) AS Found
FROM sys.server_audit_specification_details SAD
JOIN sys.server_audit_specifications SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits S ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('SCHM','DAUC','CDBR')
  AND S.is_state_enabled = 1 AND SA.is_state_enabled = 1;
"@
                    $ddlAudit = Invoke-DbaQuery @connSplat -Query $ddlAuditQuery -WarningAction SilentlyContinue
                    $found    = $ddlAudit -and $ddlAudit.Found -gt 0
                    $splatCheck = @{
                        CheckId        = "PCI-4.6"
                        CheckName      = "Audit — DDL / Schema Changes"
                        Category       = "Audit"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["4.6"]
                        Status         = if ($found) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($found) { "Configured" } else { "Not configured" }
                        ExpectedValue  = "SCHEMA_OBJECT_CHANGE_GROUP or DATABASE_CHANGE_GROUP captured"
                        Remediation    = "Add SCHEMA_OBJECT_CHANGE_GROUP to your active server audit specification. For database-level coverage on PCI-scope databases: CREATE DATABASE AUDIT SPECIFICATION covering SCHEMA_OBJECT_CHANGE_GROUP."
                        Reference      = "PCI DSS v4.0.1 Req 10.2.1.2"
                        SqlQuery       = $ddlAuditQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-4.6: $($_.Exception.Message)" }
            }

            # ── §5 Vulnerability Management (Req 6) ──────────────────────────────
            if (ShouldRun "5") {
                Write-Verbose "[$instance] §5 Vulnerability Management"

                # PCI-5.1 Patch level — Req 6.3.3: critical security patches within 1 month.
                # Test-DbaBuild -Latest -Update returns Compliant, BuildLevel, BuildTarget, and CUTarget.
                try {
                    $build = Test-DbaBuild @connSplat -Latest -Update -WarningAction SilentlyContinue | Select-Object -First 1
                    if ($build) {
                        $splatCheck = @{
                            CheckId        = "PCI-5.1"
                            CheckName      = "Patch Level — Req 6.3.3"
                            Category       = "Vulnerability Management"
                            AssessmentType = "Automated"
                            Priority       = $pciPriority["5.1"]
                            Status         = if ($build.Compliant) { "Pass" } else { "Fail" }
                            CurrentValue   = $build.BuildLevel.ToString()
                            ExpectedValue  = $build.BuildTarget.ToString()
                            Remediation    = if ($build.Compliant) { $null } else { "Apply the latest SQL Server CU: $($build.CUTarget)" }
                            Reference      = "PCI DSS v4.0.1 Req 6.3.3"
                            SqlQuery       = "SELECT SERVERPROPERTY('ProductVersion') AS Build, SERVERPROPERTY('ProductLevel') AS SPLevel, SERVERPROPERTY('ProductUpdateLevel') AS CULevel, SERVERPROPERTY('Edition') AS Edition;"
                        }
                        & $emit (New-DakCheckResult @sharedParams @splatCheck)
                    }
                } catch { Write-Warning "[$instance] PCI-5.1: $($_.Exception.Message)" }

                # PCI-5.2 DBCC CHECKDB within 7 days — structural integrity is a pre-condition for data reliability.
                try {
                    $checkdbInfo  = Get-DbaLastGoodCheckDb @connSplat -ExcludeDatabase tempdb -WarningAction SilentlyContinue
                    $staleCheckdb = @($checkdbInfo | Where-Object {
                        $null -eq $_.LastGoodCheckDb -or $_.LastGoodCheckDb -lt (Get-Date).AddDays(-7)
                    })
                    $count = $staleCheckdb.Count
                    $splatCheck = @{
                        CheckId        = "PCI-5.2"
                        CheckName      = "DBCC CHECKDB Within 7 Days"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["5.2"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All databases checked within 7 days" } else { "$count database(s) overdue: $($staleCheckdb.Database -join ', ')" }
                        ExpectedValue  = "DBCC CHECKDB completed within 7 days on all databases"
                        Remediation    = "Schedule integrity checks: Invoke-DbaDbIntegrityCheck -SqlInstance $instance -Database <db>  -- or use Ola Hallengren's DatabaseIntegrityCheck job."
                        Reference      = "PCI DSS v4.0.1 Req 6"
                        SqlQuery       = "-- Automated via Get-DbaLastGoodCheckDb. T-SQL reference: DBCC DBINFO() WITH TABLERESULTS;  -- Look for dbi_dbccLastKnownGood."
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-5.2: $($_.Exception.Message)" }

                # PCI-5.3 All user databases accessible — inaccessible databases indicate a potential breach or failure.
                try {
                    $problemDbs = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { -not $_.IsAccessible }
                    $count = if ($problemDbs) { @($problemDbs).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-5.3"
                        CheckName      = "All User Databases Accessible"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["5.3"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases accessible" } else { "$count inaccessible: $($problemDbs.Name -join ', ')" }
                        ExpectedValue  = "All user databases in an accessible state"
                        Remediation    = "Investigate inaccessible databases in the SQL Server error log. Databases in Suspect or Recovery_Pending state may indicate corruption or an incomplete restore."
                        Reference      = "PCI DSS v4.0.1 Req 6"
                        SqlQuery       = "-- Automated via Get-DbaDatabase (IsAccessible). T-SQL: SELECT name, state_desc FROM sys.databases WHERE database_id > 4 AND state <> 0;  -- state 0 = ONLINE"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-5.3: $($_.Exception.Message)" }

                # PCI-5.4 Page verify CHECKSUM — detects I/O-layer corruption before it silently spreads.
                try {
                    $noCksum = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue |
                        Where-Object { $_.PageVerify -ne "Checksum" }
                    $count = if ($noCksum) { @($noCksum).Count } else { 0 }
                    $splatCheck = @{
                        CheckId        = "PCI-5.4"
                        CheckName      = "Page Verify CHECKSUM"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["5.4"]
                        Status         = if ($count -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = if ($count -eq 0) { "All user databases use CHECKSUM" } else { "$count database(s) without CHECKSUM: $($noCksum.Name -join ', ')" }
                        ExpectedValue  = "PAGE_VERIFY = CHECKSUM for all user databases"
                        Remediation    = "ALTER DATABASE [<dbname>] SET PAGE_VERIFY CHECKSUM;"
                        Reference      = "PCI DSS v4.0.1 Req 6"
                        SqlQuery       = "-- Automated via Get-DbaDatabase. T-SQL: SELECT name, page_verify_option_desc FROM sys.databases WHERE database_id > 4 AND page_verify_option_desc <> 'CHECKSUM';"
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-5.4: $($_.Exception.Message)" }

                # PCI-5.5 UNSAFE CLR assemblies — Req 6.3.2: identify and address security vulnerabilities.
                # UNSAFE assemblies can call arbitrary Win32 APIs and read/write the file system.
                # No dbatools equivalent — using Invoke-DbaQuery per user database.
                try {
                    $clrUnsafeQuery = "SELECT COUNT(*) AS UnsafeAssemblies FROM sys.assemblies WHERE permission_set_desc = 'UNSAFE_ACCESS' AND is_user_defined = 1;"
                    $userDbs5       = Get-DbaDatabase @connSplat -ExcludeSystem -WarningAction SilentlyContinue
                    $unsafeCount    = 0
                    foreach ($db in @($userDbs5)) {
                        $r = Invoke-DbaQuery @connSplat -Database $db.Name -Query $clrUnsafeQuery -WarningAction SilentlyContinue
                        if ($r) { $unsafeCount += $r.UnsafeAssemblies }
                    }
                    $splatCheck = @{
                        CheckId        = "PCI-5.5"
                        CheckName      = "No UNSAFE CLR Assemblies"
                        Category       = "Vulnerability Management"
                        AssessmentType = "Automated"
                        Priority       = $pciPriority["5.5"]
                        Status         = if ($unsafeCount -eq 0) { "Pass" } else { "Fail" }
                        CurrentValue   = "$unsafeCount UNSAFE CLR assembly/assemblies across all user databases"
                        ExpectedValue  = "0 — no user-defined assemblies with UNSAFE_ACCESS permission set"
                        Remediation    = "Per database: SELECT name, permission_set_desc FROM sys.assemblies WHERE permission_set_desc = 'UNSAFE_ACCESS' AND is_user_defined = 1. Review each assembly for necessity. Recreate with SAFE or EXTERNAL_ACCESS where possible; drop if not required."
                        Reference      = "PCI DSS v4.0.1 Req 6.3.2"
                        SqlQuery       = $clrUnsafeQuery
                    }
                    & $emit (New-DakCheckResult @sharedParams @splatCheck)
                } catch { Write-Warning "[$instance] PCI-5.5: $($_.Exception.Message)" }
            }

            Write-Verbose "[$instance] PCI assessment complete"
        }
    }

    end {}
}
