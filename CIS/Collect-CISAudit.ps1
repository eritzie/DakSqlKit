<#
    Collect-CISAudit.ps1
    Purpose: Collect all CIS SQL Server 2022 Benchmark audit data using 
             dbatools cmdlets and export to a single dated Excel workbook.
    
    Dependencies: 
        - dbatools      (Install-Module dbatools)
        - ImportExcel   (Install-Module ImportExcel)
    
    Usage:
        # Basic — outputs to current directory
        .\Collect-CISAudit.ps1 -SqlInstance "SQLPROD01"

        # Specify output folder
        .\Collect-CISAudit.ps1 -SqlInstance "SQLPROD01" -OutputPath "C:\Audit"

        # Multiple instances
        .\Collect-CISAudit.ps1 -SqlInstance "SQLPROD01","SQLPROD02"

        # With SQL authentication
        .\Collect-CISAudit.ps1 -SqlInstance "SQLPROD01" -SqlCredential (Get-Credential)

    Output:
        CIS_Audit_SERVERNAME_2026-03-25.xlsx
        One worksheet per CIS section, plus a Cover sheet with run metadata.

    Notes:
        - Based on CIS Microsoft SQL Server 2022 Benchmark v1.2.1
        - Sections 1.2, 2.10, 3.5-3.7, 6.1, 8.1 include data for manual review
        - xp_cmdshell check is included as an additional best practice 
          (removed from 2022 benchmark, retained here)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]$SqlInstance,

    [Parameter()]
    [string]$OutputPath = ".",

    [Parameter()]
    [PSCredential]$SqlCredential
)

# ── Prerequisites ──────────────────────────────────────────────
$requiredModules = @('dbatools', 'ImportExcel')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' not found. Install with: Install-Module $mod"
        return
    }
}

# ── Build output filename ─────────────────────────────────────
$serverClean = ($SqlInstance -join '_') -replace '\\', '_'
$datestamp   = Get-Date -Format 'yyyy-MM-dd'
$fileName    = "CIS_Audit_${serverClean}_${datestamp}.xlsx"
$outputFile  = Join-Path $OutputPath $fileName

if (Test-Path $outputFile) { Remove-Item $outputFile -Force }

# ── Shared connection params ──────────────────────────────────
$connParams = @{ SqlInstance = $SqlInstance }
if ($SqlCredential) { $connParams.SqlCredential = $SqlCredential }

# ── Helper function ────────────────────────────────────────────
function Export-Tab {
    param ($Data, $TabName, $Path)
    if ($null -ne $Data -and @($Data).Count -gt 0) {
        $Data | Export-Excel -Path $Path -WorksheetName $TabName -AutoSize -TableName $TabName -Append
    } else {
        [PSCustomObject]@{ Result = 'No rows returned — compliant or not applicable' } | 
            Export-Excel -Path $Path -WorksheetName $TabName -AutoSize -Append
    }
}

# ── Collection ─────────────────────────────────────────────────
$errors = @()

# --- 1.1 Patch Level ---
Write-Host "1.1  Patch Level..." -ForegroundColor Cyan -NoNewline
try {
    $c1_1 = Test-DbaBuild -SqlInstance $SqlInstance -Latest -Update -WarningAction SilentlyContinue |
        Select-Object SqlInstance, NameLevel, KBLevel, SPLevel, CULevel, SPTarget, CUTarget, BuildLevel, BuildTarget, Compliant
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "1.1: $($_.Exception.Message)"
    $c1_1 = $null
}

# --- 2.1-2.8, 2.17 Surface Area sp_configure checks ---
Write-Host "2.x  Surface Area Configuration..." -ForegroundColor Cyan -NoNewline
try {
    $configNames = @(
        'AdHocDistributedQueriesEnabled',    # 2.1
        'IsSqlClrEnabled',                   # 2.2
        'CrossDBOwnershipChaining',          # 2.3
        'DatabaseMailEnabled',               # 2.4
        'OleAutomationProceduresEnabled',    # 2.5
        'RemoteAccess',                      # 2.6
        'RemoteDacConnectionsEnabled',       # 2.7
        'ScanForStartupProcedures',          # 2.8
        'ClrStrictSecurity',                 # 2.17
        'XPCmdShellEnabled'                  # Additional
    )
    $c2_config = foreach ($name in $configNames) {
        Get-DbaSpConfigure -SqlInstance $SqlInstance -Name $name -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, DisplayName, DefaultValue, ConfiguredValue, RunningValue
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.x Config: $($_.Exception.Message)"
    $c2_config = $null
}

# --- 2.9 Trustworthy ---
Write-Host "2.9  Trustworthy..." -ForegroundColor Cyan -NoNewline
try {
    $c2_9 = Get-DbaDatabase -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Name -ne 'msdb' } |
        Select-Object SqlInstance, Name, Trustworthy |
        Sort-Object Trustworthy -Descending
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.9: $($_.Exception.Message)"
    $c2_9 = $null
}

# --- 2.10 Protocols ---
Write-Host "2.10 Protocols..." -ForegroundColor Cyan -NoNewline
try {
    $c2_10 = Get-DbaInstanceProtocol -ComputerName $SqlInstance -WarningAction SilentlyContinue |
        Select-Object ComputerName, DisplayName, Order, IsEnabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.10: $($_.Exception.Message)"
    $c2_10 = $null
}

# --- 2.11 TCP Port ---
Write-Host "2.11 TCP Port..." -ForegroundColor Cyan -NoNewline
try {
    $c2_11 = Get-DbaTcpPort -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, IPAddress, Port, Static
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.11: $($_.Exception.Message)"
    $c2_11 = $null
}

# --- 2.12 Hide Instance ---
Write-Host "2.12 Hide Instance..." -ForegroundColor Cyan -NoNewline
try {
    $c2_12 = Get-DbaHideInstance -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, HideInstance
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.12: $($_.Exception.Message)"
    $c2_12 = $null
}

# --- 2.13 sa Disabled ---
Write-Host "2.13 sa Disabled..." -ForegroundColor Cyan -NoNewline
try {
    $c2_13 = Get-DbaLogin -SqlInstance $SqlInstance -Login 'sa' -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, IsDisabled, HasAccess
    # Also check by SID 0x01 in case sa was renamed
    $c2_13_sid = Get-DbaLogin -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Sid -and [System.BitConverter]::ToString($_.Sid) -eq '01' } |
        Select-Object SqlInstance, Name, IsDisabled, HasAccess
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.13: $($_.Exception.Message)"
    $c2_13 = $null
    $c2_13_sid = $null
}

# --- 2.14/2.16 sa Renamed / No sa login ---
Write-Host "2.14 sa Renamed..." -ForegroundColor Cyan -NoNewline
try {
    $c2_14 = Get-DbaLogin -SqlInstance $SqlInstance -Detailed -WarningAction SilentlyContinue |
        Where-Object { $_.SidString -eq '0x01' } |
        Select-Object SqlInstance, Name, SidString
    $c2_16 = Get-DbaLogin -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Name -eq 'sa' } |
        Select-Object SqlInstance, Name, IsDisabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.14: $($_.Exception.Message)"
    $c2_14 = $null
    $c2_16 = $null
}

# --- 2.15 AUTO_CLOSE ---
Write-Host "2.15 AUTO_CLOSE..." -ForegroundColor Cyan -NoNewline
try {
    $c2_15 = Get-DbaDatabase -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, ContainmentType, AutoClose |
        Sort-Object SqlInstance, Name
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "2.15: $($_.Exception.Message)"
    $c2_15 = $null
}

# --- 3.1 Server Authentication ---
Write-Host "3.1  Auth Mode..." -ForegroundColor Cyan -NoNewline
try {
    $c3_1 = Get-DbaInstanceProperty -SqlInstance $SqlInstance -InstanceProperty LoginMode -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, Value
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.1: $($_.Exception.Message)"
    $c3_1 = $null
}

# --- 3.2 Guest CONNECT ---
Write-Host "3.2  Guest CONNECT..." -ForegroundColor Cyan -NoNewline
try {
    $c3_2 = Get-DbaDbUser -SqlInstance $SqlInstance -ExcludeDatabase master, msdb, tempdb -User 'guest' -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Database, Name, Login, LoginType, HasDbAccess
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.2: $($_.Exception.Message)"
    $c3_2 = $null
}

# --- 3.3 Orphaned Users ---
Write-Host "3.3  Orphaned Users..." -ForegroundColor Cyan -NoNewline
try {
    $c3_3 = Get-DbaDbOrphanUser -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Database, Name
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.3: $($_.Exception.Message)"
    $c3_3 = $null
}

# --- 3.4 SQL Auth in Contained DBs ---
Write-Host "3.4  Contained DB Auth..." -ForegroundColor Cyan -NoNewline
try {
    $containedDbs = Get-DbaDatabase -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.ContainmentType -ne 'None' }
    if ($containedDbs) {
        $c3_4 = foreach ($db in $containedDbs) {
            Get-DbaDbUser -SqlInstance $db.Parent.Name -Database $db.Name -WarningAction SilentlyContinue |
            Where-Object { $_.AuthenticationType -eq 'Database' } |
            Select-Object SqlInstance, Database, Name, LoginType, AuthenticationType
        }
    } else {
        $c3_4 = [PSCustomObject]@{ Result = 'No contained databases found' }
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.4: $($_.Exception.Message)"
    $c3_4 = $null
}

# --- 3.5-3.7 Service Accounts ---
Write-Host "3.5  Service Accounts..." -ForegroundColor Cyan -NoNewline
try {
    $c3_5 = Get-DbaService -ComputerName $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.ServiceType -in ('Engine', 'Agent', 'FullText') } |
        Select-Object ComputerName, ServiceType, ServiceName, StartName, State, StartMode
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.5: $($_.Exception.Message)"
    $c3_5 = $null
}

# --- 3.8 Public Server Role Permissions ---
Write-Host "3.8  Public Role Perms..." -ForegroundColor Cyan -NoNewline
try {
    $query3_8 = @"
SELECT @@SERVERNAME AS [ServerName], *
FROM master.sys.server_permissions
WHERE (grantee_principal_id = SUSER_SID(N'public') AND state_desc LIKE 'GRANT%')
    AND NOT (state_desc = 'GRANT' AND [permission_name] = 'VIEW ANY DATABASE' AND class_desc = 'SERVER')
    AND NOT (state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 2)
    AND NOT (state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 3)
    AND NOT (state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 4)
    AND NOT (state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 5);
"@
    $c3_8 = Invoke-DbaQuery @connParams -Query $query3_8 -WarningAction SilentlyContinue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.8: $($_.Exception.Message)"
    $c3_8 = $null
}

# --- 3.9 BUILTIN Groups ---
Write-Host "3.9  BUILTIN Groups..." -ForegroundColor Cyan -NoNewline
try {
    $c3_9 = Get-DbaLogin -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Name -like 'BUILTIN\*' } |
        Select-Object SqlInstance, Name, LoginType, HasAccess, IsDisabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.9: $($_.Exception.Message)"
    $c3_9 = $null
}

# --- 3.10 Local Windows Groups ---
Write-Host "3.10 Local Groups..." -ForegroundColor Cyan -NoNewline
try {
    $c3_10 = foreach ($inst in $SqlInstance) {
        $machineName = ($inst -split '\\')[0]
        Get-DbaLogin -SqlInstance $inst -WarningAction SilentlyContinue |
        Where-Object { $_.LoginType -eq 'WindowsGroup' -and $_.Name -like "$machineName\*" } |
        Select-Object SqlInstance, Name, LoginType, HasAccess, IsDisabled
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.10: $($_.Exception.Message)"
    $c3_10 = $null
}

# --- 3.11 Public + Agent Proxies ---
Write-Host "3.11 Agent Proxies..." -ForegroundColor Cyan -NoNewline
try {
    $query3_11 = @"
SELECT @@SERVERNAME AS [ServerName], sp.name AS proxyname
FROM msdb.dbo.sysproxylogin spl
    JOIN sys.database_principals dp ON dp.sid = spl.sid
    JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id
WHERE principal_id = USER_ID('public');
"@
    $c3_11 = Invoke-DbaQuery @connParams -Database msdb -Query $query3_11 -WarningAction SilentlyContinue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.11: $($_.Exception.Message)"
    $c3_11 = $null
}

# --- 3.12 SYSADMIN Role ---
Write-Host "3.12 SYSADMIN Role..." -ForegroundColor Cyan -NoNewline
try {
    $c3_12 = Get-DbaServerRoleMember -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Role -eq 'sysadmin' -and $_.Name -notlike '##*' -and $_.Name -notlike 'NT SERVICE\*' } |
        Select-Object SqlInstance, @{ Name = 'LoginName'; Expression = { $_.Name } }, Role
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.12: $($_.Exception.Message)"
    $c3_12 = $null
}

# --- 3.13 msdb Admin Roles ---
Write-Host "3.13 msdb Roles..." -ForegroundColor Cyan -NoNewline
try {
    $c3_13 = Get-DbaDbRoleMember -SqlInstance $SqlInstance -Database msdb -WarningAction SilentlyContinue |
        Where-Object { $_.Role -in 'db_owner','db_securityadmin','db_ddladmin','db_datawriter' -and $_.UserName -ne 'dbo' } |
        Select-Object SqlInstance, Database, @{ Name = 'MemberName'; Expression = { $_.UserName } }, Role
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "3.13: $($_.Exception.Message)"
    $c3_13 = $null
}

# --- 4.1 MUST_CHANGE ---
Write-Host "4.1  MUST_CHANGE..." -ForegroundColor Cyan -NoNewline
try {
    $c4_1 = Get-DbaLogin -SqlInstance $SqlInstance -Type SQL -Detailed -WarningAction SilentlyContinue |
        Where-Object { $_.IsMustChange -eq $true } |
        Select-Object SqlInstance, Name, IsMustChange
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "4.1: $($_.Exception.Message)"
    $c4_1 = $null
}

# --- 4.2 CHECK_EXPIRATION for sysadmins ---
Write-Host "4.2  CHECK_EXPIRATION..." -ForegroundColor Cyan -NoNewline
try {
    $sysadminNames = (Get-DbaServerRoleMember -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.Role -eq 'sysadmin' }).Name

    $c4_2 = Get-DbaLogin -SqlInstance $SqlInstance -Type SQL -WarningAction SilentlyContinue |
        Where-Object { $_.Name -in $sysadminNames -and -not $_.PasswordExpirationEnabled } |
        Select-Object SqlInstance, Name, PasswordExpirationEnabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "4.2: $($_.Exception.Message)"
    $c4_2 = $null
}

# --- 4.3 CHECK_POLICY ---
Write-Host "4.3  CHECK_POLICY..." -ForegroundColor Cyan -NoNewline
try {
    $c4_3 = Get-DbaLogin -SqlInstance $SqlInstance -Type SQL -WarningAction SilentlyContinue |
        Where-Object { -not $_.PasswordPolicyEnforced } |
        Select-Object SqlInstance, Name, PasswordPolicyEnforced, IsDisabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "4.3: $($_.Exception.Message)"
    $c4_3 = $null
}

# --- 5.1 Error Log Count ---
Write-Host "5.1  Error Log Count..." -ForegroundColor Cyan -NoNewline
try {
    $c5_1 = Get-DbaErrorLogConfig -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, LogCount, LogSize
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "5.1: $($_.Exception.Message)"
    $c5_1 = $null
}

# --- 5.2 Default Trace ---
Write-Host "5.2  Default Trace..." -ForegroundColor Cyan -NoNewline
try {
    $c5_2 = Get-DbaSpConfigure -SqlInstance $SqlInstance -Name 'DefaultTraceEnabled' -WarningAction SilentlyContinue |
        Select-Object SqlInstance, DisplayName, ConfiguredValue, RunningValue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "5.2: $($_.Exception.Message)"
    $c5_2 = $null
}

# --- 5.3 Login Auditing ---
Write-Host "5.3  Login Auditing..." -ForegroundColor Cyan -NoNewline
try {
    $c5_3 = Invoke-DbaQuery @connParams -Query "EXEC xp_loginconfig 'audit level';" -WarningAction SilentlyContinue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "5.3: $($_.Exception.Message)"
    $c5_3 = $null
}

# --- 5.4 SQL Server Audit ---
Write-Host "5.4  SQL Server Audit..." -ForegroundColor Cyan -NoNewline
try {
    $c5_4_audits = Get-DbaInstanceAudit -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, Enabled, FilePath, QueueDelay
    $c5_4_specs = Get-DbaInstanceAuditSpecification -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Name, Enabled, AuditName
    # Combine into one dataset with a Type column
    $c5_4 = @()
    if ($c5_4_audits) {
        $c5_4 += $c5_4_audits | Select-Object SqlInstance, Name, Enabled, @{ Name = 'Type'; Expression = { 'Audit' } }, @{ Name = 'Detail'; Expression = { $_.FilePath } }
    }
    if ($c5_4_specs) {
        $c5_4 += $c5_4_specs | Select-Object SqlInstance, Name, Enabled, @{ Name = 'Type'; Expression = { 'Specification' } }, @{ Name = 'Detail'; Expression = { $_.AuditName } }
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "5.4: $($_.Exception.Message)"
    $c5_4 = $null
}

# --- 6.2 CLR Assembly Permission Sets ---
Write-Host "6.2  CLR Assemblies..." -ForegroundColor Cyan -NoNewline
try {
    $query6_2 = @"
SELECT @@SERVERNAME AS [ServerName], DB_NAME() AS [Database], 
    name, permission_set_desc
FROM sys.assemblies
WHERE is_user_defined = 1 AND name <> 'Microsoft.SqlServer.Types';
"@
    $c6_2 = foreach ($inst in $SqlInstance) {
        $dbs = Get-DbaDatabase -SqlInstance $inst -ExcludeSystem -WarningAction SilentlyContinue
        foreach ($db in $dbs) {
            Invoke-DbaQuery -SqlInstance $inst -Database $db.Name -Query $query6_2 -WarningAction SilentlyContinue
        }
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "6.2: $($_.Exception.Message)"
    $c6_2 = $null
}

# --- 7.1 Symmetric Key Encryption ---
Write-Host "7.1  Symmetric Keys..." -ForegroundColor Cyan -NoNewline
try {
    $query7_1 = @"
SELECT @@SERVERNAME AS [ServerName], DB_NAME() AS [Database], 
    name AS Key_Name, algorithm_desc
FROM sys.symmetric_keys
WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
    AND DB_ID() > 4;
"@
    $c7_1 = foreach ($inst in $SqlInstance) {
        $dbs = Get-DbaDatabase -SqlInstance $inst -ExcludeSystem -WarningAction SilentlyContinue
        foreach ($db in $dbs) {
            Invoke-DbaQuery -SqlInstance $inst -Database $db.Name -Query $query7_1 -WarningAction SilentlyContinue
        }
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "7.1: $($_.Exception.Message)"
    $c7_1 = $null
}

# --- 7.2 Asymmetric Key Size ---
Write-Host "7.2  Asymmetric Keys..." -ForegroundColor Cyan -NoNewline
try {
    $query7_2 = @"
SELECT @@SERVERNAME AS [ServerName], DB_NAME() AS [Database], 
    name AS Key_Name, key_length
FROM sys.asymmetric_keys
WHERE key_length < 2048
    AND DB_ID() > 4;
"@
    $c7_2 = foreach ($inst in $SqlInstance) {
        $dbs = Get-DbaDatabase -SqlInstance $inst -ExcludeSystem -WarningAction SilentlyContinue
        foreach ($db in $dbs) {
            Invoke-DbaQuery -SqlInstance $inst -Database $db.Name -Query $query7_2 -WarningAction SilentlyContinue
        }
    }
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "7.2: $($_.Exception.Message)"
    $c7_2 = $null
}

# --- 7.3 Backup Encryption ---
Write-Host "7.3  Backup Encryption..." -ForegroundColor Cyan -NoNewline
try {
    $query7_3 = @"
SELECT @@SERVERNAME AS [ServerName], b.database_name, b.backup_finish_date,
    b.key_algorithm, b.encryptor_type, d.is_encrypted
FROM msdb.dbo.backupset b
    INNER JOIN sys.databases d ON b.database_name = d.name
WHERE b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted = 0;
"@
    $c7_3 = Invoke-DbaQuery @connParams -Query $query7_3 -WarningAction SilentlyContinue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "7.3: $($_.Exception.Message)"
    $c7_3 = $null
}

# --- 7.4 Network Encryption ---
Write-Host "7.4  Network Encryption..." -ForegroundColor Cyan -NoNewline
try {
    $query7_4 = @"
SELECT DISTINCT @@SERVERNAME AS [ServerName], encrypt_option
FROM sys.dm_exec_connections c
WHERE net_transport <> 'Shared memory'
    AND c.endpoint_id NOT IN (
        SELECT endpoint_id FROM sys.database_mirroring_endpoints
        WHERE encryption_algorithm IS NOT NULL);
"@
    $c7_4 = Invoke-DbaQuery @connParams -Query $query7_4 -WarningAction SilentlyContinue
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "7.4: $($_.Exception.Message)"
    $c7_4 = $null
}

# --- 7.5 TDE ---
Write-Host "7.5  TDE..." -ForegroundColor Cyan -NoNewline
try {
    $c7_5 = Get-DbaDbEncryption -SqlInstance $SqlInstance -WarningAction SilentlyContinue |
        Select-Object SqlInstance, Database, EncryptionEnabled
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "7.5: $($_.Exception.Message)"
    $c7_5 = $null
}

# --- 8.1 Browser Service ---
Write-Host "8.1  Browser Service..." -ForegroundColor Cyan -NoNewline
try {
    $c8_1 = Get-DbaService -ComputerName $SqlInstance -WarningAction SilentlyContinue |
        Where-Object { $_.ServiceType -eq 'Browser' } |
        Select-Object ComputerName, ServiceName, State, StartMode
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "8.1: $($_.Exception.Message)"
    $c8_1 = $null
}

# ── Export to Excel ────────────────────────────────────────────
Write-Host "`nExporting to Excel..." -ForegroundColor Cyan

# Cover sheet
[PSCustomObject]@{
    'Benchmark'    = 'CIS Microsoft SQL Server 2022 Benchmark v1.2.1'
    'Server(s)'    = $SqlInstance -join ', '
    'Collected By' = "$env:USERDOMAIN\$env:USERNAME"
    'Run Date'     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    'Machine'      = $env:COMPUTERNAME
    'Errors'       = if ($errors.Count -eq 0) { 'None' } else { $errors -join '; ' }
} | Export-Excel -Path $outputFile -WorksheetName 'Cover' -AutoSize -TableName 'AuditInfo'

# Section tabs
Export-Tab -Data $c1_1      -TabName '1.1_PatchLevel'         -Path $outputFile
Export-Tab -Data $c2_config -TabName '2.x_Configuration'      -Path $outputFile
Export-Tab -Data $c2_9      -TabName '2.9_Trustworthy'        -Path $outputFile
Export-Tab -Data $c2_10     -TabName '2.10_Protocols'         -Path $outputFile
Export-Tab -Data $c2_11     -TabName '2.11_TCPPort'           -Path $outputFile
Export-Tab -Data $c2_12     -TabName '2.12_HideInstance'      -Path $outputFile
Export-Tab -Data $c2_13     -TabName '2.13_saDisabled'        -Path $outputFile
Export-Tab -Data $c2_14     -TabName '2.14_saRenamed'         -Path $outputFile
Export-Tab -Data $c2_15     -TabName '2.15_AutoClose'         -Path $outputFile
Export-Tab -Data $c2_16     -TabName '2.16_NoSaLogin'         -Path $outputFile
Export-Tab -Data $c3_1      -TabName '3.1_AuthMode'           -Path $outputFile
Export-Tab -Data $c3_2      -TabName '3.2_GuestConnect'       -Path $outputFile
Export-Tab -Data $c3_3      -TabName '3.3_OrphanedUsers'      -Path $outputFile
Export-Tab -Data $c3_4      -TabName '3.4_ContainedDBAuth'    -Path $outputFile
Export-Tab -Data $c3_5      -TabName '3.5_ServiceAccounts'    -Path $outputFile
Export-Tab -Data $c3_8      -TabName '3.8_PublicPerms'        -Path $outputFile
Export-Tab -Data $c3_9      -TabName '3.9_BuiltinGroups'      -Path $outputFile
Export-Tab -Data $c3_10     -TabName '3.10_LocalGroups'       -Path $outputFile
Export-Tab -Data $c3_11     -TabName '3.11_AgentProxies'      -Path $outputFile
Export-Tab -Data $c3_12     -TabName '3.12_Sysadmin'          -Path $outputFile
Export-Tab -Data $c3_13     -TabName '3.13_msdbRoles'         -Path $outputFile
Export-Tab -Data $c4_1      -TabName '4.1_MustChange'         -Path $outputFile
Export-Tab -Data $c4_2      -TabName '4.2_CheckExpiration'    -Path $outputFile
Export-Tab -Data $c4_3      -TabName '4.3_CheckPolicy'        -Path $outputFile
Export-Tab -Data $c5_1      -TabName '5.1_ErrorLogCount'      -Path $outputFile
Export-Tab -Data $c5_2      -TabName '5.2_DefaultTrace'       -Path $outputFile
Export-Tab -Data $c5_3      -TabName '5.3_LoginAuditing'      -Path $outputFile
Export-Tab -Data $c5_4      -TabName '5.4_SQLServerAudit'     -Path $outputFile
Export-Tab -Data $c6_2      -TabName '6.2_CLRAssemblies'      -Path $outputFile
Export-Tab -Data $c7_1      -TabName '7.1_SymmetricKeys'      -Path $outputFile
Export-Tab -Data $c7_2      -TabName '7.2_AsymmetricKeys'     -Path $outputFile
Export-Tab -Data $c7_3      -TabName '7.3_BackupEncryption'   -Path $outputFile
Export-Tab -Data $c7_4      -TabName '7.4_NetworkEncryption'  -Path $outputFile
Export-Tab -Data $c7_5      -TabName '7.5_TDE'                -Path $outputFile
Export-Tab -Data $c8_1      -TabName '8.1_BrowserService'     -Path $outputFile

# ── Summary ────────────────────────────────────────────────────
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "CIS Audit Collection Complete"     -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Benchmark:  CIS SQL Server 2022 v1.2.1"
Write-Host "Server(s):  $($SqlInstance -join ', ')"
Write-Host "Output:     $outputFile"

if ($errors.Count -gt 0) {
    Write-Host "Errors:     $($errors.Count)" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "Errors:     None" -ForegroundColor Green
}

Write-Host ""