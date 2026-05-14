<#
    Collect-SOXAudit-dbatools.ps1
    Purpose: Collect all SOX audit data using dbatools cmdlets and export 
             to a single dated Excel workbook.
    
    Dependencies: 
        - dbatools      (Install-Module dbatools)
        - ImportExcel   (Install-Module ImportExcel)
    
    Usage:
        # Basic — outputs to current directory
        .\Collect-SOXAudit-dbatools.ps1 -SqlInstance "SQLPROD01"

        # Specify output folder
        .\Collect-SOXAudit-dbatools.ps1 -SqlInstance "SQLPROD01" -OutputPath "C:\Audit"

        # Multiple instances
        .\Collect-SOXAudit-dbatools.ps1 -SqlInstance "SQLPROD01","SQLPROD02"

        # With SQL authentication
        .\Collect-SOXAudit-dbatools.ps1 -SqlInstance "SQLPROD01" -SqlCredential (Get-Credential)

    Output:
        SOX_Audit_dbatools_SERVERNAME_2026-03-25.xlsx
        Worksheets: Cover, SQL_Logins, Server_Logins, Server_Roles, 
                    Database_Roles, Blank_Passwords, Auth_Mode, 
                    Server_Configuration, Backup_History, Backup_Job_Schedules,
                    Agent_Job_Access

    Notes:
        - This is the dbatools-native alternative to Collect-SOXAudit.ps1,
          which runs .sql files via Invoke-DbaQuery.
        - Both produce equivalent audit data; this version is better for 
          multi-instance sweeps and doesn't require the .sql files.
        - Backup job schedules assume Ola Hallengren's Maintenance Solution
          naming convention (DatabaseBackup*). Adjust the filter if using 
          a different backup solution.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]$SqlInstance,

    [Parameter()]
    [string]$OutputPath = ".",

    [Parameter()]
    [int]$BackupDaysBack = 30,

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
$fileName    = "SOX_Audit_dbatools_${serverClean}_${datestamp}.xlsx"
$outputFile  = Join-Path $OutputPath $fileName

if (Test-Path $outputFile) { Remove-Item $outputFile -Force }

# ── Shared connection params ──────────────────────────────────
$connParams = @{ SqlInstance = $SqlInstance }
if ($SqlCredential) { $connParams.SqlCredential = $SqlCredential }

# ── Collection ─────────────────────────────────────────────────
$errors = @()
$tabCount = 0

# --- 1. SQL Logins ---
Write-Host "Collecting: SQL Logins..." -ForegroundColor Cyan -NoNewline
try {
    $sqlLogins = Get-DbaLogin @connParams | 
        Where-Object { $_.LoginType -eq 'SqlLogin' -and $_.Name -notlike '##*' } |
        Select-Object @(
            'ComputerName', 'SqlInstance', 'Name'
            @{ Name = 'Disabled';                   Expression = { if ($_.IsDisabled) { 'Yes' } else { 'No' } } }
            'DefaultDatabase', 'CreateDate', 'DateLastModified'
            @{ Name = 'PasswordPolicyEnforced';     Expression = { if ($_.PasswordPolicyEnforced)    { 'Yes' } else { 'No' } } }
            @{ Name = 'PasswordExpirationEnabled';  Expression = { if ($_.PasswordExpirationEnabled) { 'Yes' } else { 'No' } } }
        )
    Write-Host " $($sqlLogins.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "SQL_Logins: $($_.Exception.Message)"
    $sqlLogins = $null
}

# --- 2. Server Logins (all types) ---
Write-Host "Collecting: Server Logins..." -ForegroundColor Cyan -NoNewline
try {
    $serverLogins = Get-DbaLogin @connParams | 
        Where-Object { $_.Name -notlike '##*' -and $_.Name -notlike 'NT SERVICE\*' } |
        Select-Object @(
            'ComputerName', 'SqlInstance', 'Name'
            @{ Name = 'LoginType';  Expression = { $_.LoginType.ToString() } }
            'DefaultDatabase'
            @{ Name = 'Disabled';   Expression = { if ($_.IsDisabled) { 'Yes' } else { 'No' } } }
            @{ Name = 'HasAccess';  Expression = { if ($_.HasAccess)  { 'Yes' } else { 'No' } } }
            'CreateDate', 'DateLastModified'
            @{ Name = 'PasswordPolicyEnforced';    Expression = { 
                if ($_.LoginType -eq 'SqlLogin') { if ($_.PasswordPolicyEnforced)    { 'Yes' } else { 'No' } } else { 'N/A' } 
            }}
            @{ Name = 'PasswordExpirationEnabled'; Expression = { 
                if ($_.LoginType -eq 'SqlLogin') { if ($_.PasswordExpirationEnabled) { 'Yes' } else { 'No' } } else { 'N/A' } 
            }}
        )
    Write-Host " $($serverLogins.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Server_Logins: $($_.Exception.Message)"
    $serverLogins = $null
}

# --- 3. Server Role Memberships ---
Write-Host "Collecting: Server Roles..." -ForegroundColor Cyan -NoNewline
try {
    $serverRoles = Get-DbaServerRoleMember -SqlInstance $SqlInstance |
        Where-Object { $_.Name -notlike '##*' -and $_.Name -notlike 'NT SERVICE\*' } |
        Select-Object 'SqlInstance', @{ Name = 'LoginName'; Expression = { $_.Name } }, 'Role'
    Write-Host " $($serverRoles.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Server_Roles: $($_.Exception.Message)"
    $serverRoles = $null
}

# --- 4. Database Roles ---
Write-Host "Collecting: Database Roles..." -ForegroundColor Cyan -NoNewline
try {
    $databaseRoles = Get-DbaDbRoleMember @connParams |
        Where-Object { $_.UserName -notlike '##*' -and $_.UserName -notin @('dbo','guest','INFORMATION_SCHEMA','sys') } |
        Select-Object 'SqlInstance', @{ Name = 'Database'; Expression = { $_.Database } }, 
            @{ Name = 'PrincipalName'; Expression = { $_.UserName } }, 'Role'
    Write-Host " $($databaseRoles.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Database_Roles: $($_.Exception.Message)"
    $databaseRoles = $null
}

# --- 5. Blank Passwords ---
Write-Host "Collecting: Blank Passwords..." -ForegroundColor Cyan -NoNewline
try {
    $blankPwQuery = @"
        SELECT @@SERVERNAME AS [ServerName], [name] AS [LoginName], [type_desc] AS [LoginType],
               [is_disabled], [is_policy_checked], [create_date], [modify_date]
        FROM sys.sql_logins
        WHERE PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE('', password_hash, 1) = 1
"@
    $blankPasswords = Invoke-DbaQuery @connParams -Query $blankPwQuery -EnableException
    $count = if ($blankPasswords) { @($blankPasswords).Count } else { 0 }
    Write-Host " $count rows" -ForegroundColor $(if ($count -eq 0) { 'Green' } else { 'Red' })
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Blank_Passwords: $($_.Exception.Message)"
    $blankPasswords = $null
}

# --- 6. Auth Mode ---
Write-Host "Collecting: Auth Mode..." -ForegroundColor Cyan -NoNewline
try {
    $authModeQuery = @"
        SELECT @@SERVERNAME AS [ServerName],
               CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                   WHEN 1 THEN 'Windows Authentication'
                   WHEN 0 THEN 'Windows and SQL Server Authentication'
               END AS [AuthenticationMode]
"@
    $authMode = Invoke-DbaQuery @connParams -Query $authModeQuery -EnableException
    Write-Host " Done" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Auth_Mode: $($_.Exception.Message)"
    $authMode = $null
}

# --- 7. Server Configuration ---
Write-Host "Collecting: Server Configuration..." -ForegroundColor Cyan -NoNewline
try {
    $serverConfig = Get-DbaSpConfigure @connParams |
        Select-Object @(
            'SqlInstance'
            @{ Name = 'Setting';         Expression = { $_.DisplayName } }
            @{ Name = 'ConfiguredValue'; Expression = { $_.ConfiguredValue } }
            @{ Name = 'RunningValue';    Expression = { $_.RunningValue } }
            'DefaultValue', 'MinValue', 'MaxValue'
            @{ Name = 'PendingRestart';  Expression = { if ($_.ConfiguredValue -ne $_.RunningValue) { 'Yes' } else { 'No' } } }
            'Description'
        )
    Write-Host " $($serverConfig.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Server_Configuration: $($_.Exception.Message)"
    $serverConfig = $null
}

# --- 8. Backup History ---
Write-Host "Collecting: Backup History..." -ForegroundColor Cyan -NoNewline
try {
    $backupHistory = Get-DbaDbBackupHistory @connParams -Last |
        Select-Object @(
            'SqlInstance'
            @{ Name = 'Database';        Expression = { $_.Database } }
            'Type'
            @{ Name = 'BackupStart';     Expression = { $_.Start } }
            @{ Name = 'BackupFinish';    Expression = { $_.End } }
            @{ Name = 'DurationSeconds'; Expression = { if ($_.Start -and $_.End) { ($_.End - $_.Start).TotalSeconds } } }
            @{ Name = 'BackupSizeMB';    Expression = { [math]::Round($_.TotalSize.Megabyte, 2) } }
            @{ Name = 'CompressedMB';    Expression = { [math]::Round($_.CompressedBackupSize.Megabyte, 2) } }
            'Path'
        )
    Write-Host " $($backupHistory.Count) rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Backup_History: $($_.Exception.Message)"
    $backupHistory = $null
}

# --- 9. Backup Job Schedules (Ola Hallengren) ---
Write-Host "Collecting: Backup Job Schedules..." -ForegroundColor Cyan -NoNewline
try {
    $backupJobs = Get-DbaAgentJob @connParams |
        Where-Object { $_.Name -like 'DatabaseBackup*' } |
        Select-Object @(
            'SqlInstance'
            @{ Name = 'JobName';      Expression = { $_.Name } }
            @{ Name = 'Enabled';      Expression = { if ($_.IsEnabled) { 'Yes' } else { 'No' } } }
            'LastRunDate'
            @{ Name = 'LastRunResult'; Expression = { $_.LastRunOutcome.ToString() } }
            'NextRunDate'
        )
    $count = if ($backupJobs) { @($backupJobs).Count } else { 0 }
    Write-Host " $count rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Backup_Job_Schedules: $($_.Exception.Message)"
    $backupJobs = $null
}

# --- 10. Agent Job Access ---
Write-Host "Collecting: Agent Job Access..." -ForegroundColor Cyan -NoNewline
try {
    $agentAccessQuery = @"
        SELECT @@SERVERNAME AS [ServerName], 'Database' AS [Level], 'msdb' AS [Database],
               dp.[name] AS [PrincipalName], dp.[type_desc] AS [PrincipalType], r.[name] AS [Role]
        FROM msdb.sys.database_principals dp
        INNER JOIN msdb.sys.database_role_members drm ON dp.[principal_id] = drm.[member_principal_id]
        INNER JOIN msdb.sys.database_principals r ON drm.[role_principal_id] = r.[principal_id]
        WHERE r.[name] IN ('SQLAgentOperatorRole', 'SQLAgentReaderRole', 'SQLAgentUserRole')
          AND dp.[name] NOT LIKE '##[%]'
        UNION ALL
        SELECT @@SERVERNAME, 'Server', sp.[default_database_name],
               sp.[name], sp.[type_desc], 'sysadmin'
        FROM master.sys.server_principals sp
        INNER JOIN master..syslogins sl ON sp.[sid] = sl.[sid]
        WHERE sl.[sysadmin] = 1 AND sp.[name] NOT LIKE '##[%]' AND sp.[name] NOT LIKE 'NT SERVICE\%'
        ORDER BY [Role], [PrincipalName]
"@
    $agentAccess = Invoke-DbaQuery @connParams -Query $agentAccessQuery -EnableException
    $count = if ($agentAccess) { @($agentAccess).Count } else { 0 }
    Write-Host " $count rows" -ForegroundColor Green
} catch {
    Write-Host " ERROR" -ForegroundColor Red
    $errors += "Agent_Job_Access: $($_.Exception.Message)"
    $agentAccess = $null
}

# ── Export to Excel ────────────────────────────────────────────
Write-Host "`nExporting to Excel..." -ForegroundColor Cyan

# Helper function to export a tab
function Export-Tab {
    param ($Data, $TabName, $Path)
    if ($null -ne $Data -and @($Data).Count -gt 0) {
        $Data | Export-Excel -Path $Path -WorksheetName $TabName -AutoSize -TableName $TabName -Append
    } else {
        [PSCustomObject]@{ Result = 'No rows returned' } | 
            Export-Excel -Path $Path -WorksheetName $TabName -AutoSize -Append
    }
}

# Cover sheet
[PSCustomObject]@{
    'Server(s)'    = $SqlInstance -join ', '
    'Collected By' = "$env:USERDOMAIN\$env:USERNAME"
    'Run Date'     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    'Machine'      = $env:COMPUTERNAME
    'Method'       = 'dbatools'
    'Errors'       = if ($errors.Count -eq 0) { 'None' } else { $errors -join '; ' }
} | Export-Excel -Path $outputFile -WorksheetName 'Cover' -AutoSize -TableName 'AuditInfo'

# Data tabs
Export-Tab -Data $sqlLogins      -TabName 'SQL_Logins'            -Path $outputFile
Export-Tab -Data $serverLogins   -TabName 'Server_Logins'         -Path $outputFile
Export-Tab -Data $serverRoles    -TabName 'Server_Roles'          -Path $outputFile
Export-Tab -Data $databaseRoles  -TabName 'Database_Roles'        -Path $outputFile
Export-Tab -Data $blankPasswords -TabName 'Blank_Passwords'       -Path $outputFile
Export-Tab -Data $authMode       -TabName 'Auth_Mode'             -Path $outputFile
Export-Tab -Data $serverConfig   -TabName 'Server_Configuration'  -Path $outputFile
Export-Tab -Data $backupHistory  -TabName 'Backup_History'        -Path $outputFile
Export-Tab -Data $backupJobs     -TabName 'Backup_Job_Schedules'  -Path $outputFile
Export-Tab -Data $agentAccess    -TabName 'Agent_Job_Access'      -Path $outputFile

# ── Summary ────────────────────────────────────────────────────
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "SOX Audit Collection Complete"     -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Server(s):  $($SqlInstance -join ', ')"
Write-Host "Method:     dbatools"
Write-Host "Output:     $outputFile"

if ($errors.Count -gt 0) {
    Write-Host "Errors:     $($errors.Count)" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "Errors:     None" -ForegroundColor Green
}

Write-Host ""