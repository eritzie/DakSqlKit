function Get-SurfaceAreaConfig {
    param ([hashtable]$ctx)
    $names = @(
        'xp_cmdshell',
        'Ole Automation Procedures',
        'Ad Hoc Distributed Queries',
        'clr enabled',
        'clr strict security'
    )
    $map = @{}
    foreach ($n in $names) {
        $map[$n] = Get-DbaSpConfigure @ctx -Name $n -WarningAction SilentlyContinue | Select-Object -First 1
    }
    [PSCustomObject]@{
        XpCmdshell        = $map['xp_cmdshell']
        OleAutomation     = $map['Ole Automation Procedures']
        AdHocDistributed  = $map['Ad Hoc Distributed Queries']
        ClrEnabled        = $map['clr enabled']
        ClrStrictSecurity = $map['clr strict security']
    }
}

function Get-NetworkConfig {
    param ([hashtable]$ctx)
    $tcpPort = Get-DbaTcpPort @ctx -WarningAction SilentlyContinue | Select-Object -First 1
    $hideQ   = @"
SELECT CAST(value_data AS INT) AS HideInstance
FROM sys.dm_server_registry
WHERE registry_key LIKE N'%SuperSocketNetLib%'
  AND value_name = N'HideInstance';
"@
    $hideResult = Invoke-DbaQuery @ctx -Query $hideQ -WarningAction SilentlyContinue
    [PSCustomObject]@{
        TcpPort   = if ($tcpPort) { $tcpPort.Port } else { -1 }
        Hidden    = ($hideResult -and @($hideResult)[0].HideInstance -eq 1)
        HideQuery = $hideQ
    }
}

function Get-NetworkEncryption {
    param ([hashtable]$ctx)
    $q = @"
SELECT DISTINCT encrypt_option
FROM sys.dm_exec_connections c
WHERE net_transport <> 'Shared memory'
  AND c.endpoint_id NOT IN (
      SELECT endpoint_id FROM sys.database_mirroring_endpoints
      WHERE encryption_algorithm IS NOT NULL
  );
"@
    $rows  = Invoke-DbaQuery @ctx -Query $q -WarningAction SilentlyContinue
    $unenc = if ($rows) { @($rows | Where-Object { $_.encrypt_option -ne 'TRUE' }).Count } else { 0 }
    [PSCustomObject]@{ UnencryptedCount = $unenc; Query = $q }
}

function Get-MaxMemory {
    param ([hashtable]$ctx)
    $cfg = Get-DbaMaxMemory @ctx -WarningAction SilentlyContinue | Select-Object -First 1
    [PSCustomObject]@{ Config = $cfg }
}

function Get-DatabaseConfig {
    param ([hashtable]$ctx)
    $dbs = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    [PSCustomObject]@{
        Databases        = $dbs
        Count            = $dbs.Count
        SimpleRecovery   = @($dbs | Where-Object { $_.RecoveryModel -eq 'Simple' })
        FullBulkRecovery = @($dbs | Where-Object { $_.RecoveryModel -in 'Full', 'BulkLogged' })
        NoChecksum       = @($dbs | Where-Object { $_.PageVerify -ne 'Checksum' })
        AutoClose        = @($dbs | Where-Object { $_.AutoClose -eq $true })
        AutoShrink       = @($dbs | Where-Object { $_.AutoShrink -eq $true })
    }
}

function Get-SqlServices {
    param ([hashtable]$ctx)
    $computer = ($ctx.SqlInstance -split '\\')[0].Split(',')[0]
    $browser  = Get-DbaService -ComputerName $computer -Type Browser -WarningAction SilentlyContinue |
        Select-Object -First 1
    [PSCustomObject]@{ Browser = $browser; ComputerName = $computer }
}
