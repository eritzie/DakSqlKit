function Get-BackupHistory {
    param ([hashtable]$ctx)
    $history = @(Get-DbaDbBackupHistory @ctx -Type Full -WarningAction SilentlyContinue)
    [PSCustomObject]@{ History = $history; Count = $history.Count }
}

function Get-CheckDbHistory {
    param ([hashtable]$ctx)
    $history = @(Get-DbaLastGoodCheckDb @ctx -ExcludeDatabase tempdb -WarningAction SilentlyContinue)
    $stale   = @($history | Where-Object {
        $null -eq $_.LastGoodCheckDb -or $_.LastGoodCheckDb -lt (Get-Date).AddDays(-7)
    })
    [PSCustomObject]@{ History = $history; Stale = $stale; StaleCount = $stale.Count }
}

function Get-DatabaseStatus {
    param ([hashtable]$ctx)
    $dbs      = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    $problem  = @($dbs | Where-Object { -not $_.IsAccessible })
    [PSCustomObject]@{
        Databases    = $dbs
        Inaccessible = $problem
        Count        = $dbs.Count
    }
}
