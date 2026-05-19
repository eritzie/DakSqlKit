function Get-TdeStatus {
    param ([hashtable]$ctx)
    $allDbs = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    $enc    = @($allDbs | Where-Object { $_.EncryptionEnabled })
    $unenc  = @($allDbs | Where-Object { -not $_.EncryptionEnabled })
    [PSCustomObject]@{
        TotalCount       = $allDbs.Count
        EncryptedCount   = $enc.Count
        UnencryptedCount = $unenc.Count
        EncryptedNames   = @($enc   | Select-Object -ExpandProperty Name)
        UnencryptedNames = @($unenc | Select-Object -ExpandProperty Name)
    }
}

function Get-SymmetricKeys {
    param ([hashtable]$ctx)
    $q       = "SELECT COUNT(*) AS WeakKeys FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256');"
    $userDbs = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    $weak    = 0
    foreach ($db in $userDbs) {
        $r = Invoke-DbaQuery @ctx -Database $db.Name -Query $q -WarningAction SilentlyContinue
        if ($r) { $weak += $r.WeakKeys }
    }
    [PSCustomObject]@{ WeakCount = $weak; Query = $q }
}

function Get-AsymmetricKeys {
    param ([hashtable]$ctx)
    $q       = "SELECT COUNT(*) AS ShortKeys FROM sys.asymmetric_keys WHERE key_length < 2048;"
    $userDbs = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    $short   = 0
    foreach ($db in $userDbs) {
        $r = Invoke-DbaQuery @ctx -Database $db.Name -Query $q -WarningAction SilentlyContinue
        if ($r) { $short += $r.ShortKeys }
    }
    [PSCustomObject]@{ ShortCount = $short; Query = $q }
}

function Get-ClrAssemblies {
    param ([hashtable]$ctx)
    $q       = "SELECT name FROM sys.assemblies WHERE permission_set_desc = 'UNSAFE_ACCESS' AND is_user_defined = 1;"
    $userDbs = @(Get-DbaDatabase @ctx -ExcludeSystem -WarningAction SilentlyContinue)
    $names   = @()
    foreach ($db in $userDbs) {
        $r = Invoke-DbaQuery @ctx -Database $db.Name -Query $q -WarningAction SilentlyContinue
        if ($r) { $names += @($r | ForEach-Object { "$($db.Name).$($_.name)" }) }
    }
    [PSCustomObject]@{ UnsafeCount = $names.Count; Names = $names; Query = $q }
}
