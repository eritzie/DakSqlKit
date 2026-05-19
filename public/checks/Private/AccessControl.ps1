function Get-SaLogin {
    param ([hashtable]$ctx)
    $login = Get-DbaLogin @ctx -WarningAction SilentlyContinue |
        Where-Object { $_.Sid.Length -eq 1 -and $_.Sid[0] -eq 1 } |
        Select-Object -First 1
    [PSCustomObject]@{ Login = $login }
}

function Get-AuthMode {
    param ([hashtable]$ctx)
    $prop = Get-DbaInstanceProperty @ctx -InstanceProperty LoginMode -WarningAction SilentlyContinue |
        Select-Object -First 1
    [PSCustomObject]@{ LoginMode = if ($prop) { $prop.Value } else { $null } }
}

function Get-BuiltinGroups {
    param ([hashtable]$ctx)
    $groups = @(Get-DbaLogin @ctx -WarningAction SilentlyContinue |
        Where-Object { $_.Name -like 'BUILTIN\*' })
    [PSCustomObject]@{
        Groups = $groups
        Names  = @($groups | Select-Object -ExpandProperty Name)
        Count  = $groups.Count
    }
}

function Get-GuestAccess {
    param ([hashtable]$ctx)
    $dbs = @(Get-DbaDbUser @ctx -ExcludeDatabase master, msdb, tempdb -User 'guest' -WarningAction SilentlyContinue |
        Where-Object { $_.HasDbAccess -eq $true })
    [PSCustomObject]@{
        Databases      = $dbs
        DatabaseNames  = @($dbs | Select-Object -ExpandProperty Database)
        Count          = $dbs.Count
    }
}

function Get-PublicRolePerms {
    param ([hashtable]$ctx)
    $q = @"
SELECT COUNT(*) AS Count
FROM sys.server_permissions
WHERE grantee_principal_id = 2
  AND state IN ('G','W')
  AND type NOT IN (
      'CO',
      'VASM'
  );
"@
    $r = Invoke-DbaQuery @ctx -Query $q -WarningAction SilentlyContinue
    [PSCustomObject]@{ Count = if ($r) { $r.Count } else { 0 }; Query = $q }
}

function Get-SqlAuthLogins {
    param ([hashtable]$ctx)
    $logins = @(Get-DbaLogin @ctx -Type SQL -WarningAction SilentlyContinue |
        Where-Object { $_.Name -notlike '##MS_%' })
    [PSCustomObject]@{
        Logins = $logins
        Names  = @($logins | Select-Object -ExpandProperty Name)
        Count  = $logins.Count
    }
}

function Get-SysadminLogins {
    param ([hashtable]$ctx)
    $members = @(Get-DbaServerRoleMember @ctx -ServerRole sysadmin -WarningAction SilentlyContinue |
        Where-Object { $_.Name -notlike '##*' })
    [PSCustomObject]@{
        Members = $members
        Names   = @($members | Select-Object -ExpandProperty Name)
        Count   = $members.Count
    }
}

function Get-OrphanedUsers {
    param ([hashtable]$ctx)
    $orphans = @(Get-DbaDbOrphanUser @ctx -WarningAction SilentlyContinue)
    [PSCustomObject]@{ Orphans = $orphans; Count = $orphans.Count }
}

function Get-DatabaseUsers {
    param ([hashtable]$ctx)
    $exclDbs = @('master', 'msdb', 'model', 'tempdb')
    $users   = @(Get-DbaDbUser @ctx -ExcludeDatabase $exclDbs -ExcludeSystemUser -WarningAction SilentlyContinue)
    [PSCustomObject]@{ Users = $users; ExcludedDbs = $exclDbs; Count = $users.Count }
}

function Get-DbOwnerMembers {
    param ([hashtable]$ctx)
    $exclDbs = @('master', 'msdb', 'model', 'tempdb')
    $members = @(Get-DbaDbRoleMember @ctx -Role 'db_owner' -WarningAction SilentlyContinue |
        Where-Object { $_.Database -notin $exclDbs })
    [PSCustomObject]@{ Members = $members; ExcludedDbs = $exclDbs; Count = $members.Count }
}

function Get-NewPrincipals {
    param ([hashtable]$ctx)
    $q = @"
SELECT name, create_date, type_desc
FROM sys.server_principals
WHERE type IN ('S','U','G')
  AND create_date >= DATEADD(DAY,-90,GETDATE())
  AND name NOT LIKE '##%'
ORDER BY create_date DESC;
"@
    $rows = @(Invoke-DbaQuery @ctx -Query $q -WarningAction SilentlyContinue)
    [PSCustomObject]@{ Principals = $rows; Count = $rows.Count; Query = $q }
}
