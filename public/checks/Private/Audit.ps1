function Get-SqlAudits {
    param ([hashtable]$ctx)
    $specQ = @"
SELECT SAD.audit_action_name, SAD.audit_action_id,
       S.is_state_enabled AS AuditEnabled, SA.is_state_enabled AS SpecEnabled
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid;
"@
    $failQ = @"
SELECT name, on_failure_desc
FROM sys.server_audits
WHERE is_state_enabled = 1 AND on_failure_desc = 'CONTINUE';
"@
    $rows    = @(Invoke-DbaQuery @ctx -Query $specQ -WarningAction SilentlyContinue)
    $enabled = @($rows | Where-Object { $_.AuditEnabled -and $_.SpecEnabled })
    $fail    = @(Invoke-DbaQuery @ctx -Query $failQ  -WarningAction SilentlyContinue)
    [PSCustomObject]@{
        Rows           = $rows
        EnabledRows    = $enabled
        ActionNames    = @($enabled | Select-Object -ExpandProperty audit_action_name -Unique)
        ContinueAudits = $fail
        SpecQuery      = $specQ
    }
}

function Get-LoginAuditLevel {
    param ([hashtable]$ctx)
    $rows  = Invoke-DbaQuery @ctx -Query "EXEC xp_loginconfig 'audit level';" -WarningAction SilentlyContinue
    $raw   = if ($rows -and $rows[0]) { $rows[0].config_value } else { $null }
    $level = if ($null -ne $raw) { $raw.Trim() } else { 'none' }
    [PSCustomObject]@{ Level = $level }
}

function Get-DefaultTrace {
    param ([hashtable]$ctx)
    $cfg = Get-DbaSpConfigure @ctx -Name 'DefaultTraceEnabled' -WarningAction SilentlyContinue |
        Select-Object -First 1
    [PSCustomObject]@{
        Config  = $cfg
        Enabled = if ($cfg) { $cfg.RunningValue -eq 1 } else { $null }
    }
}

function Get-ErrorLogRetention {
    param ([hashtable]$ctx)
    $cfg      = Get-DbaErrorLogConfig @ctx -WarningAction SilentlyContinue | Select-Object -First 1
    $rawCount = if ($cfg) { $cfg.LogCount } else { -1 }
    $count    = if ($rawCount -lt 0) { 6 } else { $rawCount }
    $display  = if ($rawCount -lt 0) { "default (6) — registry key absent" } else { $count.ToString() }
    [PSCustomObject]@{ Count = $count; Display = $display; RawCount = $rawCount }
}
