function Get-AgentOperators {
    param ([hashtable]$ctx)
    $all     = @(Get-DbaAgentOperator @ctx -WarningAction SilentlyContinue)
    $enabled = @($all | Where-Object { $_.Enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($_.EmailAddress) })
    [PSCustomObject]@{ All = $all; EnabledWithEmail = $enabled; Count = $enabled.Count }
}

function Get-AgentJobOwners {
    param ([hashtable]$ctx)
    $jobs      = @(Get-DbaAgentJob @ctx -WarningAction SilentlyContinue)
    $ownerless = @($jobs | Where-Object { [string]::IsNullOrWhiteSpace($_.OwnerLoginName) })
    [PSCustomObject]@{ Jobs = $jobs; Ownerless = $ownerless; OwnerlessCount = $ownerless.Count }
}

function Get-SqlAlerts {
    param ([hashtable]$ctx)
    $all       = @(Get-DbaAgentAlert @ctx -WarningAction SilentlyContinue)
    $enabled   = @($all | Where-Object { $_.IsEnabled })
    $sevAlerts = @($enabled | Where-Object { $_.Severity -ge 19 -and $_.Severity -le 25 })
    $ioAlerts  = @($enabled | Where-Object { $_.MessageId -in 823, 824, 825 })
    [PSCustomObject]@{
        All        = $all
        Enabled    = $enabled
        SevAlerts  = $sevAlerts
        IoAlerts   = $ioAlerts
    }
}

function Get-DatabaseMail {
    param ([hashtable]$ctx)
    $profiles = @(Get-DbaDbMailProfile @ctx -WarningAction SilentlyContinue)
    [PSCustomObject]@{ Profiles = $profiles; Count = $profiles.Count }
}
