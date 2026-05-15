function New-DakCheckResult {
    [CmdletBinding()]
    param (
        [string]$ComputerName,
        [string]$SqlInstance,
        [ValidateSet("CIS", "SOX", "STIG", "PCI", "SOC2", "DbConfig")]
        [string]$Framework,
        [string]$CheckId,
        [string]$CheckName,
        [string]$Category,
        # Automated = tool determines pass/fail.
        # Manual    = tool collects evidence; human must make the compliance determination.
        [ValidateSet("Automated", "Manual")]
        [string]$AssessmentType = "Automated",
        [ValidateSet("Pass", "Fail", "Warning", "Manual", "Data", "Skip", "Error")]
        [string]$Status,
        # Priority reflects how critical the finding is if the check fails.
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Priority      = "Low",
        [string]$CurrentValue  = $null,
        [string]$ExpectedValue = $null,
        [string]$Remediation   = $null,
        [string]$Reference     = $null,
        [string]$SqlQuery      = $null,
        [datetime]$RunDate,
        [string]$RunBy
    )

    $ErrorActionPreference = "Stop"

    $obj = [PSCustomObject][ordered]@{
        RunDate        = $RunDate
        RunBy          = $RunBy
        ComputerName   = $ComputerName
        SqlInstance    = $SqlInstance
        Framework      = $Framework
        CheckId        = $CheckId
        CheckName      = $CheckName
        Category       = $Category
        AssessmentType = $AssessmentType
        Status         = $Status
        Priority       = $Priority
        # Pass = $true, Fail/Warning/Error = $false, Manual/Data/Skip = $null
        Compliant      = if ($Status -eq "Pass") { $true }
                         elseif ($Status -in "Fail", "Warning", "Error") { $false }
                         else { $null }
        CurrentValue   = $CurrentValue
        ExpectedValue  = $ExpectedValue
        Remediation    = if ($Status -in "Fail", "Warning", "Manual") { $Remediation } else { $null }
        Reference      = $Reference
        SqlQuery       = $SqlQuery
    }

    $obj.PSObject.TypeNames.Insert(0, "DakSqlKit.AuditResult")

    $defaultProps = [string[]]("Framework", "CheckId", "CheckName", "SqlInstance", "AssessmentType", "Priority", "Status", "CurrentValue")
    $psDps = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", $defaultProps)
    $splatMember = @{
        MemberType = "MemberSet"
        Name       = "PSStandardMembers"
        Value      = [System.Management.Automation.PSMemberInfo[]]@($psDps)
        Force      = $true
    }
    $obj | Add-Member @splatMember

    $obj
}
