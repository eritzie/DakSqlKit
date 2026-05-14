@{
    ModuleVersion     = '1.0.0'
    GUID              = 'c4f7e2a1-8b3d-4e9f-a6c0-2d5f8b1e3a70'
    Author            = 'Eric Ritzie'
    CompanyName       = 'Personal'
    Copyright         = '(c) 2026 Eric Ritzie. MIT License.'
    Description       = 'SQL Server security audit toolkit covering CIS, SOX, STIG, PCI-DSS, and SOC 2. Built on dbatools conventions — pipeline-friendly objects with Pass/Fail/Warning status and remediation guidance.'
    PowerShellVersion = '5.1'
    RootModule        = 'DbAuditKit.psm1'
    FunctionsToExport = @(
        'Invoke-DakAuditSuite',
        'Test-DakCISBenchmark'
    )
    PrivateData       = @{
        PSData = @{
            Tags       = @('SQL', 'SQLServer', 'Security', 'CIS', 'SOX', 'STIG', 'PCI', 'SOC2', 'dbatools', 'Audit', 'Compliance')
            ProjectUri = 'https://github.com/ericritzie/DbAuditKit'
            LicenseUri = 'https://github.com/ericritzie/DbAuditKit/blob/main/LICENSE'
        }
    }
}
