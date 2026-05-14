# SQL-Server-Security-Audit

SQL Server security audit toolkit covering CIS, SOX, STIG, PCI-DSS, and SOC 2. Built on dbatools conventions — pipeline-friendly objects with Pass/Fail/Warning/Manual status and remediation guidance on every finding.

## DakAuditKit Module

### Install

```powershell
# Required
Install-Module dbatools

# Optional — needed for Excel export
Install-Module ImportExcel

# Word export requires Microsoft Word (uses built-in COM automation — no extra module needed)

# Import from repo
Import-Module .\DakAuditKit\DakAuditKit.psd1
```

### Quick start

```powershell
# Run CIS checks — results to terminal + JSON (default)
Test-DakCISBenchmark -SqlInstance SQLPROD01

# Failures and manual checks only
Test-DakCISBenchmark -SqlInstance SQLPROD01 -FailedOnly

# All frameworks via orchestrator (CIS implemented; others warn and skip)
Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS -OutputFormat Excel, HTML -OutputPath C:\Audit

# Pipe from registered servers
Get-DbaRegisteredServer | Test-DakCISBenchmark -FailedOnly | Format-Table -AutoSize

# Persist results for trend tracking
Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS -Repository SQLAUDIT01
```

---

## Module Structure

```
DakAuditKit/
├── DakAuditKit.psd1
├── DakAuditKit.psm1
├── public/
│   ├── core/
│   │   └── Invoke-DakAuditSuite.ps1        # Orchestrator
│   ├── checks/
│   │   ├── Test-DakCISBenchmark.ps1         # Full — CIS 2025 v1.0.0 (48 checks)
│   │   ├── Test-DakSOXCompliance.ps1        # Pending
│   │   ├── Test-DakSTIGChecks.ps1           # Pending
│   │   ├── Test-DakPCIChecks.ps1            # Pending
│   │   └── Test-DakSOC2Checks.ps1           # Pending
│   └── reports/
│       ├── Export-DakAuditExcel.ps1         # ImportExcel — multi-sheet workbook
│       ├── Export-DakAuditWord.ps1          # Word COM — formal .docx report
│       ├── Export-DakAuditHTML.ps1          # Self-contained HTML — no extra deps
│       └── Export-DakAuditJson.ps1          # Structured JSON with header + results
├── private/
│   ├── New-DakCheckResult.ps1               # Result object factory
│   └── Save-DakAuditResult.ps1             # Optional SQL persistence
└── schema/
    ├── Create-AuditDatabase.sql             # AuditKit DB, tables, and views
    └── ControlCrossRef-Seed.sql            # Cross-framework control mappings
```

---

## Invoke-DakAuditSuite

Main orchestrator. Calls the active framework check functions, collects all results, routes to export functions, and optionally persists to a central database.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SqlInstance` | `string[]` | required | Target instances. Pipeline-compatible with `Get-DbaRegisteredServer`. |
| `-SqlCredential` | `PSCredential` | — | SQL auth credential. Omit for Windows auth. |
| `-Framework` | `string[]` | `All` | `CIS`, `SOX`, `STIG`, `PCI`, `SOC2`, or `All`. |
| `-OutputFormat` | `string[]` | `Terminal, JSON` | `Terminal`, `JSON`, `XML`, `Excel`, `Word`, `HTML`. Multiple values accepted. |
| `-OutputPath` | `string` | `.` | Required when OutputFormat includes Excel, Word, or HTML. |
| `-FailedOnly` | `switch` | — | Return only Fail, Warning, and Manual results. |
| `-Repository` | `string` | — | SQL Server instance for result persistence. |
| `-RepositoryDatabase` | `string` | `AuditKit` | Persistence database name. |

---

## Test-DakCISBenchmark

Runs CIS Microsoft SQL Server 2025 Benchmark v1.0.0 checks. One result object per check per instance.

```powershell
# All sections
Test-DakCISBenchmark -SqlInstance SQLPROD01

# Section filter
Test-DakCISBenchmark -SqlInstance SQLPROD01 -Section 2, 3

# Export direct from check function
Test-DakCISBenchmark -SqlInstance SQLPROD01 -OutputPath C:\Audit
```

### CIS section coverage

| Section | Checks |
|---|---|
| 1 — Patches | 1.1 Patch level, 1.2 Latest cumulative update |
| 2 — Surface Area | 2.1–2.8 sp_configure settings, 2.9 Trustworthy databases, 2.10 Network protocols, 2.11 TCP port, 2.12 Hide instance, 2.13–2.16 sa account, 2.17 CLR Strict Security |
| 3 — Authentication | 3.1 Auth mode, 3.2 Guest CONNECT, 3.3 Orphaned users, 3.4 Contained DB auth, 3.5–3.7 Service accounts, 3.8 Public role perms, 3.9 BUILTIN groups, 3.10 Local groups, 3.11 Agent proxies, 3.12 SYSADMIN, 3.13 msdb roles, 3.14 ALTER ANY SERVER AUDIT, 3.15 Excessive sysadmin membership |
| 4 — Password Policy | 4.1 MUST_CHANGE, 4.2 CHECK_EXPIRATION (sysadmins), 4.3 CHECK_POLICY |
| 5 — Auditing | 5.1 Error log count, 5.2 Default trace, 5.3 Login audit level, 5.4 SQL Server Audit action groups |
| 6 — App Dev | 6.1 Database-level CLR, 6.2 CLR assembly permission sets |
| 7 — Encryption | 7.1 Symmetric key algorithms, 7.2 Asymmetric key size, 7.3 Backup encryption (L2), 7.4 Network encryption (L2), 7.5 TDE (L2) |
| 8 — Additional | 8.1 SQL Browser service |

### Result object (DakAuditKit.AuditResult)

Default table display:

```
Framework  CheckId  CheckName                     SqlInstance  AssessmentType  Status   CurrentValue
---------  -------  ---------                     -----------  --------------  ------   ------------
CIS        1.1      Latest Patch Level            SQLPROD01    Automated       Pass     16.0.4165.4
CIS        2.1      Ad Hoc Distributed Queries    SQLPROD01    Automated       Pass     0
CIS        2.2      CLR Integration               SQLPROD01    Automated       Fail     1
CIS        3.5      MSSQL Engine Service Account  SQLPROD01    Manual          Manual   NT SERVICE\MSSQLSERVER
```

Full properties (via `Format-List *`):

| Property | Description |
|---|---|
| `RunDate` | Timestamp when the audit ran |
| `RunBy` | DOMAIN\username that ran the audit |
| `ComputerName` | Host name |
| `SqlInstance` | Instance name |
| `Framework` | CIS / SOX / STIG / PCI / SOC2 |
| `CheckId` | Framework control number |
| `CheckName` | Human-readable check name |
| `Category` | Section grouping |
| `AssessmentType` | `Automated` — tool determines pass/fail; `Manual` — tool collects evidence, human decides |
| `Status` | Pass / Fail / Warning / Manual / Data / Skip / Error |
| `Compliant` | `$true` if Pass; `$false` if Fail/Warning/Error; `$null` if Manual/Data/Skip |
| `CurrentValue` | Value found on the instance |
| `ExpectedValue` | Value required for compliance |
| `Remediation` | Fix guidance (null on Pass; audit note on Manual checks) |
| `Reference` | Benchmark citation |
| `SqlQuery` | T-SQL used to collect the evidence |

#### Manual checks

Checks classified `AssessmentType = 'Manual'` require human judgment to determine compliance. The tool collects the current configuration as evidence (`CurrentValue`) and sets `Status = 'Manual'` with a `Remediation` note describing what to review. These checks are included in `-FailedOnly` output and in report findings sections.

---

## Export functions

All accept pipeline input and return a `PSCustomObject` with `OutputFile` and `TotalRows` properties. Files are named `AuditKit_<instance>_<date>_<time>.<ext>`.

| Function | Dependency | Output |
|---|---|---|
| `Export-DakAuditJson` | None | `.json` — structured file with header + results array |
| `Export-DakAuditExcel` | ImportExcel | `.xlsx` — Summary, AllChecks, Failures worksheets |
| `Export-DakAuditWord` | Microsoft Word | `.docx` — cover page, summary table, findings, appendix |
| `Export-DakAuditHTML` | None | `.html` — self-contained report with scorecard, filter buttons, and collapsible T-SQL |

`Export-DakAuditWord` uses Word COM automation and requires Microsoft Word to be installed. No additional PowerShell modules are needed.

---

## Optional persistence

Run `schema/Create-AuditDatabase.sql` on a repository SQL Server instance, then pass `-Repository` to `Invoke-DakAuditSuite`. Results are written to `[AuditKit].[dbo].[AuditResult]` after each run.

Two views are created automatically:

| View | Purpose |
|---|---|
| `dbo.vw_LatestRunResults` | Current-state dashboard — most recent result per check per instance |
| `dbo.vw_FailureTrend` | Fail/warning counts per instance per day for trend tracking |

---

## Cross-framework control mapping

`schema/ControlCrossRef-Seed.sql` pre-populates `dbo.ControlCrossRef` with controls that overlap across frameworks (e.g., authentication mode, password policy, and sysadmin membership appear in both CIS and SOX). Use this table to identify redundant findings in combined reports and to run gap analysis when a new framework is added.

Each framework check function is scoped to its own control set — there is no shared check logic between CIS and SOX. Cross-framework mappings are reference data only and do not affect check execution or result de-duplication.

---

## Framework implementation status

| Framework | Status | Notes |
|---|---|---|
| CIS | Complete | CIS Microsoft SQL Server 2025 Benchmark v1.0.0 — 48 checks |
| SOX | Pending | 9 areas planned: role membership, orphaned users, password policy, SQL Server Audit, login audit, linked servers, Agent jobs, ALTER ANY SERVER AUDIT permissions |
| STIG | Pending | DISA SQL Server STIG |
| PCI | Pending | PCI-DSS v4.0 |
| SOC 2 | Pending | Trust Service Criteria CC6.x |

---

## Dependencies

| Module | Required by | Install |
|---|---|---|
| [dbatools](https://dbatools.io) | All check functions | `Install-Module dbatools` |
| [ImportExcel](https://github.com/dfinke/ImportExcel) | `Export-DakAuditExcel` | `Install-Module ImportExcel` |
| Microsoft Word | `Export-DakAuditWord` | Office install — no PowerShell module needed |

---

## Standalone scripts (legacy)

The original standalone collection scripts are retained in `Archive/` for reference. See commit history for details.

---

## License

MIT
