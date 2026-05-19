# DakSqlKit — Database Audit Kit for SQL Server

SQL Server security audit toolkit covering CIS, SOX, STIG, PCI-DSS, and SOC 2. Built on dbatools conventions — pipeline-friendly objects with Pass/Fail/Warning/Manual status and remediation guidance on every finding.

## Install

```powershell
# Required dependency
Install-Module dbatools

# Import from repo
Import-Module .\DakSqlKit.psd1
```

## Quick start

```powershell
# CIS Benchmark — all 48 checks
Test-DakCISBenchmark -SqlInstance SQLPROD01

# DbConfig health — all 92 checks
Test-DakDbConfig -SqlInstance SQLPROD01

# SOX IT General Controls — all 31 checks
Test-DakSOXBenchmark -SqlInstance SQLPROD01

# PCI DSS v4.0.1 — all 34 checks
Test-DakPCIBenchmark -SqlInstance SQLPROD01

# SOC 2 Trust Services Criteria — all 32 checks
Test-DakSOC2Benchmark -SqlInstance SQLPROD01

# Failures and manual checks only
Test-DakCISBenchmark -SqlInstance SQLPROD01 -FailedOnly

# Specific sections only
Test-DakDbConfig -SqlInstance SQLPROD01 -Section 4        # Security only
Test-DakSOXBenchmark -SqlInstance SQLPROD01 -Section 1,2  # Access + Audit only
Test-DakPCIBenchmark -SqlInstance SQLPROD01 -Section 3,4  # Data protection + Audit only
Test-DakSOC2Benchmark -SqlInstance SQLPROD01 -Section 1,5 # Access + Confidentiality only

# Run all implemented frameworks via orchestrator
Invoke-DakAuditSuite -SqlInstance SQLPROD01

# Pipe from registered servers
Get-DbaRegisteredServer -Group Production | Invoke-DakAuditSuite -Framework CIS, SOX, PCI, SOC2 -FailedOnly

# Persist results to a centralized audit repository
Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS, SOX, PCI, SOC2 -Repository SQLAUDIT01

# Export to Excel (requires ImportExcel module)
Test-DakSOC2Benchmark -SqlInstance SQLPROD01 | Export-Excel -Path .\SOC2-$(Get-Date -f yyyyMMdd).xlsx -AutoSize
```

---

## Module structure

```
DakSqlKit.psd1
DakSqlKit.psm1
public/
├── core/
│   └── Invoke-DakAuditSuite.ps1         # Orchestrator — runs frameworks, persists results
└── checks/
    ├── Test-DakCISBenchmark.ps1          # Full — CIS SQL Server 2025 v1.0.0 (48 checks)
    ├── Test-DakDbConfig.ps1              # Full — Instance/DB health and security (92 checks)
    ├── Test-DakPCIBenchmark.ps1          # Full — PCI DSS v4.0.1 (34 checks)
    ├── Test-DakSOC2Benchmark.ps1         # Full — SOC 2 Trust Services Criteria (32 checks)
    └── Test-DakSOXBenchmark.ps1          # Full — SOX IT General Controls (31 checks)
private/
├── New-DakCheckResult.ps1               # Result object factory
├── Save-DakAuditResult.ps1              # Persistence — writes to audit repository
└── Initialize-DakRepository.ps1         # Auto-provisions repository DB, schema, tables, views
_Archive/
├── CIS/                                  # Original standalone CIS scripts
└── SOX/                                  # Original standalone SOX scripts
```

---

## Invoke-DakAuditSuite

Orchestrator. Calls one or more framework check functions, collects all results, and optionally persists to a central database. The repository database and schema are created automatically on first use — no pre-requisite SQL scripts required.

```powershell
Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS, SOX -Repository SQLAUDIT01
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SqlInstance` | `string[]` | required | Target instances. Pipeline-compatible with `Get-DbaRegisteredServer`. |
| `-SqlCredential` | `PSCredential` | — | SQL auth credential. Omit for Windows auth. |
| `-Framework` | `string[]` | `All` | `CIS`, `DbConfig`, `PCI`, `SOC2`, `SOX`, `STIG`, or `All`. |
| `-FailedOnly` | `switch` | — | Return only Fail, Warning, and Manual results. |
| `-Repository` | `string` | — | SQL Server instance for centralized result persistence. |
| `-RepositoryDatabase` | `string` | `DBAOps` | Persistence database name. Created automatically if absent. |
| `-RepositoryCredential` | `PSCredential` | — | Credential for the repository instance (if different from audited instance). |

---

## Test-DakCISBenchmark

Runs CIS Microsoft SQL Server 2025 Benchmark v1.0.0. One result object per check per instance. Sections 1–8 selectable via `-Section`.

| Section | Checks |
|---|---|
| §1 — Installation & Patches | 1.1 Latest patch level, 1.2 Single-function member server |
| §2 — Surface Area Reduction | 2.1–2.8 sp_configure settings, 2.9 Trustworthy databases, 2.10 Network protocols, 2.11 Non-standard TCP port, 2.12 Hide instance, 2.13–2.16 sa account controls, 2.17 CLR strict security |
| §3 — Authentication & Authorization | 3.1 Auth mode, 3.2 Guest CONNECT, 3.3 Orphaned users, 3.4 Contained DB SQL auth, 3.5–3.7 Service accounts, 3.8 Public role permissions, 3.9 BUILTIN groups, 3.10 Local Windows groups, 3.11 Agent proxy public access, 3.12 SYSADMIN membership, 3.13 msdb admin roles, 3.14 CONTROL SERVER permission, 3.15 sp_invoke_external_rest_endpoint access |
| §4 — Password Policy | 4.1 MUST_CHANGE logins, 4.2 CHECK_EXPIRATION (sysadmins), 4.3 CHECK_POLICY |
| §5 — Auditing & Logging | 5.1 Error log count, 5.2 Default trace, 5.3 Login audit level, 5.4 SQL Server Audit action groups |
| §6 — Application Development | 6.1 Input sanitization, 6.2 CLR assembly permission sets |
| §7 — Encryption (Level 2) | 7.1 Symmetric key algorithms, 7.2 Asymmetric key size, 7.3 Backup encryption, 7.4 Network encryption, 7.5 TDE |
| §8 — Additional | 8.1 SQL Browser service |

---

## Test-DakDbConfig

Instance and database configuration health and security checks beyond the CIS benchmark. One result object per check per instance. Sections 1–10 selectable via `-Section`.

| Section | Checks |
|---|---|
| §1 — Instance Memory/CPU/OS | 15 checks — max/min server memory, MAXDOP, cost threshold, lock pages, priority boost, lightweight pooling, xp_cmdshell, linked server RPC, CLR, contained databases |
| §2 — Database Settings | 9 checks — auto-statistics, auto-update async, compatibility level, containment, snapshot isolation, read committed snapshot, forced parameterization |
| §3 — File & Autogrowth | 4 checks — data file autogrowth percent, log file autogrowth percent, autogrowth events, TempDB file count |
| §4 — Security Configuration | 29 checks — sa disabled/renamed, CHECK_POLICY/EXPIRATION, linked server passwords, server audit, public permissions, BUILTIN groups, cross-DB chaining, database ownership, external scripts, ad hoc queries, OLE Automation, mail XPs, remote access, admin connections |
| §5 — Storage Layout | 4 checks — TempDB on dedicated drive, data/log on separate drives, system databases on default path, VLF count |
| §6 — Database Health | 8 checks — database state, recovery model, page verify, last CHECKDB, last backup, log space usage, data file space, auto-shrink |
| §7 — SQL Agent & Alerting | 10 checks — Agent service running, operators, severity 19–25 alerts, I/O error alerts, Database Mail, job failure notification, Agent mail profile |
| §8 — High Availability / HADR | 7 checks — AG health, AG synchronization state, AG automated failover, AG endpoint encryption, AG backup preference, mirroring state, mirroring encryption |
| §9 — Log Shipping | 4 checks — log shipping status, backup job latency, copy job latency, restore job latency |
| §10 — Operational Governance | 2 checks (Manual) — change management process, documentation currency |

---

## Test-DakSOXBenchmark

SOX Section 404 IT general controls for SQL Server. One result object per check per instance. Sections 1–5 selectable via `-Section`.

| Section | Checks |
|---|---|
| §1 — Access & Identity Controls | SOX-1.1 Windows-only auth, SOX-1.2 sa disabled, SOX-1.3 sa renamed, SOX-1.4 BUILTIN groups absent, SOX-1.5 Guest access revoked, SOX-1.6 Password policy enforced, SOX-1.7 Privileged login expiration, SOX-1.8 Sysadmin membership review (Manual) |
| §2 — Audit & Logging | SOX-2.1 SQL Server Audit action groups, SOX-2.2 Login audit level, SOX-2.3 Error log retention, SOX-2.4 Default trace, SOX-2.5 Role membership change auditing, SOX-2.6 DDL/schema change auditing |
| §3 — Change Management | SOX-3.1 Agent job ownership, SOX-3.2 Operator configured, SOX-3.3 Severity 19–25 alerts, SOX-3.4 I/O error alerts 823/824/825, SOX-3.5 Database Mail configured |
| §4 — Data Integrity & Recovery | SOX-4.1 Full backup within 24 hours, SOX-4.2 DBCC CHECKDB within 7 days, SOX-4.3 All databases accessible, SOX-4.4 Full recovery model, SOX-4.5 Log backup within 4 hours, SOX-4.6 Page verify CHECKSUM, SOX-4.7 AUTO_CLOSE disabled, SOX-4.8 AUTO_SHRINK disabled |
| §5 — Encryption | SOX-5.1 Network encryption enforced, SOX-5.2 Backup encryption, SOX-5.3 TDE scope review (Manual), SOX-5.4 Symmetric key algorithms |

---

## Test-DakPCIBenchmark

PCI DSS v4.0.1 database infrastructure controls for SQL Server. One result object per check per instance. Sections 1–5 selectable via `-Section`.

| Section | Checks |
|---|---|
| §1 — Secure Configuration (Req 2) | PCI-1.1 sa disabled, PCI-1.2 sa renamed, PCI-1.3 xp_cmdshell disabled, PCI-1.4 OLE Automation disabled, PCI-1.5 Ad hoc distributed queries disabled, PCI-1.6 CLR strict security, PCI-1.7 SQL Browser disabled, PCI-1.8 Non-standard TCP port, PCI-1.9 Hide instance enabled |
| §2 — Access Control (Req 7–8) | PCI-2.1 Windows-only auth, PCI-2.2 BUILTIN groups absent, PCI-2.3 Guest access revoked, PCI-2.4 Public role no excess permissions, PCI-2.5 No orphaned users, PCI-2.6 CHECK_POLICY enforced, PCI-2.7 Privileged login CHECK_EXPIRATION, PCI-2.8 MUST_CHANGE logins, PCI-2.9 Sysadmin membership review (Manual) |
| §3 — Data Protection (Req 3–4) | PCI-3.1 TDE scope review (Manual), PCI-3.2 Symmetric key algorithms AES only, PCI-3.3 Asymmetric key size min 2048-bit, PCI-3.4 Network encryption enforced, PCI-3.5 Backup encryption |
| §4 — Audit & Logging (Req 10) | PCI-4.1 SQL Server Audit — 6 required PCI action groups, PCI-4.2 Login audit level, PCI-4.3 Error log retention min 12, PCI-4.4 Default trace enabled, PCI-4.5 Audit role membership changes, PCI-4.6 Audit DDL/schema changes |
| §5 — Vulnerability Management (Req 6) | PCI-5.1 Patch level (Req 6.3.3), PCI-5.2 DBCC CHECKDB within 7 days, PCI-5.3 All user databases accessible, PCI-5.4 Page verify CHECKSUM, PCI-5.5 No UNSAFE CLR assemblies |

---

## Test-DakSOC2Benchmark

AICPA SOC 2 Trust Services Criteria for SQL Server database infrastructure. One result object per check per instance. Sections 1–5 selectable via `-Section`.

| Section | Checks |
|---|---|
| §1 — CC6: Logical Access Controls | SOC2-1.1 Windows-only auth, SOC2-1.2 BUILTIN groups absent, SOC2-1.3 Guest access revoked, SOC2-1.4 No orphaned users, SOC2-1.5 sa login disabled, SOC2-1.6 sa login renamed, SOC2-1.7 Password policy enforced, SOC2-1.8 Privileged login password expiration, SOC2-1.9 Public role excess permissions, SOC2-1.10 Sysadmin membership review (Manual) |
| §2 — CC7: Monitoring & Threat Detection | SOC2-2.1 SQL Server Audit — 6 SOC 2 action groups, SOC2-2.2 Login audit level, SOC2-2.3 Error log retention, SOC2-2.4 Default trace enabled, SOC2-2.5 Audit role membership changes, SOC2-2.6 Audit DDL/schema changes |
| §3 — CC8: Change Management | SOC2-3.1 Agent job ownership, SOC2-3.2 Operator configured, SOC2-3.3 Severity 19–25 alerts, SOC2-3.4 Database Mail configured |
| §4 — A1/PI1: Availability & Processing Integrity | SOC2-4.1 Full backup within 24 hours, SOC2-4.2 DBCC CHECKDB within 7 days, SOC2-4.3 All user databases accessible, SOC2-4.4 Full recovery model, SOC2-4.5 Log backup within 4 hours, SOC2-4.6 Page verify CHECKSUM, SOC2-4.7 AUTO_SHRINK disabled |
| §5 — C1: Confidentiality & Encryption | SOC2-5.1 Network encryption enforced, SOC2-5.2 Backup encryption, SOC2-5.3 TDE scope review (Manual), SOC2-5.4 Symmetric key algorithms AES only, SOC2-5.5 No UNSAFE CLR assemblies |

---

## Result object (DakSqlKit.AuditResult)

Default table display:

```
Framework  CheckId    CheckName                      SqlInstance  AssessmentType  Status   CurrentValue
---------  -------    ---------                      -----------  --------------  ------   ------------
CIS        1.1        Latest Patch Level             SQLPROD01    Automated       Pass     16.0.4165.4
CIS        2.2        CLR Integration                SQLPROD01    Automated       Fail     1
DbConfig   DC-4.7     Authentication Mode            SQLPROD01    Automated       Fail     Mixed Mode
SOX        SOX-1.8    Sysadmin Membership Review     SQLPROD01    Manual          Manual   3 non-system accounts
SOX        SOX-4.1    Full Backup Within 24 Hours    SQLPROD01    Automated       Pass     All databases backed up
PCI        PCI-1.3    xp_cmdshell Disabled           SQLPROD01    Automated       Pass     0
PCI        PCI-3.1    TDE Scope Review               SQLPROD01    Manual          Manual   2 user database(s) without TDE
PCI        PCI-5.1    Patch Level — Req 6.3.3        SQLPROD01    Automated       Fail     15.0.4280.7
SOC2       SOC2-1.10  Sysadmin Membership Review     SQLPROD01    Manual          Manual   2 non-system accounts
SOC2       SOC2-4.1   Full Backup Within 24 Hours    SQLPROD01    Automated       Pass     All user databases backed up within 24h
SOC2       SOC2-5.5   No UNSAFE CLR Assemblies       SQLPROD01    Automated       Pass     None
```

Full properties (via `Format-List *` or `Export-Excel`):

| Property | Description |
|---|---|
| `RunDate` | Timestamp when the audit ran |
| `RunBy` | `DOMAIN\username` that ran the audit |
| `ComputerName` | Host name |
| `SqlInstance` | Instance name |
| `Framework` | `CIS`, `DbConfig`, `PCI`, `SOC2`, or `SOX` |
| `CheckId` | Framework control number |
| `CheckName` | Human-readable check name |
| `Category` | Section grouping (e.g., Logical Access, Monitoring, Confidentiality) |
| `AssessmentType` | `Automated` — tool determines pass/fail; `Manual` — tool collects evidence, human decides |
| `Status` | `Pass` / `Fail` / `Warning` / `Manual` / `Data` / `Skip` / `Error` |
| `Compliant` | `$true` if Pass; `$false` if Fail/Warning/Error; `$null` if Manual/Data/Skip |
| `CurrentValue` | Value found on the instance |
| `ExpectedValue` | Value required for compliance |
| `Remediation` | Fix guidance (`$null` on Pass; audit procedure on Manual checks) |
| `Reference` | Benchmark or control citation |
| `SqlQuery` | T-SQL or cmdlet note documenting how evidence was collected |

### Manual checks

Checks with `AssessmentType = 'Manual'` require human judgment to determine compliance. The tool collects the current configuration as evidence (`CurrentValue`) and sets `Status = 'Manual'` with a `Remediation` note describing the audit procedure. Manual results are included in `-FailedOnly` output.

---

## Result persistence

Pass `-Repository` to `Invoke-DakAuditSuite` to persist results to a central SQL Server instance. The database, schema, tables, and views are provisioned automatically on first use — no pre-requisite scripts required.

```powershell
# Central repository on a separate instance
Invoke-DakAuditSuite -SqlInstance SQLPROD01 -Framework CIS, SOX -Repository SQLAUDIT01

# Local persistence — save to the audited instance itself
Invoke-DakAuditSuite -SqlInstance SQL-DEV-01 -Framework DbConfig -RepositoryDatabase DBAOps
```

Two reporting views are created automatically:

| View | Purpose |
|---|---|
| `audit.vw_LatestRunResults` | Current-state dashboard — most recent result per check per instance |
| `audit.vw_FailureTrend` | Fail/warning counts per instance per framework per day for trend tracking |

---

## Framework implementation status

| Framework | Status | Checks |
|---|---|---|
| CIS | Complete | 48 — CIS Microsoft SQL Server 2025 Benchmark v1.0.0 |
| DbConfig | Complete | 92 — Instance and database configuration health and security |
| PCI | Complete | 34 — PCI DSS v4.0.1 database infrastructure controls |
| SOC 2 | Complete | 32 — AICPA Trust Services Criteria CC6/CC7/CC8/A1/C1 |
| SOX | Complete | 31 — Sarbanes-Oxley Section 404 IT general controls |
| STIG | Pending | DISA SQL Server 2022 STIG |

---

## Dependencies

| Module | Required by | Install |
|---|---|---|
| [dbatools](https://dbatools.io) | All check functions | `Install-Module dbatools` |
| [ImportExcel](https://github.com/dfinke/ImportExcel) | `Export-Excel` output (optional) | `Install-Module ImportExcel` |

---

## License

MIT
