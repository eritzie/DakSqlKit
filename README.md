# SQL-Server-Security-Audit

SQL Server security and compliance audit scripts for SOX, CIS benchmarking, and general DBA security reviews.

## Folder Structure

```
SQL-Server-Security-Audit/
├── README.md
├── .gitignore
├── SOX/
│   ├── SQL_Logins.sql
│   ├── Server_Logins.sql
│   ├── Server_Logins.ps1
│   ├── Database_Roles.sql
│   ├── Blank_Passwords.sql
│   ├── Auth_Mode.sql
│   ├── Server_Configuration.sql
│   ├── Backup_History.sql
│   ├── Agent_Job_Access.sql
│   ├── Collect-SOXAudit.ps1
│   └── Collect-SOXAudit-dbatools.ps1
└── CIS/
    ├── CIS-Benchmark-Check.ipynb
    └── Collect-CISAudit.ps1
```

## Quick Start

### Run individual scripts in SSMS

Open any `.sql` file in SSMS and execute against the target instance. Most scripts are server-scoped; `Database_Roles.sql` iterates all online databases automatically.

### Collect all SOX audit data to Excel

**Option A — Run the `.sql` files via PowerShell:**

```powershell
.\SOX\Collect-SOXAudit.ps1 -SqlInstance "YOURSERVER" -OutputPath "C:\Audit"
```

**Option B — Pure dbatools (no `.sql` files needed):**

```powershell
.\SOX\Collect-SOXAudit-dbatools.ps1 -SqlInstance "YOURSERVER" -OutputPath "C:\Audit"
```

Both produce a single dated Excel workbook with one worksheet per audit area.

### Multi-instance collection (dbatools version only)

```powershell
.\SOX\Collect-SOXAudit-dbatools.ps1 -SqlInstance "SQLPROD01","SQLPROD02","SQLDEV01"
```

### Collect all CIS audit data to Excel

```powershell
.\CIS\Collect-CISAudit.ps1 -SqlInstance "YOURSERVER" -OutputPath "C:\Audit"
```

### Interactive CIS check-and-remediate workflow

Open `CIS/CIS-Benchmark-Check.ipynb` in VS Code with the Jupyter extension (PowerShell kernel). Set your instances in the first code cell, then step through each check interactively. Remediation commands are included but commented out.

## Dependencies

| Dependency | Required By | Install |
|---|---|---|
| [dbatools](https://dbatools.io) | All `.ps1` scripts and notebook | `Install-Module dbatools` |
| [ImportExcel](https://github.com/dfinke/ImportExcel) | Collect scripts (Excel export) | `Install-Module ImportExcel` |
| [kbupdate](https://github.com/potatoqualitee/kbupdate) | CIS 1.1 patch level check | `Install-Module kbupdate` |
| [Ola Hallengren's Maintenance Solution](https://ola.hallengren.com) | `Backup_History.sql`, `Collect-SOXAudit-dbatools.ps1` | Backup job schedule queries filter on `DatabaseBackup*` naming convention. Adjust if using a different backup solution. |

## SOX Scripts

| Script | Scope | Description |
|---|---|---|
| `SQL_Logins.sql` | Server | SQL authentication logins with password policy and lockout status |
| `Server_Logins.sql` | Server | All server principals with roles, permissions, and password policy settings |
| `Server_Logins.ps1` | Server | dbatools version of `Server_Logins.sql` with Excel/CSV export |
| `Database_Roles.sql` | All DBs | Database principals and role memberships across all online databases |
| `Blank_Passwords.sql` | Server | SQL logins with blank passwords |
| `Auth_Mode.sql` | Server | Windows-only vs. mixed mode authentication |
| `Server_Configuration.sql` | Server | All `sys.configurations` settings with pending-restart detection |
| `Backup_History.sql` | Server | Most recent backup per database per type, plus Ola Hallengren job schedules |
| `Agent_Job_Access.sql` | Server | Accounts with SQL Agent roles or sysadmin (implicit agent access) |

## Collection Scripts

| Script | Framework | Method | Description |
|---|---|---|---|
| `SOX/Collect-SOXAudit.ps1` | SOX | Runs `.sql` files via `Invoke-DbaQuery` | Executes all SOX SQL scripts and exports results to a single Excel workbook |
| `SOX/Collect-SOXAudit-dbatools.ps1` | SOX | Native dbatools cmdlets | Same audit data collected using dbatools cmdlets directly; supports multi-instance |
| `CIS/Collect-CISAudit.ps1` | CIS | Native dbatools cmdlets | Collects all CIS benchmark checks and exports to a single Excel workbook; supports multi-instance |

All collection scripts produce a workbook with a Cover sheet (server, run date, who ran it, errors) followed by one tab per audit area.

## CIS Scripts

Based on the **CIS Microsoft SQL Server 2022 Benchmark v1.2.1**.

| File | Type | Description |
|---|---|---|
| `CIS-Benchmark-Check.ipynb` | Jupyter Notebook | Interactive check-and-remediate workflow. Each CIS section includes the benchmark description, T-SQL reference query, and executable dbatools PowerShell command. Remediation commands are included but commented out. |
| `Collect-CISAudit.ps1` | PowerShell | Runs all CIS checks and exports results to a single Excel workbook with one tab per benchmark section. |

### CIS Benchmark Coverage

| Section | Checks | Method |
|---|---|---|
| 1. Installation & Patches | 1.1 Patch level | `Test-DbaBuild` |
| 2. Surface Area Reduction | 2.1–2.8, 2.17 sp_configure settings | `Get-DbaSpConfigure` |
| | 2.9 Trustworthy | `Get-DbaDatabase` |
| | 2.10 Protocols | `Get-DbaInstanceProtocol` |
| | 2.11 TCP port | `Get-DbaTcpPort` |
| | 2.12 Hide Instance | `Get-DbaHideInstance` |
| | 2.13–2.16 sa account checks | `Get-DbaLogin` |
| | 2.15 AUTO_CLOSE | `Get-DbaDatabase` |
| | Additional: xp_cmdshell | `Get-DbaSpConfigure` |
| 3. Authentication & Authorization | 3.1 Auth mode | `Get-DbaInstanceProperty` |
| | 3.2 Guest CONNECT | `Get-DbaDbUser` |
| | 3.3 Orphaned users | `Get-DbaDbOrphanUser` |
| | 3.4 Contained DB auth | `Get-DbaDatabase` + `Get-DbaDbUser` |
| | 3.5–3.7 Service accounts | `Get-DbaService` |
| | 3.8 Public role permissions | `Invoke-DbaQuery` |
| | 3.9–3.10 BUILTIN/local groups | `Get-DbaLogin` |
| | 3.11 Agent proxy access | `Invoke-DbaQuery` |
| | 3.12 SYSADMIN membership | `Get-DbaServerRoleMember` |
| | 3.13 msdb admin roles | `Get-DbaDbRoleMember` |
| 4. Password Policies | 4.1 MUST_CHANGE | `Get-DbaLogin -Detailed` |
| | 4.2 CHECK_EXPIRATION | `Get-DbaLogin` + `Get-DbaServerRoleMember` |
| | 4.3 CHECK_POLICY | `Get-DbaLogin` |
| 5. Auditing & Logging | 5.1 Error log count | `Get-DbaErrorLogConfig` |
| | 5.2 Default trace | `Get-DbaSpConfigure` |
| | 5.3 Login auditing | `Invoke-DbaQuery` (xp_loginconfig) |
| | 5.4 SQL Server Audit | `Get-DbaInstanceAudit` / `Get-DbaInstanceAuditSpecification` |
| 6. Application Development | 6.2 CLR assembly permissions | `Invoke-DbaQuery` (per database) |
| 7. Encryption | 7.1–7.2 Key algorithms/sizes | `Invoke-DbaQuery` (per database) |
| | 7.3 Backup encryption | `Invoke-DbaQuery` |
| | 7.4 Network encryption | `Invoke-DbaQuery` |
| | 7.5 TDE | `Get-DbaDbEncryption` |
| 8. Additional | 8.1 Browser service | `Get-DbaService` |
| 9. Appendix | Audit/scan user setup | `New-DbaLogin` + `Invoke-DbaQuery` |

## Notes

- Output may contain sensitive security information (SIDs, login names, role memberships). Do not commit query results to this repo.
- `Database_Roles.sql` uses a cursor over `sys.databases` instead of `sp_MSforeachdb` for reliability with offline databases and special characters.
- Some scripts contain environment-specific filters (backup job names, excluded accounts). Review and adjust before running in your environment.
- `password_hash` is intentionally excluded from all output to avoid exporting sensitive data to audit workbooks.
- The CIS notebook includes an `xp_cmdshell` check as an additional best practice. This was removed from the 2022 benchmark but is retained here as a security recommendation.
- The CIS notebook requires a PowerShell kernel in Jupyter. Use VS Code with the [Jupyter extension](https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter).

## License

MIT