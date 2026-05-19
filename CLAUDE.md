# CLAUDE.md — SQL DBA Workspace

## CONTEXT FILES

Load these at session start for environment context:

- `C:\Users\eric.r\OneDrive - Outdoor Network\notes\work-context.md` — role, stack, active projects
- `C:\Users\eric.r\OneDrive - Outdoor Network\notes\instances.md` — instance topology, AG/replication roles
- `C:\Users\eric.r\OneDrive - Outdoor Network\notes\audit-findings.md` — CIS/SOX findings and remediation status
- `C:\Users\eric.r\OneDrive - Outdoor Network\notes\maintenance-windows.md` — window schedule and blackout periods
- `C:\Users\eric.r\OneDrive - Outdoor Network\notes\snippets.md` — reusable T-SQL and PowerShell patterns

---

## CRITICAL RULES

### DBATOOLS FIRST
Before writing any PowerShell touching SQL Server, Windows services, OS settings, or AD — check https://docs.dbatools.io first.
- Cmdlet exists → use it
- No cmdlet exists → comment: `# No dbatools equivalent — using native PS`

### NO INVOKE-SQLCMD
Never suggest `Invoke-Sqlcmd` when a dbatools equivalent exists.

```powershell
# CORRECT
Invoke-DbaQuery -SqlInstance $instance -Database $db -Query $sql
```

### NO SELECT *
Always column-list in scripts committed to the repo. No exceptions.

### DESTRUCTIVE STATEMENTS REQUIRE COMMENT BLOCK
Any DELETE, TRUNCATE, or DROP must be preceded by a comment block stating intent, target, and risk.

```sql
/*
  INTENT : Remove orphaned job history rows older than 90 days
  TARGET : SQL-ENT-TEST\ENT (test run)
  RISK   : None — msdb only, no app data
*/
```

---

## POWERSHELL STANDARDS

- `$ErrorActionPreference = 'Stop'` at script top
- 1–2 parameters: inline syntax; 3+: splatted hashtable named `$splat<Purpose>`
- Hashtable `=` signs vertically aligned
- Modern parameter attributes: `[Parameter(Mandatory)]` not `[Parameter(Mandatory = $true)]`
- Emit pipeline output immediately — no ArrayList collection
- No backticks for line continuation
- `-WhatIf` on any script that modifies state
- `$true`/`$false` not `1`/`0`
- Comment-based help on all functions

```powershell
# Splat example — 3+ params
$splatInv = @{
    SqlInstance     = $instances
    SqlCredential   = $cred
    ExcludeDatabase = @('tempdb')
    EnableException = $true
}
$results = Get-DbaDatabase @splatInv
```

---

## T-SQL STANDARDS

- Uppercase reserved words
- Bracket-qualify all object names: `[dbo].[TableName]`
- Always schema-qualify: `[DatabaseName].[dbo].[TableName]`
- `NOLOCK` only when explicitly requested — flag risk once
- Temp objects use `#` prefix; `##` only if truly global scope needed
- No cursors unless no set-based alternative exists — document the reason

---

## ENVIRONMENT

| Instance | Version | Role | Safe for Writes | Notes |
|---|---|---|---|---|
| localhost | 17.0.4040 (SQL 2025) | Dev | YES | |
| SQL-ENT-TEST\ENT | 15.0.4280 (SQL 2019) | Test | NO | |
| SQL-RPL-TEST\RPL | 15.0.4280 (SQL 2019) | Test | NO | |
| TEST-WMS-SQL | 15.0.2000 (SQL 2019) | Test | NO | |
| GP-ENT-NEW\ENT | 15.0.4280 (SQL 2019) | Prod | NO | Great Plains |
| SQL-RPL-NEW\RPL | 15.0.4280 (SQL 2019) | Prod | NO | |
| WMS-SQL\ODNWMS | 15.0.4280 (SQL 2019) | Prod | NO | |
| SQL-PMA\ODNPMA | 14.0.1000 (SQL 2017) | Prod | NO | |

**Default target for all generated scripts: `SQL-ENT-TEST\ENT`**
Never target Prod instances without an explicit per-session instruction.

---

## OUTPUT PREFERENCES

- Inventory output: markdown tables or `.xlsx` via `Export-Excel` (ImportExcel module)
- Risk flags: one line, plainly stated — no repeated hedging
- Tradeoffs over recommendations where judgment calls exist
- Code in fenced blocks with language tags (`powershell`, `sql`)