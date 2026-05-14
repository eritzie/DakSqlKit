# CLAUDE.md — SQL DBA Workspace

This guide defines standards for T-SQL and PowerShell development across
SQL Server inventory and automation work.

---

## CRITICAL RULES

### NO RAW INVOKE-SQLCMD — ALWAYS USE DBATOOLS

**ABSOLUTE RULE**: Never suggest `Invoke-Sqlcmd` when a dbatools equivalent exists.
dbatools handles connections, credentials, and error handling consistently.

```powershell
# CORRECT
Invoke-DbaQuery -SqlInstance $instance -Database $db -Query $sql

# WRONG
Invoke-Sqlcmd -ServerInstance $instance -Database $db -Query $sql
```

### NO SELECT * IN PRODUCTION SCRIPTS

**ABSOLUTE RULE**: Always column-list. No exceptions in scripts committed to the repo.

```sql
-- CORRECT
SELECT database_id, name, recovery_model_desc
FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb');

-- WRONG
SELECT * FROM sys.databases;
```

### NO DESTRUCTIVE STATEMENTS WITHOUT COMMENT BLOCK

**ABSOLUTE RULE**: Any DELETE, TRUNCATE, or DROP must be preceded by an explicit
comment block stating what is being removed and why. Scripts default to DEV targets.

```sql
-- CORRECT
/*
  INTENT : Remove orphaned job history rows older than 90 days
  TARGET : SQL-DEV-01 (test run)
  RISK   : None — msdb only, no app data
*/
DELETE FROM msdb.dbo.sysjobhistory
WHERE run_date < CONVERT(int, CONVERT(varchar, DATEADD(DAY,-90,GETDATE()),112));

-- WRONG
DELETE FROM msdb.dbo.sysjobhistory WHERE run_date < 20240101;
```

---

## POWERSHELL STANDARDS

### SPLAT USAGE REQUIREMENT

- **1–2 parameters**: Inline syntax
- **3+ parameters**: Splatted hashtable named `$splat<Purpose>`

```powershell
# CORRECT — 2 params, inline
$dbs = Get-DbaDatabase -SqlInstance $instance -Name "master"

# CORRECT — 4 params, splat required
$splatInv = @{
    SqlInstance     = $instances
    SqlCredential   = $cred
    ExcludeDatabase = @('tempdb')
    EnableException = $true
}
$results = Get-DbaDatabase @splatInv
```

### PARAMETER ATTRIBUTE SYNTAX

```powershell
# CORRECT — Modern syntax
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,
    [Parameter(ValueFromPipeline)]
    [string[]]$Database,
    [switch]$EnableException
)

# WRONG — PSv2 legacy syntax
param(
    [Parameter(Mandatory = $true)]
    [string]$SqlInstance
)
```

### HASHTABLE ALIGNMENT (MANDATORY)

All hashtable `=` signs must be vertically aligned.

```powershell
# CORRECT
$splatBackup = @{
    SqlInstance       = $instance
    Database          = $dbName
    BackupDirectory   = $backupPath
    CompressBackup    = $true
    EnableException   = $true
}

# WRONG
$splat = @{
    SqlInstance = $instance
    Database = $dbName
}
```

### PIPELINE OUTPUT

Emit objects immediately. Never collect into an ArrayList.

```powershell
# CORRECT
foreach ($svr in $servers) {
    [PSCustomObject]@{
        SqlInstance = $svr.Name
        Version     = $svr.VersionString
    }
}

# WRONG
$results = [System.Collections.ArrayList]::new()
# ...
$results
```

### OTHER PS RULES

- `$ErrorActionPreference = 'Stop'` at script top
- Comment-based help on all functions
- Use `$true`/`$false` not `1`/`0` for booleans
- No backticks for line continuation — ever
- `-WhatIf` support on any script that modifies state

---

## T-SQL STANDARDS

- Uppercase reserved words
- Bracket-qualify all object names: `[dbo].[TableName]`
- Always schema-qualify: `[DatabaseName].[dbo].[TableName]`
- `NOLOCK` hints only where explicitly requested — flag the risk once if added
- All temp objects use `#` prefix (local) or `##` only if truly global scope needed
- No cursors unless there is no set-based alternative and the reason is documented

---

## ENVIRONMENT

| Alias       | Role                    | Safe for Writes |
|-------------|-------------------------|-----------------|
| SQL-PROD-01 | Primary AG node         | NO              |
| SQL-PROD-02 | Secondary AG (readable) | NO              |
| SQL-RPT-01  | Reporting               | NO              |
| SQL-DEV-01  | Dev/test                | YES             |

**Default target for all generated scripts: `SQL-DEV-01`**
Never target SQL-PROD-01 or SQL-PROD-02 without an explicit per-session instruction.

---

## OUTPUT PREFERENCES

- Inventory output: markdown tables or `.xlsx` via `Export-Excel` (ImportExcel module)
- Risk flags: one line, plainly stated — no repeated hedging
- Tradeoffs over recommendations where judgment calls exist
- Code in fenced blocks with language tags (`powershell`, `sql`)

---

## VERIFICATION CHECKLIST

**PowerShell:**
- [ ] No `Invoke-Sqlcmd` — dbatools equivalent used
- [ ] No backticks for line continuation
- [ ] No `= $true` in Parameter attributes
- [ ] Splats for 3+ parameters, named `$splat<Purpose>`
- [ ] Hashtables vertically aligned
- [ ] Pipeline output emitted immediately
- [ ] `-WhatIf` supported on state-changing scripts
- [ ] `$ErrorActionPreference = 'Stop'` set

**T-SQL:**
- [ ] No `SELECT *`
- [ ] All objects bracket-qualified and schema-qualified
- [ ] Destructive statements have comment block
- [ ] Script targets SQL-DEV-01 by default

**Safety:**
- [ ] Production instances not targeted

---

## GOLDEN RULES

1. **NEVER use `Invoke-Sqlcmd`** — use dbatools equivalents
2. **NEVER write `SELECT *`** — always column-list
3. **NEVER run against PROD** — default to SQL-DEV-01 every session
4. **ALWAYS splat at 3+ params** — named `$splat<Purpose>`
5. **ALWAYS align hashtables** — equals signs line up
6. **ALWAYS precede destructive SQL** — with a comment block stating intent and target
7. **ALWAYS emit pipeline output immediately** — no ArrayList collection