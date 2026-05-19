---
paths:
  - "**/*.ps1"
  - "**/*.psm1"
  - "**/*.psd1"
---

# PowerShell Rules

## dbatools First
Before writing any SQL Server PowerShell, check for a dbatools cmdlet.
If none exists, state: "No dbatools cmdlet found for [task]" then use native PS.
NEVER use `Invoke-Sqlcmd` — always `Invoke-DbaQuery`.

## Prod Instance Safety
These are PROD instances — never target without explicit per-session instruction:
- `GP-ENT-NEW\ENT`
- `SQL-RPL-NEW\RPL`
- `WMS-SQL\ODNWMS`
- `SQL-PMA\ODNPMA`

Default target: `localhost` or `SQL-ENT-TEST\ENT`.

## Required on Every Script
- `$ErrorActionPreference = 'Stop'` at script top
- `-WhatIf` support on any script that modifies state
- Comment-based help on all functions

## Style (enforced by validate-style.ps1)
Backticks, ArrayList, Parameter attribute syntax, hashtable alignment,
splatting naming, and OTBS are already hook-enforced. Don't repeat them.