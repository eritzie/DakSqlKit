---
name: remediate
argument-hint: "[CheckId] [Instance]"
---

# Remediate a CIS/SOX Finding

Generate a remediation script for finding $ARGUMENTS.

## Steps

1. Read `C:\Users\eric.r\OneDrive - Outdoor Network\notes\audit-findings.md`
   and locate the finding matching the CheckId in $ARGUMENTS.

2. Read the current finding status, remediation field, and any notes.

3. Confirm the target instance from $ARGUMENTS or default to `localhost`.
   NEVER target a prod instance without explicit confirmation.

4. Generate a PowerShell remediation script following these rules:
   - Use dbatools cmdlets where available
   - Include -WhatIf support
   - $ErrorActionPreference = 'Stop' at top
   - Splat all parameters (3+)
   - Comment block stating INTENT, TARGET, RISK before any destructive SQL
   - Include a verification query to confirm the change took effect

5. If the finding requires a maintenance window (restart, volume reformat,
   file move), generate a CAP document instead of a script:
   - Finding description and risk
   - Pre-change verification steps
   - Change steps with rollback for each
   - Post-change verification
   - Estimated downtime

6. Output the script or CAP. Do not apply any changes — generate only.