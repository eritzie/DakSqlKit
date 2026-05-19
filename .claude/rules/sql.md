---
paths:
  - "**/*.sql"
---

# T-SQL Rules

## Absolute Rules
- NO `SELECT *` — always column-list
- All objects bracket-qualified: `[dbo].[TableName]`
- Always schema-qualify: `[DatabaseName].[dbo].[TableName]`
- Uppercase reserved words

## Destructive Statements
Any DELETE, TRUNCATE, or DROP must be preceded by:
```sql
/*
  INTENT : What is being removed and why
  TARGET : Instance and database (default: localhost)
  RISK   : Impact assessment
*/
```

## Default Target
All generated scripts target `localhost` unless explicitly told otherwise.
Never target prod instances without explicit per-session instruction.

## Other
- `NOLOCK` only when explicitly requested — flag risk once
- No cursors unless no set-based alternative exists — document the reason
- Temp objects use `#` prefix; `##` only if truly global scope needed