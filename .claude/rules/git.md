---
paths:
  - "**/.git/COMMIT_EDITMSG"
  - "**/CHANGELOG.md"
---

# Git Rules

## Commit Message Format
Use conventional commits:
```
<type>(<scope>): <description>

Types: fix | feat | chore | docs | refactor | test
Scope: instance name, script name, or area (e.g., audit, replication, security)

Examples:
fix(SQL-ENT-TEST): disable sa login and enforce CHECK_POLICY
feat(audit): add CIS 5.4 server audit specification
chore(maintenance): install Ola Hallengren solution
```

## Rules
- Description in lowercase, no period at end
- Under 72 characters on the subject line
- Body explains why, not what — the diff shows what