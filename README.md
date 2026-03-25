# SQL-Server-Security-Audit

SQL Server security and compliance audit scripts for SOX, CIS benchmarking, and general DBA security reviews.

## Folder Structure

- **SOX/** — Scripts for SOX compliance audits (logins, roles, permissions, backup verification, agent job access)
- **CIS/** — Scripts aligned to CIS SQL Server Benchmark checks

## Usage

Run scripts in SSMS against the target instance. Most scripts are instance-scoped; database-scoped scripts are noted in their file headers.

Some scripts contain hardcoded filter values (job name patterns, database names) — review and adjust for your environment before running.

## Scripts

### SOX

| Script | Scope | Description |
|--------|-------|-------------|
| `Server_Logins.sql` | Server | Server principals, roles, permissions, password policy settings |
| `Database_Roles.sql` | Database | Database principals in elevated roles across all databases |
| `Blank_Passwords.sql` | Server | SQL logins with blank passwords |
| `Auth_Mode.sql` | Server | Windows vs. mixed mode authentication check |
| `Backup_History.sql` | Server | Backup job history and schedules |
| `Agent_Job_Access.sql` | Server | Accounts with SQLAgentOperatorRole or sysadmin access to agent jobs |

### CIS

_TBD — add as scripts are organized_

## Notes

- Output may contain sensitive security information (SIDs, login names, role memberships). Do not commit query results to this repo.
- `sp_MSforeachdb` has been replaced with explicit cursor logic for reliability.

## License

MIT
