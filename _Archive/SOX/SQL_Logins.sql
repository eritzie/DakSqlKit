/*
    SQL_Logins.sql
    Scope: Server
    Purpose: List all SQL Server authentication logins with password 
             policy settings, lockout status, and last password change.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Returns only SQL authentication accounts (not Windows auth).
    - Filters out system certificate accounts (##MS_*).
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: SQL_Logins.sql';
PRINT '============================================';
PRINT ' ';

SELECT
    @@SERVERNAME AS [ServerName],
    [name],
    [principal_id],
    [type_desc],
    [is_disabled],
    [create_date],
    [modify_date],
    [default_database_name],
    [default_language_name],
    [is_policy_checked],
    [is_expiration_checked],
    [is_locked]
FROM sys.sql_logins
WHERE [name] NOT LIKE '##%'
ORDER BY [name];