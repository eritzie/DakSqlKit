/*
    Blank_Passwords.sql
    Scope: Server
    Purpose: Identify SQL authentication logins with blank passwords.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Checks both standard and case-insensitive password comparison.
    - Ideally this returns zero rows.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Blank_Passwords.sql';
PRINT '============================================';
PRINT ' ';

SELECT
    @@SERVERNAME AS [ServerName],
    [name] AS [LoginName],
    [type_desc] AS [LoginType],
    [is_disabled],
    [is_policy_checked],
    [create_date],
    [modify_date]
FROM sys.sql_logins
WHERE PWDCOMPARE('', password_hash) = 1
   OR PWDCOMPARE('', password_hash, 1) = 1
ORDER BY [name];