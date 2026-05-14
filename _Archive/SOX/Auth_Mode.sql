/*
    Auth_Mode.sql
    Scope: Server
    Purpose: Report the SQL Server authentication mode 
             (Windows only vs. mixed mode).
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Mixed mode is a common audit finding. Most security frameworks 
      prefer Windows Authentication only.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Auth_Mode.sql';
PRINT '============================================';
PRINT ' ';

SELECT
    @@SERVERNAME AS [ServerName],
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication'
        WHEN 0 THEN 'Windows and SQL Server Authentication'
    END AS [AuthenticationMode];