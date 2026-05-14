/*
    Server_Configuration.sql
    Scope: Server
    Purpose: Report all server configuration settings, flagging 
             non-default and pending-restart values.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Replaces individual sp_configure calls (remote access, 
      remote query timeout, remote login timeout, etc.).
    - PendingRestart = Yes means the value was changed but the 
      instance hasn't been restarted to pick it up.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Server_Configuration.sql';
PRINT '============================================';
PRINT ' ';

SELECT
    @@SERVERNAME AS [ServerName],
    [name] AS [Setting],
    [value] AS [ConfiguredValue],
    [value_in_use] AS [RunningValue],
    [minimum],
    [maximum],
    CASE WHEN [value] <> [value_in_use] THEN 'Yes' ELSE 'No' END AS [PendingRestart],
    [description]
FROM sys.configurations
ORDER BY [name];