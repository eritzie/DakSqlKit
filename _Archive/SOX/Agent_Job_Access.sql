/*
    Agent_Job_Access.sql
    Scope: Server
    Purpose: Identify accounts and roles that can create, modify, 
             or execute SQL Agent jobs.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Covers msdb agent roles (SQLAgentOperatorRole, SQLAgentReaderRole, 
      SQLAgentUserRole) and sysadmin (which has implicit full agent access).
    - Auditors look for this to verify separation of duties — production 
      job changes should be restricted.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Agent_Job_Access.sql';
PRINT '============================================';
PRINT ' ';

-- ── msdb Agent Roles ──
SELECT
    @@SERVERNAME AS [ServerName],
    'Database' AS [Level],
    'msdb' AS [Database],
    dp.[name] AS [PrincipalName],
    dp.[type_desc] AS [PrincipalType],
    r.[name] AS [Role]
FROM msdb.sys.database_principals dp
INNER JOIN msdb.sys.database_role_members drm 
    ON dp.[principal_id] = drm.[member_principal_id]
INNER JOIN msdb.sys.database_principals r 
    ON drm.[role_principal_id] = r.[principal_id]
WHERE r.[name] IN ('SQLAgentOperatorRole', 'SQLAgentReaderRole', 'SQLAgentUserRole')
  AND dp.[name] NOT LIKE '##%'

UNION ALL

-- ── Sysadmins (implicit full agent access) ──
SELECT
    @@SERVERNAME AS [ServerName],
    'Server' AS [Level],
    sp.[default_database_name] AS [Database],
    sp.[name] AS [PrincipalName],
    sp.[type_desc] AS [PrincipalType],
    'sysadmin' AS [Role]
FROM master.sys.server_principals sp
INNER JOIN master..syslogins sl ON sp.[sid] = sl.[sid]
WHERE sl.[sysadmin] = 1
  AND sp.[name] NOT LIKE '##%'
  AND sp.[name] NOT LIKE 'NT SERVICE\%'

ORDER BY [Role], [PrincipalName];