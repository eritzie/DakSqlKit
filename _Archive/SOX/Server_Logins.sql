/*
    Server_Logins.sql
    Scope: Server
    Purpose: Enumerate all server principals with roles, permissions, 
             password policy settings, and disabled status.
    
    Usage: Run in SSMS against target instance. No database context required.
    Output: One row per principal/role/permission combination.
    
    Notes:
    - Filters out system principals (##MS_*, NT SERVICE\*, etc.)
    - Includes both SQL and Windows authentication principals
    - Role column uses CASE precedence — a login in multiple roles 
      will show only the highest-privilege role. Run the supplemental
      query at the bottom if you need all role memberships.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Server_Logins.sql';
PRINT '============================================';
PRINT ' ';

-- Primary query: Server principals with roles, permissions, and password policy
SELECT DISTINCT
    @@SERVERNAME AS [ServerName],
    a.[default_database_name] AS [DefaultDatabase],
    a.[sid] AS [SecurityID],
    a.[name] AS [LoginName],
    a.[type_desc] AS [LoginType],
    CASE 
        WHEN b.[sysadmin]      = 1 THEN 'SysAdmin'
        WHEN b.[securityadmin] = 1 THEN 'SecurityAdmin'
        WHEN b.[serveradmin]   = 1 THEN 'ServerAdmin'
        WHEN b.[setupadmin]    = 1 THEN 'SetupAdmin'
        WHEN b.[processadmin]  = 1 THEN 'ProcessAdmin'
        WHEN b.[diskadmin]     = 1 THEN 'DiskAdmin'
        WHEN b.[dbcreator]     = 1 THEN 'DBCreator'
        WHEN b.[bulkadmin]     = 1 THEN 'BulkAdmin'
        WHEN a.[type]          = 'R' THEN 'Role'
        ELSE 'Public'
    END AS [ServerRole],
    d.[permission_name] AS [Permission],
    d.[state_desc] AS [PermissionState],
    CASE a.[is_disabled] 
        WHEN 0 THEN 'No' 
        WHEN 1 THEN 'Yes' 
    END AS [Disabled],
    CASE c.[is_policy_checked] 
        WHEN 0 THEN 'No' 
        WHEN 1 THEN 'Yes' 
    END AS [EnforcePasswordPolicy],
    CASE c.[is_expiration_checked] 
        WHEN 0 THEN 'No' 
        WHEN 1 THEN 'Yes' 
    END AS [EnforcePasswordExpiration],
    a.[create_date] AS [CreateDate],
    a.[modify_date] AS [ModifyDate]
FROM 
    master.sys.server_principals a
    LEFT JOIN master..syslogins b ON a.[sid] = b.[sid]
    LEFT JOIN master.sys.sql_logins c ON a.[sid] = c.[sid]
    LEFT JOIN master.sys.server_permissions d ON a.[principal_id] = d.[grantee_principal_id]
WHERE
    a.[name] NOT LIKE '##%'
    AND a.[name] NOT LIKE 'NT SERVICE\%'
ORDER BY 
    [DefaultDatabase], [LoginName];