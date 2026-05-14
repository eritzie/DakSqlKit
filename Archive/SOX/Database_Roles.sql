/*
    Database_Roles.sql
    Scope: All databases on the instance
    Purpose: Enumerate database principals and their role memberships 
             across all online databases.
    
    Usage: Run in SSMS against target instance. No database context required.
    
    Notes:
    - Uses a cursor over sys.databases instead of sp_MSforeachdb for reliability.
    - Skips offline, restoring, and snapshot databases.
    - Returns all role memberships, not just elevated roles. Filter in 
      the workbook if your auditor only wants specific roles.
*/

SET NOCOUNT ON;

PRINT '============================================';
PRINT 'Server: ' + @@SERVERNAME;
PRINT 'Run Date: ' + CONVERT(varchar, GETDATE(), 120);
PRINT 'Script: Database_Roles.sql';
PRINT '============================================';
PRINT ' ';

CREATE TABLE #DatabaseRoles (
    [ServerName]    sysname,
    [Database]      sysname,
    [PrincipalName] sysname,
    [PrincipalType] nvarchar(60),
    [RoleName]      sysname NULL,
    [CreateDate]    datetime,
    [ModifyDate]    datetime
);

DECLARE @dbName sysname;
DECLARE @sql nvarchar(MAX);

DECLARE db_cursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT [name] 
    FROM sys.databases 
    WHERE [state] = 0                -- Online only
      AND [is_read_only] = 0         -- Skip read-only
      AND [source_database_id] IS NULL -- Skip snapshots
    ORDER BY [name];

OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @dbName;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'
        INSERT INTO #DatabaseRoles
        SELECT
            @@SERVERNAME,
            ''' + QUOTENAME(@dbName) + ''',
            dp.[name],
            dp.[type_desc],
            r.[name],
            dp.[create_date],
            dp.[modify_date]
        FROM ' + QUOTENAME(@dbName) + '.sys.database_principals dp
        LEFT JOIN ' + QUOTENAME(@dbName) + '.sys.database_role_members drm 
            ON dp.[principal_id] = drm.[member_principal_id]
        LEFT JOIN ' + QUOTENAME(@dbName) + '.sys.database_principals r 
            ON drm.[role_principal_id] = r.[principal_id]
        WHERE dp.[type] IN (''S'', ''U'', ''G'', ''A'', ''K'')
          AND dp.[name] NOT IN (''dbo'', ''guest'', ''INFORMATION_SCHEMA'', ''sys'')
          AND dp.[name] NOT LIKE ''##%''';

    BEGIN TRY
        EXEC sp_executesql @sql;
    END TRY
    BEGIN CATCH
        PRINT 'Warning: Could not query database ' + QUOTENAME(@dbName) + ': ' + ERROR_MESSAGE();
    END CATCH

    FETCH NEXT FROM db_cursor INTO @dbName;
END

CLOSE db_cursor;
DEALLOCATE db_cursor;

SELECT 
    [ServerName],
    [Database],
    [PrincipalName],
    [PrincipalType],
    [RoleName],
    [CreateDate],
    [ModifyDate]
FROM #DatabaseRoles
ORDER BY [Database], [RoleName], [PrincipalName];

DROP TABLE #DatabaseRoles;