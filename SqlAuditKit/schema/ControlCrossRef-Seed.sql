/*
    ControlCrossRef-Seed.sql
    Pre-maps overlapping controls across audit frameworks.
    Run after Create-AuditDatabase.sql.

    ControlGroup identifies the underlying security concern.
    Each row names the framework's specific check that addresses it.
    A single ControlGroup with rows from multiple frameworks means
    those checks are testing the same thing — useful for deduplication
    in combined reports and for gap analysis (frameworks that lack coverage).
*/

USE [AuditKit];
GO

SET NOCOUNT ON;

-- Clear and reseed
TRUNCATE TABLE dbo.ControlCrossRef;

INSERT INTO dbo.ControlCrossRef (ControlGroup, Framework, CheckId, CheckName, Notes)
VALUES

-- ── Authentication Mode ───────────────────────────────────────────────────────
('Authentication Mode', 'CIS',  '3.1',      'Windows Authentication Mode',      'CIS requires Windows-only'),
('Authentication Mode', 'SOX',  'SOX-AC-05', 'Authentication Mode',              'SOX requires documented auth mode'),

-- ── sa Account ───────────────────────────────────────────────────────────────
('sa Account',          'CIS',  '2.13',     'sa Login Disabled',                NULL),
('sa Account',          'CIS',  '2.14',     'sa Login Renamed',                 NULL),
('sa Account',          'CIS',  '2.16',     "No Active 'sa' Login",             NULL),

-- ── Password Policy ───────────────────────────────────────────────────────────
('Password Policy',     'CIS',  '4.2',      'Sysadmin CHECK_EXPIRATION',        'CIS scopes to sysadmin logins'),
('Password Policy',     'CIS',  '4.3',      'CHECK_POLICY Enabled',             'CIS applies to all enabled SQL logins'),
('Password Policy',     'SOX',  'SOX-AC-04', 'Password Policy Enforcement',     'SOX applies to all SQL logins'),

-- ── SYSADMIN Membership ───────────────────────────────────────────────────────
('SYSADMIN Membership', 'CIS',  '3.12',     'SYSADMIN Membership',              'CIS flags count > 2'),
('SYSADMIN Membership', 'SOX',  'SOX-AC-01', 'Server Role Membership',          'SOX enumerates all sysadmin/securityadmin members'),

-- ── Orphaned Users ────────────────────────────────────────────────────────────
('Orphaned Users',      'CIS',  '3.3',      'Orphaned Database Users',          NULL),
('Orphaned Users',      'SOX',  'SOX-AC-03', 'Orphaned Users',                  NULL),

-- ── SQL Server Audit Object ───────────────────────────────────────────────────
('SQL Server Audit',    'CIS',  '5.4',      'SQL Server Audit Configured',      'CIS checks existence and enabled state'),
('SQL Server Audit',    'SOX',  'SOX-AU-01', 'SQL Server Audit Existence',      'SOX checks existence, state, and specification'),

-- ── Login Audit Level ─────────────────────────────────────────────────────────
('Login Audit Level',   'CIS',  '5.3',      'Login Audit Level',                NULL),
('Login Audit Level',   'SOX',  'SOX-AU-02', 'Login Audit Level',               NULL),

-- ── Agent Proxy Access ────────────────────────────────────────────────────────
('Agent Proxy Access',  'CIS',  '3.11',     'Agent Proxy Public Access',        'CIS checks public role exposure'),
('Agent Proxy Access',  'SOX',  'SOX-OP-02', 'Agent Job Ownership and Proxies', 'SOX checks all proxy accounts and job owners'),

-- ── Surface Area — sp_configure ───────────────────────────────────────────────
('xp_cmdshell',         'CIS',  '2.x',      'xp_cmdshell (additional)',         'Not in 2022 benchmark; retained as best practice'),
('Ad Hoc Queries',      'CIS',  '2.1',      'Ad Hoc Distributed Queries',       NULL),
('CLR Integration',     'CIS',  '2.2',      'CLR Integration',                  NULL),
('CLR Integration',     'CIS',  '2.17',     'CLR Strict Security',              NULL),
('OLE Automation',      'CIS',  '2.5',      'OLE Automation Procedures',        NULL),

-- ── Encryption ────────────────────────────────────────────────────────────────
('Backup Encryption',   'CIS',  '7.3',      'Backup Encryption',                NULL),
('Network Encryption',  'CIS',  '7.4',      'Network Encryption',               NULL),
('TDE',                 'CIS',  '7.5',      'Transparent Data Encryption',      'CIS is informational/Warning only'),

-- ── Database Role — db_owner ─────────────────────────────────────────────────
('db_owner Membership', 'CIS',  '3.13',     'msdb Admin Role Members',          'CIS scopes to msdb sensitive roles'),
('db_owner Membership', 'SOX',  'SOX-AC-02', 'Database Role Membership',        'SOX enumerates db_owner across all databases'),

-- ── Linked Servers ────────────────────────────────────────────────────────────
('Linked Servers',      'SOX',  'SOX-OP-01', 'Linked Server Configuration',     'No CIS equivalent; SOX-specific access path review'),

-- ── ALTER ANY SERVER AUDIT ────────────────────────────────────────────────────
('Audit Config Permission', 'SOX', 'SOX-AU-03', 'ALTER ANY SERVER AUDIT Permission', 'No direct CIS equivalent');

GO

PRINT 'ControlCrossRef seeded — ' + CAST(@@ROWCOUNT AS VARCHAR) + ' rows.';
