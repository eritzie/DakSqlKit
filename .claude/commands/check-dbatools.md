# Check dbatools Before Writing SQL Server PowerShell

Before writing any function or script that interacts with SQL Server, Windows
services, OS-level settings, or Active Directory in a SQL Server context:

1. Search the dbatools repository for an existing cmdlet that covers the requirement:
   - Browse https://docs.dbatools.io or search https://github.com/dataplat/dbatools
   - Use the GitHub code search: https://github.com/dataplat/dbatools/search?q=<keyword>
   - Check the commands browser: https://dbatools.io/commands

2. If a dbatools cmdlet exists:
   - Use it. Do not write a custom implementation.
   - Follow all splat/parameter rules in CLAUDE.md

3. If no dbatools cmdlet exists:
   - State explicitly: "No dbatools cmdlet found for [task]"
   - Then write the custom implementation using dbatools for any SQL connectivity
     it needs, and native PowerShell for the gap (e.g. Get-LocalGroupMember)

4. Never use Invoke-Sqlcmd regardless of whether a dbatools equivalent is found.