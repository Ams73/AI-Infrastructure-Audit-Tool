# AI Infrastructure Audit Tool Plan

## Objective
Build an AI-powered infrastructure audit tool that runs 30+ audit checks on Linux servers and 30+ audit checks on Windows servers, collects findings, and produces a structured report for security, compliance, and operational health.

## Scope
- Support audit checks for Linux servers
- Support audit checks for Windows servers
- Run 60 checks total across both platforms
- Generate a human-readable and machine-readable report
- Provide extensibility for future checks and integrations

## Proposed Architecture
1. Core engine
   - Command-line interface for target selection and output format
   - Configuration file for audit rules, targets, and thresholds
   - Execution orchestrator to run checks in a consistent sequence

2. Platform adapters
   - Linux adapter for commands such as package inspection, service status, filesystem permissions, SSH config, and kernel settings
   - Windows adapter for PowerShell-based checks such as OS version, service state, firewall config, patch status, and account policies

3. Audit rule framework
   - Each check defined as an independent module with:
     - name
     - platform support
     - severity
     - description
     - execution logic
     - expected result
   - Standard output schema for findings

4. Reporting layer
   - Console summary output
   - Markdown or HTML report
   - JSON export for automation and downstream processing

## Audit Check Plan
The tool should aim to cover 60 checks distributed as follows:
- 30+ Linux checks
- 30+ Windows checks

### Linux checks
1. OS version and distribution verification
2. Critical package updates status
3. Unused or vulnerable packages review
4. Root login disabled
5. SSH password authentication disabled
6. SSH key-based authentication enforced
7. Firewall status review
8. Open ports inventory
9. Sudoers misconfiguration check
10. Service status review for critical services
11. File permission issues on sensitive paths
12. World-writable files or directories check
13. Kernel hardening settings review
14. Failed login attempt monitoring status
15. Log integrity and retention review
16. Disk space usage and alert threshold review
17. Temporary directory permissions review
18. Cron job integrity check
19. Network interface configuration review
20. DNS resolver configuration review
21. SELinux or AppArmor enforcement review
22. Time synchronization status review
23. Swap configuration review
24. Mounted filesystem security review
25. Process accounting and auditd status review
26. Anonymous FTP or insecure services review
27. User account password aging review
28. Home directory ownership review
29. Systemd service unit security review
30. Backup and recovery configuration review

### Windows checks
1. Operating system version and support status
2. Pending security updates review
3. Windows Defender status
4. Firewall profile status
5. Local administrator account review
6. Password policy compliance
7. Account lockout policy review
8. Enabled services and startup type review
9. SMB and remote access configuration review
10. Event log size and retention review
11. BitLocker protection status
12. Scheduled tasks review for suspicious entries
13. Remote desktop configuration review
14. PowerShell execution policy review
15. Critical patch and hotfix inventory review
16. User account privilege review
17. Audit policy configuration review
18. Driver signing enforcement review
19. LAPS or local password management review
20. Optional features and deprecated services review
21. Antivirus definition status review
22. Network adapter binding and DNS review
23. RDP certificate and listener review
24. Recovery partition and backup policy review
25. Startup program inventory review
26. TLS/SSL configuration review
27. Remote management and WinRM review
28. Credential guard or virtualization-based security review
29. Group policy compliance review
30. Application control and allow-list policy review

#### Critical additions from MyChecks.txt
- Linux: uptime and last reboot reason review
- Linux: accounts with UID 0 or empty passwords review
- Linux: sudoers misconfiguration and NOPASSWD rule review
- Windows: uptime and last reboot reason review
- Windows: local accounts with empty passwords and high-privilege exposure review
- Windows: local administrator group and delegated privilege review

## Implementation Phases
### Phase 1: Foundation
- Create project structure
- Define configuration schema
- Implement CLI entry points
- Add logging and error handling

### Phase 2: Core audit engine
- Build execution framework
- Implement platform detection
- Add results aggregation and scoring

### Phase 3: Check library
- Implement the first 15 Linux and 15 Windows checks
- Validate outputs against sample servers

### Phase 4: Expansion
- Implement remaining 15 Linux and 15 Windows checks
- Add reporting and export support

### Phase 5: Hardening and packaging
- Add test coverage
- Improve performance and resilience
- Package for deployment in enterprise environments

## Data Model
Each audit finding should include:
- host name
- platform
- check name
- severity
- status
- description
- evidence
- recommendation
- timestamp

## Output Formats
- Console: summary table and detailed findings
- Markdown: executive and technical report
- JSON: structured results for automation

## Success Criteria
- The tool can run against Linux and Windows targets
- All 60 checks are implemented and executed
- Results are clearly categorized by severity
- Reports are generated in multiple formats
- Tool is easy to extend with additional checks

## Next Steps
1. Define the initial project structure
2. Choose the implementation language and runtime
3. Create the first set of checks for one Linux and one Windows target
4. Validate output format and reporting
