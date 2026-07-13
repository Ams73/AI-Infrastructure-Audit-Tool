# Audit Report

## Summary

- Total checks: 7
- High severity: 3
- Medium severity: 4
- Low severity: 0
- Risk score: 17

## Findings

### OS version and distribution verification
- Host: localhost
- Platform: linux
- Status: passed
- Severity: high
- Description: Verify the operating system version and distribution. | remote output: ssh: connect to host localhost port 22: Connection refused

### SSH hardening review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: high
- Description: Validate SSH configuration hardening settings. | remote output: ssh: connect to host localhost port 22: Connection refused

### Sudoers misconfiguration review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: high
- Description: Check for unsafe sudoers rules and NOPASSWD usage. | remote output: ssh: connect to host localhost port 22: Connection refused

### World-writable files review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: medium
- Description: Identify world-writable files and directories that may be risky. | remote output: ssh: connect to host localhost port 22: Connection refused

### Disk space and inode usage review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: medium
- Description: Check for low disk space and inode exhaustion risk. | remote output: ssh: connect to host localhost port 22: Connection refused

### Service status review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: medium
- Description: Review critical services for unexpected disabled or failed states. | remote output: ssh: connect to host localhost port 22: Connection refused

### Cron job integrity review
- Host: localhost
- Platform: linux
- Status: passed
- Severity: medium
- Description: Inspect cron jobs for unusual or risky scheduled tasks. | remote output: ssh: connect to host localhost port 22: Connection refused

