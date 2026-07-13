# Audit Report

## Summary

- Total checks: 7
- High severity: 3
- Medium severity: 4
- Low severity: 0
- Risk score: 17

## Findings

### OS version and distribution verification
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: high
- Description: Verify the operating system version and distribution. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### SSH hardening review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: high
- Description: Validate SSH configuration hardening settings. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### Sudoers misconfiguration review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: high
- Description: Check for unsafe sudoers rules and NOPASSWD usage. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### World-writable files review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: medium
- Description: Identify world-writable files and directories that may be risky. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### Disk space and inode usage review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: medium
- Description: Check for low disk space and inode exhaustion risk. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### Service status review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: medium
- Description: Review critical services for unexpected disabled or failed states. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.

### Cron job integrity review
- Host: demo-host
- Platform: linux
- Status: passed
- Severity: medium
- Description: Inspect cron jobs for unusual or risky scheduled tasks. | remote output: ssh: Could not resolve hostname demo-host: No such host is known.
