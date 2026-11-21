# Audit Report

- Target: demo-host (linux)
- Generated: 2026-11-21T19:00:02+00:00
- Risk score: 5 (sum of severity weights of failed checks)

## Summary

| Status | Count |
| --- | --- |
| pass | 0 |
| warn | 0 |
| fail | 2 |
| error | 0 |
| skipped | 5 |

Failed by severity: high 1, medium 1, low 0

## Findings requiring attention

### [FAIL] LNX-SSH-001: SSH hardening review

- Host: demo-host (linux)
- Severity: high
- Checked: 2026-11-21T19:00:02+00:00
- Description: Validate SSH daemon settings for root login, password and empty-password authentication.
- Recommendation: In /etc/ssh/sshd_config set 'PermitRootLogin no', 'PasswordAuthentication no' and 'PermitEmptyPasswords no', make sure key-based access works, then reload sshd.

Evidence:

```
Source: /etc/ssh/sshd_config
permitrootlogin = yes
passwordauthentication = yes (default)
permitemptypasswords = no
FAIL: PermitRootLogin allows root to log in with a password.
FAIL: PasswordAuthentication is enabled.
WARN: sshd_config uses Include directives that were not resolved; the effective configuration may differ. Run the audit as root so 'sshd -T' can be used.
```

### [FAIL] LNX-DISK-001: Disk space and inode usage review

- Host: demo-host (linux)
- Severity: medium
- Checked: 2026-11-21T19:00:02+00:00
- Description: Check persistent filesystems for low free space and inode exhaustion.
- Recommendation: Free space or extend the flagged filesystems, review log rotation, and set up monitoring alerts below the failure threshold.

Evidence:

```
Thresholds: warn at 80%, fail at 90%
/ space: 95% used  <-- FAIL
/var space: 84% used  <-- WARN
/ inodes: 11% used
/var inodes: 95% used  <-- FAIL
```

## Other checks

| Status | ID | Check | Severity |
| --- | --- | --- | --- |
| skipped | LNX-OS-001 | OS version and distribution verification | high |
| skipped | LNX-SUDO-001 | Sudoers misconfiguration review | high |
| skipped | LNX-CRON-001 | Cron job integrity review | medium |
| skipped | LNX-FS-001 | World-writable files review | medium |
| skipped | LNX-SVC-001 | Service status review | medium |
