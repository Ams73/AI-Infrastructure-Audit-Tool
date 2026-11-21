# Audit Report

- Target: demo-host (linux)
- Generated: 2026-11-21T19:09:12+00:00
- Risk score: 11 (sum of severity weights of failed checks)

## Summary

| Status | Count |
| --- | --- |
| pass | 1 |
| warn | 0 |
| fail | 4 |
| error | 0 |
| skipped | 3 |

Failed by severity: high 3, medium 1, low 0

## Findings requiring attention

### [FAIL] LNX-OS-001: OS version and distribution verification

- Host: demo-host (linux)
- Severity: high
- Checked: 2026-11-21T19:09:12+00:00
- Description: Identify the distribution and release and verify it still receives vendor security updates.
- Recommendation: Upgrade to a supported release of the distribution, or buy extended support (e.g. Ubuntu Pro, Debian ELTS, RHEL ELS) until the upgrade is done.

Evidence:

```
OS: Ubuntu 20.04.6 LTS
ID=ubuntu VERSION_ID=20.04
Kernel: 6.18.58.1-microsoft-standard-WSL2
FAIL: vendor security support ended on 2025-05-31 (540 days ago).
```

### [FAIL] LNX-SSH-001: SSH hardening review

- Host: demo-host (linux)
- Severity: high
- Checked: 2026-11-21T19:09:12+00:00
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
WARN: sshd_config uses Include directives that were not resolved; the effective configuration may differ. 'sshd -T' was unavailable (it needs root and the server's host keys).
```

### [FAIL] LNX-SUDO-001: Sudoers misconfiguration review

- Host: demo-host (linux)
- Severity: high
- Checked: 2026-11-21T19:09:12+00:00
- Description: Check sudoers for passwordless (NOPASSWD) rules and disabled authentication.
- Recommendation: Remove NOPASSWD from rules granting ALL commands and remove '!authenticate' defaults. Limit passwordless rules to specific commands for automation accounts and list those accounts in the allowed_nopasswd param. Edit with visudo.

Evidence:

```
Files reviewed: /etc/sudoers, /etc/sudoers.d/90-cloud-init-users, /etc/sudoers.d/deploy
FAIL: /etc/sudoers: authentication disabled: Defaults:backup	!authenticate
FAIL: /etc/sudoers.d/90-cloud-init-users: passwordless sudo for ALL commands: ubuntu ALL=(ALL) NOPASSWD:ALL
WARN: /etc/sudoers.d/deploy: passwordless sudo for specific commands: deploy	ALL=(root) NOPASSWD: /usr/bin/systemctl restart app,  	/usr/bin/systemctl status app
WARN: /etc/sudoers.d/deploy: passwordless sudo for specific commands: jenkins	ALL=(ALL) NOPASSWD: /usr/bin/ls, PASSWD: ALL
FAIL: /etc/sudoers.d/deploy: passwordless sudo for ALL commands: %ops	ALL=(ALL) NOPASSWD: SETENV: ALL
FAIL: /etc/sudoers.d/deploy: passwordless sudo for ALL commands: ansible	ALL=(ALL) NOPASSWD: ALL
WARN: could not read: /etc/sudoers.d/legacy (run as root)
```

### [FAIL] LNX-DISK-001: Disk space and inode usage review

- Host: demo-host (linux)
- Severity: medium
- Checked: 2026-11-21T19:09:12+00:00
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
| pass | LNX-ACCT-001 | Privileged and passwordless account review | high |
| skipped | LNX-CRON-001 | Cron job integrity review | medium |
| skipped | LNX-FS-001 | World-writable files review | medium |
| skipped | LNX-SVC-001 | Service status review | medium |
