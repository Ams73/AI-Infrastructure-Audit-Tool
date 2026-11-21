# Changelog

## Unreleased

Breaking changes to the CLI, config format and report schema.

- Added checks: OS release support/EOL (`LNX-OS-001`), UID 0 and empty-password accounts
  (`LNX-ACCT-001`), sudoers NOPASSWD rules (`LNX-SUDO-001`), Administrators group and
  passwordless accounts (`WIN-ADM-001`), patch currency (`WIN-UPD-001`), BitLocker (`WIN-BL-001`).
- Disk check ignores read-only mounts, which are full by design.
- Errors caused by missing privileges include a hint to run as root/Administrator.

- Checks now run real commands and evaluate their output. Implemented: SSH hardening
  (`LNX-SSH-001`), disk/inode usage (`LNX-DISK-001`), firewall profiles (`WIN-FW-001`),
  Microsoft Defender status (`WIN-DEF-001`). Other checks report `skipped` instead of `passed`.
- New statuses `pass`, `warn`, `fail`, `error`, `skipped`. Connection and command failures are
  reported as `error`, never as passed.
- Findings include check ID, evidence, recommendation and timestamp.
- Risk score counts failed checks only.
- CLI exit codes: 0 clean, 1 failures, 2 usage/config error, 3 incomplete.
- New executors: local, SSH (one reused session, known_hosts enforced) and WinRM (PowerShell,
  NTLM by default, certificate validation). Removed the placeholder fallbacks.
- Config is now per-check overrides keyed by check ID, with strict validation.
- Web UI escapes user input and uses the same execution path as the CLI.
- Tests are discovered by `python -m unittest discover` (previously 0 tests ran in CI).

## 0.1.0 - 2026-07-16

- Added a Python audit engine with CLI and browser UI
- Export reports in text, JSON, and Markdown with score summaries
- Added configurable check definitions and a reusable registry
- Added real remote execution support via Paramiko SSH and WinRM
- Added packaging metadata, wheel and source distribution builds
- Added CI workflow for tests and package build automation
