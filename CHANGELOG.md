# Changelog

## Unreleased

Version `0.2.0.dev0`. This release replaces the placeholder checks of 0.1.0 with real ones, so
upgrading is strongly recommended. It contains breaking changes to the CLI, config format and
report schema.

### Breaking changes

- `--host` other than `localhost` now requires `--platform` (or `--transport`).
- Config files use per-check overrides keyed by check ID; the 0.1.0 list format is rejected.
  See `sample_config.json`.
- Report JSON: `summary.score` is now `summary.risk_score`; findings gained `check_id`,
  `evidence`, `recommendation`, `timestamp` and `accounts`; statuses are `pass`, `warn`,
  `fail`, `error` and `skipped` instead of `passed`.
- The web UI needs `AUDIT_WEB_USERNAME`, `AUDIT_WEB_PASSWORD` and `AUDIT_WEB_TARGETS`.

### Added

- Ten real checks that run commands and evaluate their output:
  - Linux: OS release support/EOL (`LNX-OS-001`), UID 0 and empty-password accounts
    (`LNX-ACCT-001`), SSH hardening (`LNX-SSH-001`), sudoers NOPASSWD rules (`LNX-SUDO-001`),
    disk and inode usage (`LNX-DISK-001`).
  - Windows: patch currency (`WIN-UPD-001`), Administrators group and passwordless accounts
    (`WIN-ADM-001`), firewall profiles (`WIN-FW-001`), Microsoft Defender (`WIN-DEF-001`),
    BitLocker (`WIN-BL-001`).
  - Other planned checks report `skipped` until implemented.
- Optional AI summary (`--ai-summary`, `[ai]` extra): an executive summary, overall risk and
  prioritized remediation plan written by Claude, marked as AI-generated. Findings are redacted
  first (host names, addresses, SIDs, account names, secrets); `--ai-dry-run` shows exactly
  what would be sent. AI failures never change the report or exit code.
- Executors for local, SSH and WinRM (PowerShell) targets, with one session per host.
- CLI exit codes (0 clean, 1 failures, 2 usage/config error, 3 incomplete), `--fail-on`,
  `--list-checks`, `--timeout`, `-v`.
- Strict config validation: unknown check IDs, keys and parameters are errors.
- Errors caused by missing privileges include a hint to run as root/Administrator.
- `requirements_ai.txt`, and `[web]`/`[ai]` extras in `pyproject.toml`.

### Changed

- Connection, command and parsing failures are reported as `error`, never as passed.
- The risk score counts failed checks only, so a clean host scores 0.
- Reports list the findings that need attention first, with evidence and recommendations.
- The disk check ignores read-only mounts, which are full by design.
- CI installs the package with its extras and actually runs the tests.

### Security

- SSH host keys are verified against `known_hosts`; unknown hosts are rejected unless
  `--accept-unknown-host-keys` is given.
- WinRM uses NTLM by default with certificate validation; Basic auth over HTTP is refused.
- Passwords are read only from `AUDIT_PASSWORD`, and local check commands do not inherit it.
- Web UI: HTTP Basic login (locked until configured), targets restricted to
  `AUDIT_WEB_TARGETS`, anti-CSRF token, security headers, one audit at a time, API docs off,
  and all output HTML-escaped.

### Fixed

- `python -m unittest discover` ran 0 tests, so CI never tested anything.

### Removed

- Placeholder fallbacks that returned fake command output.
- `homepage.html`, `GITHUB_RELEASE.md`, `RELEASE_NOTE.md` (merged into `RELEASE.md` and this
  file) and committed test and pip log files.

## 0.1.0 - 2026-07-16

- Added a Python audit engine with CLI and browser UI
- Export reports in text, JSON, and Markdown with score summaries
- Added configurable check definitions and a reusable registry
- Added remote execution support via Paramiko SSH and WinRM
- Added packaging metadata, wheel and source distribution builds
- Added CI workflow for tests and package build automation

Known issues, found after release: checks did not inspect the target and always reported
`passed`, including when the host was unreachable; the CI test step ran no tests; and the web
UI had no authentication. Do not rely on 0.1.0 results.
