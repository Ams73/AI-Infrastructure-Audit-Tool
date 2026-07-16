# Release checklist

## Pre-release
- Confirm the latest tests pass locally.
- Build the source and wheel distributions with `python -m build`.
- Review generated artifacts in `dist/`.
- Verify the package installs cleanly from the built wheel.

## Publish
- Upload `dist/ai_infrastructure_audit_tool-0.1.0-py3-none-any.whl` and `dist/ai_infrastructure_audit_tool-0.1.0.tar.gz` to your release host.
- Attach the generated artifacts to a GitHub release.
- Share the CLI and web UI usage examples from the README.
