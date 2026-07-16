# Release 0.1.0

## Summary

AI Infrastructure Audit Tool `0.1.0` is a first release candidate with the following capabilities:

- Python CLI audit engine with configurable Linux/Windows checks
- Text, JSON, and Markdown reporting with summary risk scores
- Browser UI for running audits in a lightweight web app
- Real remote execution support via Paramiko SSH and WinRM for Windows
- Packaging for wheel and source distribution
- CI workflow to run tests and build artifacts automatically

## Artifacts

- `dist/ai_infrastructure_audit_tool-0.1.0-py3-none-any.whl`
- `dist/ai_infrastructure_audit_tool-0.1.0.tar.gz`

## Release commands

```bash
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

## Notes

- `README.md` includes install and run instructions.
- `CHANGELOG.md` documents the 0.1.0 feature set.
- `RELEASE.md` describes the publish checklist.
- `dist/` contains the generated wheel and sdist artifacts.

## Post-release

- Create a GitHub release and attach the artifacts from `dist/`.
- Optionally publish to PyPI or internal package index.
