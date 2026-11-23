# Release process

Release notes live in [CHANGELOG.md](CHANGELOG.md). The steps below turn the `Unreleased`
section into a versioned release.

## 1. Prepare

1. Pick the version number, e.g. `0.2.0`.
2. Set `version` in `pyproject.toml` (development builds use a `.devN` suffix, e.g. `0.2.0.dev0`).
3. In `CHANGELOG.md`, rename `## Unreleased` to `## <version> - <YYYY-MM-DD>` and check that it
   lists every user-visible change, including breaking changes.
4. Check that `README.md` and `INSTALL_AND_RUN.md` match the release (options, check list,
   install steps), and regenerate `sample_report.md` if the report format changed.

## 2. Verify

```bash
python -m pip install --upgrade pip build
python -m unittest discover            # all tests must pass
python -m build                        # writes the wheel and sdist to dist/
```

Install the wheel into a clean virtual environment and run it:

```bash
python -m venv /tmp/release-check && . /tmp/release-check/bin/activate
python -m pip install "dist/ai_infrastructure_audit_tool-<version>-py3-none-any.whl[web,ai]"
infra-audit --list-checks
infra-audit --format markdown            # audits the local machine
python -c "import audit_tool.web"        # the web UI imports from the installed package
```

## 3. Publish

```bash
git tag -a v<version> -m "Release <version>"
git push origin v<version>
```

Create a GitHub release for the tag, paste the version's `CHANGELOG.md` section as the release
notes, and attach the wheel and sdist from `dist/`. Optionally publish to PyPI or an internal
package index.

## 4. After the release

Bump `pyproject.toml` to the next development version (e.g. `0.3.0.dev0`) and add a new empty
`## Unreleased` section to `CHANGELOG.md`.
