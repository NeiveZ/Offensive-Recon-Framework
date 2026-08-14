# Changelog

## 3.1.0 — Maintenance release

- Restored visible module output during normal execution.
- Implemented the documented `full` workflow.
- Added passive subdomain discovery through crt.sh.
- Added `http -i` input-file workflow for discovered hosts.
- Added normalized terminal findings and consolidated reports.
- Added JSON, TXT and HTML report output.
- Improved environment validation with `./orfx.sh --check`.
- Added local `.venv` installation flow to avoid breaking system Python packages.
- Added graceful fallbacks when optional system tools are unavailable.
- Removed stale bytecode and backup artifacts from the release package.
- Updated README to match the implemented CLI.
