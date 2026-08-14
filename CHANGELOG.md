# Changelog

## 3.2.4 — Clean CLI Presentation

### Improved
- Restored the compact ORFX wordmark from the original project CLI and removed the accidental `RECONTOOL` branding from the startup screen.
- Reduced the startup banner to tool name, version and a minimal separator.
- Removed repetitive capability, scope, mode and precision lines from normal module execution.
- Added a compact `Recon Configuration` table showing the command and relevant runtime parameters before a scan starts.
- Kept the live `Resolving candidates` progress bar and final subdomain result table as the primary visual output.
- Reduced subdomain source/profiling status noise and moved full runtime details into structured result data.
- Made `--check` concise while preserving its diagnostic purpose.


## 3.2.3 — Professional CLI Presentation

### Added
- Restored the original ORFX wordmark from the initial project release.
- Reworked the startup header into a consistent, portfolio-ready CLI identity.
- Version information is now passed dynamically into the banner so the displayed release cannot silently drift from `orfx.py`.

### Improved
- Cleaner command context before each module starts.
- More compact subdomain tables: multiple addresses are summarized instead of stretching the terminal horizontally.
- Full result fidelity is preserved in JSON/HTML/TXT reports even when the terminal uses a compact view.
- Updated HTTP and passive-discovery default User-Agent identifiers to 3.2.3.
- Presentation and wording were aligned across the CLI, README and release metadata.

## 3.2.2 — Controlled User-Agent Rotation

- Added explicit User-Agent modes: exact value, `random`/`rotate`, or `@path/to/file`.
- Added a conservative browser-style User-Agent pool for authorized HTTP reconnaissance.
- HTTP probing rotates the User-Agent per request when `random`/`rotate` is selected.
- Certificate-transparency requests can use the same User-Agent controls.
- `full` propagates the selected User-Agent mode to passive and HTTP stages.
- Documented User-Agent controls, precedence, and custom wordlist usage.

## 3.2.1 — 2026-08-14

### Added
- Polished ORFX startup banner and cleaner CLI presentation.
- `--details` global flag for opt-in normalized findings.
- Subdomain scan profiles: `fast`, `balanced`, `accurate`.
- Subdomain `--retries` and `--delay` controls.

### Improved
- Default subdomain concurrency reduced to prioritize reliability over raw speed.
- Multi-label entries such as `dev.api` are preserved in custom wordlists.
- Subdomain candidates can now include nested host labels correctly.
- Retry behavior reduces transient resolver misses.
- Terminal output avoids printing large normalized-finding tables twice.
- README explains the relationship between coverage, concurrency, timeout, retries and precision.

## 3.2.0 — 2026-08-14

### Added
- TLS module and IPv4/IPv6 support.
- Correlation engine and integrated `full`/`auto` pipeline.
- Expanded diagnostics, reporting, and test coverage.
