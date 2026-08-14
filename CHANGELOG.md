# Changelog

## 3.2.0 — Robust Recon Pipeline

### Added
- TLS/SSL inspection module with certificate, protocol, cipher and expiry details.
- IPv4 and IPv6 resolution in subdomain and port discovery.
- Correlation engine that consolidates module results into a unified asset model.
- End-to-end `full` pipeline with optional HTTP, TLS and port stages.
- `auto` alias for the standard `full` workflow.
- Expanded `--check` environment and module validation.
- Automated unit tests under `tests/`.
- Structured JSON, TXT and HTML reports with summary data and raw results.

### Improved
- HTTP probing now reports valid HTTP error responses instead of treating them as empty results.
- DNS fallback now supports A and AAAA when `dig` is unavailable.
- Port discovery accepts hostnames and IPv4/IPv6 targets.
- Error messages now preserve the reason a module could not produce data.
- CLI output is immediate and does not require `--verbose`.
- README documents all behavior, limitations and workflows.

### Safety
- ORFX remains a reconnaissance framework and does not implement exploitation.
- `full` does not enable port scanning unless the user explicitly requests it.
