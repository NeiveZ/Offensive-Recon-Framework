# ORFX — Offensive Recon Framework

**Modular reconnaissance framework for authorized security assessments.**

`Python 3.10+` · `Bash` · `Simple CLI` · `JSON / TXT / HTML`

> Designed for laboratories, internal environments, and assets that you own or are explicitly authorized to assess.

---

## About

**ORFX (Offensive Recon Framework)** is a lightweight Python/Bash reconnaissance toolkit designed to centralize common reconnaissance tasks behind a simple command-line interface.

Core capabilities include:

* Domain and subdomain discovery
* IPv4 and IPv6 resolution
* DNS enumeration
* HTTP/HTTPS probing
* Basic technology detection
* TLS and certificate inspection
* TCP port discovery
* Limited banner collection
* WHOIS lookups
* Result correlation
* Structured reporting

ORFX does **not** implement exploitation, credential attacks, persistence, or destructive actions.

---

## Requirements

Supported environments:

* Kali Linux
* Debian
* Ubuntu
* WSL2
* Other Linux systems with Python 3.10+ and Bash

Required:

```text
Python 3.10+
Bash
Network access
```

Recommended system tools:

```bash
sudo apt update
sudo apt install dnsutils whois -y
```

`nmap` is optional and may be used for independent validation.

---

## Installation

```bash
git clone https://github.com/NeiveZ/Offensive-Recon-Framework.git
cd Offensive-Recon-Framework

chmod +x orfx.sh

./orfx.sh --install
./orfx.sh --check
```

The installer creates an isolated Python environment in `.venv`.

---

## Quick Start

Display available commands:

```bash
./orfx.sh --help
```

Check the environment:

```bash
./orfx.sh --check
```

Run individual modules:

```bash
./orfx.sh dns -d example.com
./orfx.sh http -u https://example.com
./orfx.sh tls -d example.com
./orfx.sh subdomains -d example.com --resolve
./orfx.sh ports -t example.com --ports top100
./orfx.sh whois -d example.com
```

---

## Core Commands

### Subdomain Discovery

Discover subdomains using passive sources and wordlists:

```bash
./orfx.sh subdomains -d example.com --resolve
```

Available profiles:

```bash
./orfx.sh subdomains -d example.com --profile fast
./orfx.sh subdomains -d example.com --profile balanced
./orfx.sh subdomains -d example.com --profile accurate
```

### DNS Enumeration

```bash
./orfx.sh dns -d example.com
```

Select specific record types:

```bash
./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA,CAA
```

### HTTP / HTTPS Probing

```bash
./orfx.sh http -u https://example.com
```

Process multiple targets:

```bash
./orfx.sh http -i reports/example_subdomains.txt
```

The module collects information such as:

* HTTP status
* Final URL
* Response headers
* Basic technology fingerprints
* Security headers
* Connection errors

### TCP Port Discovery

Specific ports:

```bash
./orfx.sh ports -t example.com --ports 22,80,443,8080
```

Port range:

```bash
./orfx.sh ports -t example.com --ports 1-1024
```

Common ports:

```bash
./orfx.sh ports -t example.com --ports top100
```

### TLS Inspection

```bash
./orfx.sh tls -d example.com
```

The TLS module reports:

* TLS protocol
* Negotiated cipher
* Certificate information
* Issuer
* Expiration
* SANs
* Verification status

### WHOIS

```bash
./orfx.sh whois -d example.com
```

---

## Full Reconnaissance

The `full` command combines the main reconnaissance modules into a single workflow:

```bash
./orfx.sh full -d example.com --resolve
```

Include TCP port discovery:

```bash
./orfx.sh full -d example.com --resolve --ports top100
```

Pipeline:

```text
Target
  |
  +-- Subdomain Discovery
  |
  +-- DNS Enumeration
  |
  +-- HTTP/HTTPS Probing
  |
  +-- TLS Inspection
  |
  +-- Optional Port Discovery
  |
  +-- Correlation Engine
  |
  +-- Unified Report
```

`auto` is an alias for `full`:

```bash
./orfx.sh auto -d example.com
```

---

## User-Agent Control

ORFX allows the HTTP `User-Agent` to be explicitly defined or rotated.

Custom value:

```bash
./orfx.sh http -u https://example.com \
  --user-agent "Mozilla/5.0 (compatible; SecurityAssessment/3.2)"
```

Random rotation:

```bash
./orfx.sh http -u https://example.com --user-agent random
```

Custom User-Agent file:

```bash
./orfx.sh http -u https://example.com \
  --user-agent @/path/to/user-agents.txt
```

The feature modifies only the `User-Agent` header.

---

## Result Correlation

ORFX combines module output into a unified asset model containing:

```text
Target
Assets
DNS
Subdomains
HTTP Services
Open Ports
TLS Services
WHOIS
Findings
Errors
Summary
```

The correlation layer connects collected information without inventing additional findings.

---

## Reporting

ORFX supports:

```text
JSON
TXT
HTML
```

Example:

```bash
./orfx.sh full \
  -d example.com \
  --resolve \
  --json \
  --html \
  --out reports/example_full
```

Output:

```text
reports/example_full.json
reports/example_full.html
```

| Format | Purpose                                 |
| ------ | --------------------------------------- |
| JSON   | Automation and further processing       |
| TXT    | Quick review and archival               |
| HTML   | Browser-based analysis and presentation |

---

## Normalized Findings

Modules convert collected data into a common finding format:

```json
{
  "severity": "INFO",
  "target": "example.com",
  "check": "HTTP status",
  "detail": "200"
}
```

Severity levels:

```text
INFO
LOW
WARN
HIGH
ERROR
```

These classifications are intended for reporting and do not replace manual validation or specialized security scanners.

---

## Architecture

```text
ORFX/
├── orfx.py
├── orfx.sh
├── core/
├── modules/
├── utils/
├── tests/
├── config/
├── reports/
├── requirements.txt
├── SECURITY.md
├── ETHICS.md
├── CHANGELOG.md
└── README.md
```

Main components:

```text
core/       → correlation, pipeline and configuration
modules/    → DNS, HTTP, ports, subdomains, TLS and WHOIS
utils/      → utilities and session management
tests/      → automated tests
config/     → configuration files
reports/    → generated results
```

---

## Performance Controls

ORFX provides controlled concurrency, configurable timeouts, retries, and scanning profiles.

| Profile    | Threads | Timeout | Retries |
| ---------- | ------: | ------: | ------: |
| `fast`     |      30 |      2s |       1 |
| `balanced` |      15 |      3s |       2 |
| `accurate` |       5 |      5s |       3 |

Higher concurrency does not necessarily increase discovery accuracy. Coverage also depends on wordlists, retries, timeouts, DNS behavior, and network conditions.

---

## Testing

Tests are located in `tests/`.

Run them with:

```bash
python3 -m pytest -q
```

Coverage includes areas such as:

* Domain normalization
* Port parsing
* HTTP behavior
* TLS handling
* Result correlation

---

## Design Principles

### Simplicity

A single CLI provides access to the main reconnaissance workflows.

### Modularity

Each major reconnaissance function is implemented as an independent module.

### Traceability

Results and collection errors remain available in generated reports.

### Controlled Execution

Concurrency, timeouts, retries, and discovery depth remain configurable.

### Correlation

Results from multiple modules are presented as a unified asset model.

---

## Scope and Limitations

ORFX is a **reconnaissance framework**, not a complete offensive security platform.

It is not intended to replace:

* Full vulnerability scanners
* Exploitation frameworks
* Credential attack platforms
* Advanced web crawlers
* Specialized enterprise scanners

Its purpose is to provide a lightweight and organized workflow for discovery, enumeration, and correlation.

---

## Responsible Use

ORFX must only be used against:

* Systems you own
* Authorized laboratories
* Internal environments
* Assets for which you have explicit permission to perform security testing

The operator is responsible for ensuring that all activity remains within the authorized scope.

> Technical capability does not imply authorization.

---

## License

This project is distributed under the **MIT License**.

See [LICENSE](LICENSE) for the full license terms.

---

## Additional Documentation

```text
ETHICS.md
SECURITY.md
CHANGELOG.md
```
