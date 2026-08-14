# ORFX — Offensive Recon Framework

> A focused command-line reconnaissance framework for authorized security assessments, laboratories, internal environments, and assets you own or are explicitly permitted to test.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Version](https://img.shields.io/badge/ORFX-3.2.0-00AEEF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

## 1. What is ORFX?

ORFX (Offensive Recon Framework) is a lightweight Python/Bash reconnaissance toolkit designed around one principle: **keep the command line simple while the framework handles the complexity internally**.

The project focuses on the early stages of an authorized assessment:

- identifying domains and subdomains;
- resolving IPv4 and IPv6 addresses;
- enumerating DNS records;
- probing HTTP/HTTPS services;
- identifying basic technologies from service responses;
- inspecting TLS certificates and protocol information;
- discovering TCP ports and collecting limited banners;
- querying WHOIS information;
- correlating results into a single asset model;
- generating structured JSON, TXT and HTML reports.

ORFX does **not** implement exploitation, credential attacks, persistence, or destructive actions.

> **Authorization is required.** Only use ORFX against systems you own or have explicit permission to assess. The ability to send a request does not imply authorization to send it.

---

## 2. What changed in ORFX 3.2.0?

Version 3.2.0 is a robustness release focused on making the framework more useful without making its commands harder to remember.

### New capabilities

- TLS/SSL inspection through the new `tls` module.
- IPv4 and IPv6 support in DNS, subdomain resolution and TCP port discovery.
- A correlation engine that converts independent module output into one unified asset model.
- A real end-to-end `full` reconnaissance pipeline.
- `auto` as a short alias for `full`.
- More explicit errors instead of silently discarding failures.
- Expanded environment verification through `--check`.
- Automated tests under `tests/`.
- Richer JSON/TXT/HTML reports containing normalized findings plus raw module results.

### Behavior improvements

The terminal is now the primary interface again. A normal command immediately prints the module's progress and findings. `--verbose` is no longer required to make results visible.

The framework also distinguishes between three different situations:

1. **A result was found.**
2. **The target responded but a particular security/header check was missing.**
3. **A module could not collect data because of DNS, timeout, missing tooling, network or certificate problems.**

This distinction is important because an unavailable service should not look like an empty scan.

---

## 3. Requirements

### Supported systems

ORFX is designed for:

- Kali Linux;
- Debian;
- Ubuntu;
- WSL2 Linux distributions with normal network access;
- other Linux systems with Python 3.10+ and Bash.

### Required

- Python 3.10 or newer;
- Bash;
- normal network access for network-based modules.

### Recommended system tools

```bash
sudo apt update
sudo apt install dnsutils whois -y
```

`nmap` is optional and is **not required by ORFX's Python port scanner**. It can still be useful on an assessment workstation for independent validation.

---

## 4. Installation

Clone the repository:

```bash
git clone https://github.com/NeiveZ/Offensive-Recon-Framework.git
cd Offensive-Recon-Framework
```

Make the launcher executable:

```bash
chmod +x orfx.sh
```

Create the isolated Python environment:

```bash
./orfx.sh --install
```

Run the environment check:

```bash
./orfx.sh --check
```

The installer creates a local `.venv` directory. ORFX does not require `pip --break-system-packages`.

---

## 5. First run

Show the command list:

```bash
./orfx.sh --help
```

Show command-specific options:

```bash
./orfx.sh subdomains --help
./orfx.sh dns --help
./orfx.sh http --help
./orfx.sh ports --help
./orfx.sh tls --help
./orfx.sh whois --help
```

Recommended first validation against an authorized domain:

```bash
./orfx.sh dns -d example.com
./orfx.sh http -u https://example.com
./orfx.sh tls -d example.com
./orfx.sh subdomains -d example.com --resolve
```

---

## 6. Command reference

### 6.1 `subdomains`

Discovers subdomains from certificate-transparency data and an active wordlist, then optionally resolves them.

Basic:

```bash
./orfx.sh subdomains -d example.com
```

Resolve discovered names:

```bash
./orfx.sh subdomains -d example.com --resolve
```

Use a custom wordlist:

```bash
./orfx.sh subdomains -d example.com --wordlist /path/to/subdomains.txt --threads 50
```

Disable the passive source:

```bash
./orfx.sh subdomains -d example.com --active
```

The result model contains:

- passive names discovered;
- active candidates;
- resolved IPv4 addresses;
- resolved IPv6 addresses;
- total candidate count;
- total resolved count.

The framework deduplicates names before resolution.

#### Important behavior

Active wordlist candidates are resolved by default because that is the purpose of the active stage. Passive names are only resolved when `--resolve` is supplied.

A failure to contact `crt.sh` does **not** abort the command. ORFX reports the passive-source failure and continues with active DNS enumeration.

---

### 6.2 `dns`

Enumerates DNS records.

```bash
./orfx.sh dns -d example.com
```

Selected record types:

```bash
./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA,CAA
```

Use a specific resolver when `dig` is installed:

```bash
./orfx.sh dns -d example.com --records A,AAAA --server 1.1.1.1
```

Supported types:

```text
A
AAAA
CNAME
MX
NS
TXT
SOA
PTR
SRV
CAA
```

`dig` is preferred because it provides the richest record coverage and resolver control.

When `dig` is unavailable, ORFX provides a Python fallback for A and AAAA lookups. In that case, advanced record types may legitimately be unavailable.

This limitation is reported explicitly rather than producing a misleading empty result.

---

### 6.3 `http`

HTTP/HTTPS probing is designed to provide useful reconnaissance data while treating HTTP error responses as valid responses.

Basic HTTPS:

```bash
./orfx.sh http -u https://example.com
```

Automatic HTTPS → HTTP fallback:

```bash
./orfx.sh http -u example.com
```

Probe a file of targets:

```bash
./orfx.sh http -i reports/example_subdomains.txt
```

Useful options include:

```text
--scheme auto|http|https
--fallback true|false
--follow true|false
--timeout SECONDS
--user-agent STRING
```

The module reports:

- status code;
- final URL after redirects;
- response headers;
- basic technology fingerprints;
- security-header presence;
- connection and fallback errors.

A `403`, `404`, `401`, or other HTTP status is still a valid HTTP result. ORFX does not throw away the response simply because the status is not `200`.

---

### 6.4 `ports`

Performs TCP connection-based discovery.

Specific ports:

```bash
./orfx.sh ports -t example.com --ports 22,80,443,8080
```

Port range:

```bash
./orfx.sh ports -t example.com --ports 1-1024
```

Built-in common set:

```bash
./orfx.sh ports -t example.com --ports top100
```

Banner collection can be disabled:

```bash
./orfx.sh ports -t example.com --ports top100 --banners false
```

The scanner resolves the target using both address families and can test IPv4 and IPv6 addresses where the local system supports them.

The result contains:

- target;
- resolved IPv4 addresses;
- resolved IPv6 addresses;
- open ports;
- service labels;
- limited response banners where available.

The scanner is intentionally lightweight. It is not intended to replace a full service/version scanner.

---

### 6.5 `tls`

The TLS module inspects a TLS service without performing exploitation.

```bash
./orfx.sh tls -d example.com
```

Specific port:

```bash
./orfx.sh tls -d example.com --port 443
```

The module reports:

- negotiated TLS protocol;
- negotiated cipher;
- cipher strength when exposed by Python's TLS stack;
- certificate subject;
- certificate issuer;
- certificate expiration;
- remaining validity in days;
- certificate SANs;
- certificate verification result.

An expiration warning is produced when a certificate has 30 days or less remaining.

An expired certificate is represented as a high-severity finding in the normalized output.

---

### 6.6 `whois`

Basic WHOIS lookup:

```bash
./orfx.sh whois -d example.com
```

The framework prefers the local `whois` client. If it is unavailable, ORFX can use the optional `python-whois` dependency.

Depending on the registry, fields can include:

- domain;
- registrar;
- creation date;
- expiration date;
- updated date;
- name servers;
- organization;
- country;
- DNSSEC information.

WHOIS availability and field names vary by registry. Missing fields are not treated as framework failures.

---

## 7. Full reconnaissance pipeline

The `full` command is the main integrated workflow.

Basic:

```bash
./orfx.sh full -d example.com
```

Resolve passive subdomains as part of the workflow:

```bash
./orfx.sh full -d example.com --resolve
```

Disable HTTP or TLS stages when you only need DNS-oriented collection:

```bash
./orfx.sh full -d example.com --no-http --no-tls
```

Explicitly add a TCP port stage:

```bash
./orfx.sh full -d example.com --resolve --ports top100
```

### Pipeline order

The standard pipeline is:

```text
Target
  │
  ├── Subdomain discovery
  │     ├── certificate transparency
  │     └── active DNS wordlist
  │
  ├── DNS enumeration
  │
  ├── HTTP/HTTPS probing
  │
  ├── TLS inspection
  │
  └── Optional TCP port discovery
          │
          ▼
    Correlation Engine
          │
          ▼
      Unified Report
```

### Why port scanning is optional

The default `full` command does not automatically scan ports because it is designed to remain predictable and comparatively lightweight.

You explicitly opt into it:

```bash
./orfx.sh full -d example.com --ports top100
```

This keeps the simplest form of the command easy to use while still allowing a deeper authorized workflow.

---

## 8. `auto`

`auto` is simply an alias for the standard full pipeline:

```bash
./orfx.sh auto -d example.com
```

This exists for users who prefer a semantic command name over `full`.

The behavior is intentionally not different from `full`.

---

## 9. Correlation engine

One of the main improvements in 3.2.0 is that module results are no longer treated as unrelated pieces of output.

ORFX builds a unified internal model containing:

```text
Target
Assets
DNS
Subdomains
HTTP services
Open ports
TLS services
WHOIS
Findings
Errors
Summary
```

For example, a discovery chain can be represented as:

```text
api.example.com
      │
      ├── IPv4: 203.0.113.10
      ├── IPv6: 2001:db8::10
      │
      ├── HTTPS: 443
      ├── HTTP: 80
      │
      ├── Technology: nginx
      └── TLS certificate: valid
```

The purpose of correlation is not to invent findings. It simply connects the information already collected by the individual modules.

---

## 10. Reports

ORFX supports three report formats:

```bash
--json
--txt
--html
```

The `--out` parameter controls the report basename.

Example:

```bash
./orfx.sh full -d example.com --resolve --json --txt --html --out reports/example_full
```

Generated files:

```text
reports/example_full.json
reports/example_full.txt
reports/example_full.html
```

### JSON

JSON is intended for automation and further processing.

It includes:

- metadata;
- summary;
- raw module results;
- correlated results;
- normalized findings.

### TXT

TXT is intended for quick terminal-style review, ticket attachments and simple archival.

### HTML

HTML provides a browser-readable report containing:

- summary information;
- normalized findings;
- raw result data.

---

## 11. Normalized findings

Every module converts its raw result into a common finding shape:

```json
{
  "severity": "INFO",
  "target": "example.com",
  "check": "HTTP status",
  "detail": "200"
}
```

The severity currently helps distinguish:

- `INFO` — normal reconnaissance information;
- `LOW` — a low-priority observation such as a missing security header;
- `WARN` — incomplete or degraded collection;
- `HIGH` — important normalized condition such as an expired TLS certificate;
- `ERROR` — a module could not complete its intended collection.

These severities are reporting aids. They are not a replacement for a vulnerability scanner or manual validation.

---

## 12. Error handling philosophy

An important goal of ORFX is to avoid the original "empty output" problem.

Bad behavior:

```text
Module fails
   ↓
Exception swallowed
   ↓
No output
   ↓
User assumes nothing was found
```

ORFX 3.2.0 instead aims for:

```text
Module fails
   ↓
Reason recorded
   ↓
Other stages continue when safe
   ↓
User sees the failure
   ↓
Report contains the reason
```

Examples include:

- DNS timeout;
- missing `dig`;
- `crt.sh` unavailable;
- target cannot be resolved;
- HTTP connection refused;
- TLS verification error;
- WHOIS unavailable.

A collection failure should be visible and actionable.

---

## 13. Environment validation

Run:

```bash
./orfx.sh --check
```

The check validates:

- Python version;
- importability of all modules;
- Python syntax across the project;
- presence of useful external tools.

External tools are reported as optional because ORFX contains internal fallbacks where practical.

A successful check ends with:

```text
[+] ORFX is ready
```

---

## 14. Testing

Development tests are stored under `tests/`.

If `pytest` is available:

```bash
python3 -m pytest -q
```

Expected result for the current release:

```text
7 passed
```

The tests cover core behavior such as:

- domain normalization;
- domain validation;
- local address resolution;
- port specification parsing;
- TLS module options;
- HTTP scheme selection;
- result correlation.

The tests are lightweight and deterministic. Network-heavy integration tests are deliberately kept out of the default unit-test run.

---

## 15. Development layout

The project is intentionally separated into small components:

```text
ORFX/
├── orfx.py
├── orfx.sh
│
├── core/
│   ├── correlator.py
│   ├── helpers.py
│   ├── pipeline.py
│   └── settings.py
│
├── modules/
│   ├── base.py
│   ├── dns_recon.py
│   ├── http_probe.py
│   ├── port_scanner.py
│   ├── subdomain_enum.py
│   ├── tls_probe.py
│   ├── whois_lookup.py
│   └── report_gen.py
│
├── utils/
│   ├── colors.py
│   └── session.py
│
├── tests/
│   ├── test_correlator.py
│   ├── test_helpers.py
│   ├── test_http.py
│   ├── test_ports.py
│   └── test_tls.py
│
├── config/
│   └── orfx.json.example
│
├── reports/
├── requirements.txt
├── requirements-dev.txt
├── SECURITY.md
├── ETHICS.md
├── CHANGELOG.md
└── README.md
```

The architecture keeps the CLI stable while allowing new modules to be added later.

---

## 16. Performance and safety controls

ORFX uses bounded concurrency and configurable timeouts.

Examples:

```bash
./orfx.sh subdomains -d example.com --threads 50 --timeout 3
./orfx.sh ports -t example.com --threads 100 --timeout 1
./orfx.sh http -u https://example.com --timeout 10
```

Concurrency is capped internally to avoid accidental extreme values.

The framework also limits some integrated stages when using `full` so a large discovery set does not automatically turn into an unbounded downstream scan.

This is intentional: **discovery depth and resource usage should be explicit.**

---

## 17. Operational recommendations

For a controlled assessment, a useful workflow is:

```bash
./orfx.sh --check
./orfx.sh subdomains -d example.com --resolve
./orfx.sh dns -d example.com
./orfx.sh http -i reports/example_subdomains.txt
./orfx.sh tls -d example.com
./orfx.sh ports -t example.com --ports top100
./orfx.sh full -d example.com --resolve --json --html --out reports/example_full
```

The order is not mandatory. It simply demonstrates how the modules can be used independently or as one pipeline.

---

## 18. Troubleshooting

### ORFX appears to return nothing

Run:

```bash
./orfx.sh --check
```

Then verify DNS outside the framework:

```bash
getent hosts example.com
dig example.com A
```

If `dig` is missing:

```bash
sudo apt update
sudo apt install dnsutils -y
```

### Subdomains returns very few results

Certificate-transparency and wordlist enumeration are not exhaustive. Results vary according to:

- certificates known to public transparency logs;
- the chosen wordlist;
- DNS resolver behavior;
- target configuration;
- network reachability.

Try a larger custom wordlist on systems you are authorized to assess.

### HTTP fails but the site opens in a browser

Test both schemes:

```bash
./orfx.sh http -u https://example.com
./orfx.sh http -u http://example.com
```

Then verify the host resolves and is reachable from the same machine.

### TLS verification fails

The failure may be caused by:

- an expired certificate;
- a name mismatch;
- an incomplete certificate chain;
- an intentionally private CA;
- local trust-store configuration.

ORFX reports the reason instead of treating the target as empty.

### WHOIS is unavailable

Install the system client:

```bash
sudo apt install whois -y
```

or install the project dependencies again:

```bash
./orfx.sh --install
```

### Python environment became inconsistent

Recreate the isolated environment:

```bash
rm -rf .venv
./orfx.sh --install
./orfx.sh --check
```

---

## 19. Scope and limitations

ORFX is intentionally a reconnaissance framework, not a complete offensive security platform.

It does not attempt to be:

- a full vulnerability scanner;
- an exploitation framework;
- a password attack platform;
- a web crawler with unrestricted depth;
- a replacement for Nmap or specialized enterprise scanners.

Its value comes from providing a compact, understandable workflow that combines common discovery tasks and keeps their results correlated.

---

## 20. Roadmap

The next sensible improvements are expected to build on the 3.2.0 architecture rather than replace it.

Potential future work includes:

- richer technology fingerprints;
- deeper TLS policy reporting;
- more passive discovery sources;
- scan history and comparison;
- configurable profiles;
- plugin registration for additional modules;
- optional local database storage;
- broader integration tests.

The goal remains the same: **more capability behind the same simple commands.**

---

## 21. License

This project is distributed under the MIT License. See [LICENSE](LICENSE).

## 22. Ethics and security

See:

- [ETHICS.md](ETHICS.md)
- [SECURITY.md](SECURITY.md)
- [CHANGELOG.md](CHANGELOG.md)
