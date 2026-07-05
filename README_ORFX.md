# ORFX

> Offensive Recon Framework — clean CLI recon workflow for authorized assessments.

![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Category](https://img.shields.io/badge/Category-Reconnaissance-0ea5e9?style=flat-square)
![Status](https://img.shields.io/badge/Interface-Direct%20CLI-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

ORFX is a reconnaissance toolkit designed to centralize early-stage enumeration in a direct command-line workflow.

This version removes the old interactive `use / set / run` style and replaces it with explicit commands such as `subdomains`, `dns`, `http`, `ports`, `whois`, and `full`.

ORFX is intended for authorized labs, certification preparation, internal audits, and scoped security assessments.

---

## What ORFX Does

ORFX helps organize the first phase of an assessment:

- Discover subdomains.
- Enumerate DNS records.
- Probe HTTP services.
- Identify headers and technologies.
- Run light TCP service discovery.
- Save outputs into repeatable reports.

It is not an exploitation framework and does not attempt automatic exploitation.

---

## Installation

### 1. Clone or extract the project

```bash
git clone https://github.com/NeiveZ/ORFX.git
cd ORFX
```

Or, if using the ZIP build:

```bash
unzip ORFX-cli-branded.zip
cd ORFX-cli-branded
```

### 2. Make the launcher executable

```bash
chmod +x orfx.sh
```

### 3. Install dependencies

```bash
./orfx.sh --install
```

### 4. Validate the environment

```bash
./orfx.sh --check
```

Expected result:

```text
[+] Python detected
[+] Required modules loaded
[+] Optional tools checked
[+] ORFX is ready
```

---

## Usage

```bash
./orfx.sh <command> [options]
```

Show help:

```bash
./orfx.sh --help
```

List command help:

```bash
./orfx.sh subdomains --help
./orfx.sh dns --help
./orfx.sh http --help
./orfx.sh ports --help
```

---

## Commands

### Subdomain Enumeration

```bash
./orfx.sh subdomains -d example.com
```

With IP resolution:

```bash
./orfx.sh subdomains -d example.com --resolve
```

Save reports:

```bash
./orfx.sh subdomains -d example.com --resolve --json --txt --out reports/example_subdomains
```

### DNS Enumeration

```bash
./orfx.sh dns -d example.com
```

Query specific record types:

```bash
./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA
```

### HTTP Probe

```bash
./orfx.sh http -u https://example.com
```

If HTTPS fails, test HTTP explicitly:

```bash
./orfx.sh http -u http://example.com
```

### Port Discovery

```bash
./orfx.sh ports -t 192.168.1.10 --ports 21,22,80,443,445
```

### WHOIS Lookup

```bash
./orfx.sh whois -d example.com
```

### Full Recon Flow

```bash
./orfx.sh full -d example.com --resolve --http --out reports/example_full
```

---

## Recommended Procedure

1. Start with subdomains:

```bash
./orfx.sh subdomains -d example.com --resolve --out reports/example_subdomains
```

2. Enumerate DNS records:

```bash
./orfx.sh dns -d example.com --out reports/example_dns
```

3. Probe discovered HTTP services:

```bash
./orfx.sh http -i reports/example_subdomains.txt --out reports/example_http
```

4. Run a full summary:

```bash
./orfx.sh full -d example.com --resolve --http --json --txt --out reports/example_summary
```

---

## Output

ORFX uses a structured terminal layout:

```text
ORFX Recon Summary

Target       example.com
Command      subdomains
Subdomains   24
Resolved IPs 6
Reports      reports/example_subdomains.*

Results
Severity  Target                  Check             Detail
INFO      example.com             Subdomains        24 names discovered
INFO      api.example.com         DNS A             203.0.113.10
LOW       crt.sh                  Passive source    Source unavailable
```

---

## Reports

Supported output options:

```bash
--json
--txt
--out <path_without_extension>
```

Example:

```bash
./orfx.sh full -d example.com --json --txt --out reports/example
```

Generated files:

```text
reports/example.json
reports/example.txt
```

---

## Troubleshooting

### Python module errors

```bash
./orfx.sh --install
./orfx.sh --check
```

### DNS tools missing

```bash
sudo apt update
sudo apt install dnsutils whois nmap -y
```

### HTTP target does not respond

Try specifying the scheme:

```bash
./orfx.sh http -u http://example.com
./orfx.sh http -u https://example.com
```

---

## Ethics

Use ORFX only on assets you own or have explicit written authorization to test.

Unauthorized scanning or enumeration of third-party infrastructure may be illegal.

---

## License

MIT License.
