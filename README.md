# ORFX

> Offensive Recon Framework — clean direct CLI edition for authorized security testing.

![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-CLI%20Clean-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

ORFX is part of the NeiveZ security toolkit. This edition removes the old interactive
`use / set / run` workflow and replaces it with direct command-line usage.

The goal is to make the tool cleaner, easier to use in labs and certifications, and less
similar to exploitation frameworks.

---

## Commands

- `subdomains` — Passive and active subdomain discovery
- `dns` — DNS record enumeration
- `http` — HTTP headers, technology and security header audit
- `ports` — TCP port scanning and banner grabbing
- `whois` — WHOIS lookup for domains and IPs

---

## Installation

```bash
chmod +x orfx.sh
./orfx.sh --install
```

Validate the project:

```bash
./orfx.sh --check
```

---

## Usage

```bash
./orfx.sh --help
```

Examples:

```bash
./orfx.sh --help
```

For intrusive or high-impact checks, commands require `--authorized`.

---

## Output

The CLI uses a clean summary-oriented output:

```text
Run Summary
  Tool       : ORFX
  Command    : <command>
  Purpose    : <purpose>

Results
Severity     Target                       Check                    Detail
```

Reports can be saved with:

```bash
./orfx.sh <command> [options] --json --txt --out reports/orfx_scan
```

---

## Ethics

Use only on systems you own or have explicit written authorization to assess.
Do not run against third-party infrastructure without permission.

---

## License

MIT License.


## Branding

This CLI clean edition uses a project-specific banner and direct command-line workflow. It intentionally avoids Metasploit-style `use / set / run` interaction.
