#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ORFX — Offensive Recon Framework CLI."""
from __future__ import annotations

import compileall
import datetime as dt
import html
import importlib
import json
import shutil
import sys
import time
from pathlib import Path

from core.correlator import Correlator
from utils.colors import Colors

TOOL = "ORFX"
TAGLINE = "Offensive Recon Framework"
VERSION = "3.2.0"

COMMANDS = {
    "subdomains": ("modules.subdomain_enum", "SubdomainEnumerator", "Discover subdomains using certificate transparency and DNS enumeration."),
    "dns": ("modules.dns_recon", "DNSRecon", "Enumerate DNS records including IPv4 and IPv6."),
    "http": ("modules.http_probe", "HTTPProbe", "Probe HTTP/HTTPS services, redirects, headers and technologies."),
    "ports": ("modules.port_scanner", "PortScanner", "Perform TCP port discovery with IPv4/IPv6 support."),
    "tls": ("modules.tls_probe", "TLSProbe", "Inspect TLS protocol, cipher and certificate information."),
    "whois": ("modules.whois_lookup", "WhoisLookup", "Query WHOIS information."),
}

ALIASES = {
    "-d":"TARGET", "-u":"TARGET", "-t":"TARGET", "-i":"INPUT",
    "--records":"TYPES", "--wordlist":"WORDLIST", "--threads":"THREADS", "--timeout":"TIMEOUT",
    "--resolve":"RESOLVE", "--http":"HTTP", "--passive":"PASSIVE", "--active":"ACTIVE",
    "--follow":"FOLLOW", "--scheme":"SCHEME", "--fallback":"FALLBACK", "--banners":"BANNERS",
    "--ports":"PORTS", "--server":"SERVER", "--verify":"VERIFY", "--user-agent":"USER_AGENT",
    "--port":"PORT",
}


def banner():
    print(f"{Colors.BOLD}{Colors.CYAN}ORFX{Colors.RESET}  {TAGLINE}  {Colors.WHITE}v{VERSION}{Colors.RESET}")
    print(f"{Colors.DARK_GRAY}Authorized security testing, labs and internal assessments only.{Colors.RESET}\n")


def print_commands():
    banner()
    print(f"{Colors.BOLD}Available commands{Colors.RESET}\n" + "-" * 92)
    for name, (_, _, description) in COMMANDS.items():
        print(f"  {name:<14} {description}")
    print(f"  {'full':<14} End-to-end recon pipeline: subdomains → DNS → HTTP → TLS")
    print(f"  {'auto':<14} Alias for full; enables the standard pipeline with one simple command")
    print(f"\nGlobal: --json --txt --html --out PATH --silent --no-color")
    print("\nExamples:")
    examples = [
        "./orfx.sh subdomains -d example.com --resolve",
        "./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA,CAA",
        "./orfx.sh http -u https://example.com",
        "./orfx.sh ports -t example.com --ports 22,80,443,8080",
        "./orfx.sh tls -d example.com",
        "./orfx.sh whois -d example.com",
        "./orfx.sh full -d example.com --resolve",
    ]
    for item in examples:
        print("  " + item)


def load_module(command):
    mod_name, cls_name, _ = COMMANDS[command]
    module = importlib.import_module(mod_name)
    return getattr(module, cls_name)()


def parse_common(argv):
    common = {"json": False, "txt": False, "html": False, "out": "", "silent": False, "no_color": False}
    cleaned = []
    i = 0
    while i < len(argv):
        item = argv[i]
        if item in ("--json", "--txt", "--html", "--silent", "--no-color"):
            common[item[2:].replace("-", "_")] = True
            i += 1
            continue
        if item == "--out":
            if i + 1 >= len(argv):
                raise ValueError("--out requires a path")
            common["out"] = argv[i + 1]
            i += 2
            continue
        if item.startswith("--out="):
            common["out"] = item.split("=", 1)[1]
            i += 1
            continue
        cleaned.append(item)
        i += 1
    return cleaned, common


def set_options(obj, args):
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--help", "-h"):
            return "help"
        if arg in ("--verbose", "--authorized"):
            i += 1
            continue
        key = ALIASES.get(arg)
        if key:
            if key in ("RESOLVE", "HTTP", "PASSIVE", "ACTIVE"):
                obj.set_option(key, "true")
                i += 1
                continue
            if i + 1 >= len(args):
                raise ValueError(f"{arg} requires a value")
            obj.set_option(key, args[i + 1])
            i += 2
            continue
        if arg.startswith("--"):
            key = arg[2:].replace("-", "_").upper()
            if key not in obj.options:
                raise ValueError(f"Unknown option: {arg}")
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                raise ValueError(f"{arg} requires a value")
            obj.set_option(key, args[i + 1])
            i += 2
            continue
        if arg.startswith("-"):
            raise ValueError(f"Unknown option: {arg}")
        raise ValueError(f"Unexpected argument: {arg}")
    return None


def show_module_help(command, obj):
    banner()
    print(f"{Colors.BOLD}Command: {command}{Colors.RESET}\n{COMMANDS[command][2]}\n")
    for name, meta in obj.options.items():
        req = "required" if meta.get("required") else "optional"
        print(f"  --{name.lower().replace('_', '-'):18} {req:9} {meta.get('desc', '')}")
    print("\nAliases: -d/-u/-t for TARGET, -i for INPUT, plus global report flags.")


def scalar(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return str(value)


def findings(command, result):
    rows = []
    if not isinstance(result, dict):
        return [{"severity": "INFO", "target": "", "check": command, "detail": scalar(result)}]
    target = result.get("target", "")
    if result.get("error"):
        rows.append({"severity": "ERROR", "target": target, "check": command, "detail": result["error"]})
    if command == "subdomains":
        for item in result.get("subdomains", []):
            rows.append({"severity": "INFO", "target": item.get("subdomain", ""), "check": "DNS resolution", "detail": f"IPv4={', '.join(item.get('ipv4', [])) or '-'} IPv6={', '.join(item.get('ipv6', [])) or '-'}"})
        rows.append({"severity": "INFO", "target": target, "check": "Subdomains", "detail": f"{result.get('total', 0)} resolved / {result.get('candidates', 0)} candidates"})
    elif command == "dns":
        for rtype, values in result.get("records", {}).items():
            for item in values:
                rows.append({"severity": "INFO", "target": item.get("name", target), "check": rtype, "detail": item.get("data", "")})
        if result.get("errors"):
            for item in result["errors"]:
                rows.append({"severity": "WARN", "target": target, "check": f"DNS {item['type']}", "detail": item["error"]})
    elif command == "http":
        for item in result.get("results", [result]):
            if item.get("error"):
                rows.append({"severity": "ERROR", "target": item.get("target", target), "check": "HTTP", "detail": item["error"]})
                continue
            rows.append({"severity": "INFO", "target": item.get("final_url", item.get("target", target)), "check": "HTTP status", "detail": item.get("status_code", "")})
            if item.get("technologies"):
                rows.append({"severity": "INFO", "target": item.get("host", target), "check": "Technologies", "detail": ", ".join(item["technologies"])})
            for header, present in item.get("security_headers", {}).items():
                rows.append({"severity": "INFO" if present else "LOW", "target": item.get("host", target), "check": "Security header", "detail": f"{header}: {'PRESENT' if present else 'MISSING'}"})
    elif command == "ports":
        for item in result.get("open_ports", []):
            rows.append({"severity": "INFO", "target": item.get("address", target), "check": f"TCP/{item.get('port')}", "detail": f"{item.get('service', 'unknown')} OPEN {item.get('banner', '')}"})
        rows.append({"severity": "INFO", "target": target, "check": "Port scan", "detail": f"{result.get('total_open', 0)} open port(s)"})
    elif command == "tls":
        if result.get("error"):
            return rows
        rows += [
            {"severity": "INFO", "target": target, "check": "TLS protocol", "detail": result.get("protocol", "")},
            {"severity": "INFO", "target": target, "check": "TLS cipher", "detail": result.get("cipher", "")},
        ]
        days = result.get("days_remaining")
        if isinstance(days, int):
            rows.append({"severity": "HIGH" if days < 0 else "LOW" if days <= 30 else "INFO", "target": target, "check": "Certificate expiry", "detail": f"{days} day(s) remaining"})
    elif command == "whois":
        for key, value in result.items():
            if key not in ("target",) and value not in (None, ""):
                rows.append({"severity": "INFO", "target": target, "check": key, "detail": scalar(value)})
    return rows


def print_rows(rows):
    print(f"\n{Colors.BOLD}Normalized findings{Colors.RESET}\n" + "-" * 112)
    if not rows:
        print(f"{Colors.YELLOW}No structured findings returned.{Colors.RESET}")
        return
    print(f"{'Severity':<10} {'Target':<38} {'Check':<23} Detail")
    print("-" * 112)
    for row in rows[:400]:
        sev = str(row.get("severity", "INFO")).upper()
        color = Colors.RED if sev in ("ERROR", "HIGH") else Colors.YELLOW if sev == "LOW" else Colors.CYAN
        print(f"{color}{sev:<10}{Colors.RESET} {str(row.get('target', ''))[:38]:<38} {str(row.get('check', ''))[:23]:<23} {str(row.get('detail', ''))[:160]}")
    if len(rows) > 400:
        print(f"{Colors.DARK_GRAY}... {len(rows) - 400} more findings; inspect JSON/HTML report.{Colors.RESET}")


def save_reports(command, result, rows, common, summary=None):
    if not (common["json"] or common["txt"] or common["html"] or common["out"]):
        return []
    base = Path(common["out"] or f"reports/{command}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    if base.suffix:
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": TOOL, "version": VERSION, "command": command,
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "summary": summary or {}, "results": result, "findings": rows,
    }
    saved = []
    if common["json"] or common["out"]:
        path = Path(str(base) + ".json")
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        saved.append(str(path))
    if common["txt"]:
        path = Path(str(base) + ".txt")
        lines = [f"{TOOL} {VERSION} — {command}", "=" * 90, ""]
        if summary:
            lines += ["SUMMARY", json.dumps(summary, ensure_ascii=False, indent=2), ""]
        lines += [f"{r['severity']} | {r['target']} | {r['check']} | {r['detail']}" for r in rows]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        saved.append(str(path))
    if common["html"]:
        path = Path(str(base) + ".html")
        summary_rows = "".join(f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in (summary or {}).items())
        finding_rows = "".join(f"<tr><td>{html.escape(str(r['severity']))}</td><td>{html.escape(str(r['target']))}</td><td>{html.escape(str(r['check']))}</td><td>{html.escape(str(r['detail']))}</td></tr>" for r in rows)
        content = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>ORFX {html.escape(command)}</title><style>body{{font-family:system-ui;background:#0b1020;color:#e6edf3;padding:24px}}section{{background:#11182b;border:1px solid #26304a;border-radius:10px;padding:18px;margin:18px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #26304a;padding:8px;text-align:left}}th{{color:#8dd7ff}}h1{{margin-bottom:4px}}small{{color:#8b949e}}code{{color:#a5d6ff}}</style></head><body><h1>ORFX — {html.escape(command)}</h1><small>Generated {html.escape(payload['timestamp'])}</small><section><h2>Summary</h2><table>{summary_rows}</table></section><section><h2>Findings</h2><table><tr><th>Severity</th><th>Target</th><th>Check</th><th>Detail</th></tr>{finding_rows}</table></section><section><h2>Raw result</h2><pre>{html.escape(json.dumps(result, indent=2, ensure_ascii=False, default=str))}</pre></section></body></html>"""
        path.write_text(content, encoding="utf-8")
        saved.append(str(path))
    return saved


def run_check():
    checks = []
    ok = True
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("Python", version, sys.version_info >= (3, 10), "3.10+ required"))
    for command, (_, _, _) in COMMANDS.items():
        try:
            load_module(command)
            checks.append((f"Module: {command}", "loaded", True, ""))
        except Exception as exc:
            checks.append((f"Module: {command}", str(exc), False, ""))
    for tool in ("dig", "whois", "nmap"):
        checks.append((f"Tool: {tool}", shutil.which(tool) or "optional/missing", True, "ORFX has fallbacks; nmap is not required"))
    compiled = compileall.compile_dir(".", quiet=1)
    checks.append(("Python syntax", "PASS" if compiled else "FAIL", compiled, ""))
    for label, value, passed, note in checks:
        ok = ok and passed
        marker = f"{Colors.GREEN}OK{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
        suffix = f" — {note}" if note else ""
        print(f"{marker:<18} {label:<24} {value}{suffix}")
    print(f"\n{Colors.GREEN if ok else Colors.RED}{'[+] ORFX is ready' if ok else '[-] ORFX check failed'}{Colors.RESET}")
    return 0 if ok else 1


def run_command(command, args, common):
    obj = load_module(command)
    try:
        status = set_options(obj, args)
    except ValueError as exc:
        print(f"{Colors.RED}{exc}{Colors.RESET}")
        return 2
    if status == "help":
        show_module_help(command, obj)
        return 0
    if command != "http" and not obj._validate():
        return 2
    if not common["silent"]:
        banner()
        print(f"Command: {command}\n")
    try:
        started = time.monotonic()
        result = obj.run()
        elapsed = time.monotonic() - started
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}Interrupted.{Colors.RESET}")
        return 130
    except Exception as exc:
        print(f"{Colors.RED}Module execution failed: {exc}{Colors.RESET}")
        return 1
    rows = findings(command, result)
    if not common["silent"]:
        print(f"\nElapsed: {elapsed:.2f}s")
        print_rows(rows)
    else:
        print(json.dumps({"command": command, "results": result, "findings": rows}, ensure_ascii=False, default=str))
    saved = save_reports(command, result, rows, common)
    if saved and not common["silent"]:
        print(f"\n{Colors.GREEN}Reports saved:{Colors.RESET}")
        for item in saved:
            print("  " + item)
    return 0 if not any(r["severity"] in ("ERROR", "HIGH") for r in rows) else 1


def configure_module(command, target=None):
    obj = load_module(command)
    if target:
        obj.set_option("TARGET", target)
    return obj


def run_full(args, common):
    # full/auto accept the same simple -d target and a small set of toggles.
    clean_args = list(args)
    target = None
    resolve = False
    http_enabled = True
    tls_enabled = True
    ports_enabled = False
    port_spec = "top100"
    i = 0
    while i < len(clean_args):
        arg = clean_args[i]
        if arg in ("-d", "--target"):
            target = clean_args[i + 1]; i += 2; continue
        if arg in ("--resolve", "--http"):
            if arg == "--resolve":
                resolve = True
            i += 1; continue
        if arg == "--no-http":
            http_enabled = False; i += 1; continue
        if arg == "--no-tls":
            tls_enabled = False; i += 1; continue
        if arg == "--ports":
            if i + 1 < len(clean_args) and not clean_args[i + 1].startswith("-"):
                ports_enabled = True; port_spec = clean_args[i + 1]; i += 2; continue
            ports_enabled = True; i += 1; continue
        if arg == "--json" or arg.startswith("--"):
            i += 1; continue
        i += 1
    if not target:
        print(f"{Colors.RED}full requires a target. Example: ./orfx.sh full -d example.com{Colors.RESET}")
        return 2
    if not common["silent"]:
        banner()
        print(f"{Colors.BOLD}Full Recon Pipeline{Colors.RESET}\n")
    aggregate = {}
    correlator = Correlator(target)

    sub = configure_module("subdomains", target)
    sub.set_option("RESOLVE", "true" if resolve else "false")
    sub_result = sub.run()
    aggregate["subdomains"] = sub_result
    correlator.add("subdomains", sub_result)

    dns = configure_module("dns", target)
    dns_result = dns.run()
    aggregate["dns"] = dns_result
    correlator.add("dns", dns_result)

    hosts = [target]
    for item in sub_result.get("subdomains", []) if isinstance(sub_result, dict) else []:
        hosts.append(item.get("subdomain"))
    hosts = [x for x in dict.fromkeys(x for x in hosts if x)]

    aggregate["http"] = []
    if http_enabled:
        print(f"\n{Colors.BOLD}HTTP stage{Colors.RESET}")
        for host in hosts[:100]:
            http = configure_module("http", host)
            result = http.run()
            aggregate["http"].append(result)
            correlator.add("http", result)

    aggregate["tls"] = []
    if tls_enabled:
        print(f"\n{Colors.BOLD}TLS stage{Colors.RESET}")
        for host in hosts[:100]:
            tls = configure_module("tls", host)
            result = tls.run()
            aggregate["tls"].append(result)
            correlator.add("tls", result)

    aggregate["ports"] = []
    if ports_enabled:
        print(f"\n{Colors.BOLD}Port stage{Colors.RESET}")
        for host in hosts[:25]:
            scanner = configure_module("ports", host)
            scanner.set_option("PORTS", port_spec)
            result = scanner.run()
            aggregate["ports"].append(result)
            correlator.add("ports", result)

    model = correlator.finalize()
    aggregate["correlated"] = model
    rows = []
    for command, data in (("subdomains", sub_result), ("dns", dns_result)):
        rows.extend(findings(command, data))
    for data in aggregate["http"]:
        rows.extend(findings("http", data))
    for data in aggregate["tls"]:
        rows.extend(findings("tls", data))
    for data in aggregate["ports"]:
        rows.extend(findings("ports", data))

    summary = model.get("summary", {})
    if not common["silent"]:
        print(f"\n{Colors.BOLD}Recon Summary{Colors.RESET}")
        for key, value in summary.items():
            if isinstance(value, list):
                value = ", ".join(value)
            print(f"  {key:<18}: {value}")
        print_rows(rows)
    else:
        print(json.dumps({"command": "full", "summary": summary, "results": aggregate, "findings": rows}, ensure_ascii=False, default=str))
    saved = save_reports("full", aggregate, rows, common, summary=summary)
    if saved and not common["silent"]:
        print(f"\n{Colors.GREEN}Reports saved:{Colors.RESET}")
        for item in saved:
            print("  " + item)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--no-color" in argv:
        Colors.disable()
    if not argv or argv[0] in ("-h", "--help", "help"):
        print_commands()
        return 0
    if argv[0] == "--check":
        banner()
        return run_check()
    command = argv[0]
    if command in ("commands", "list"):
        print_commands()
        return 0
    args, common = parse_common(argv[1:])
    if command in ("full", "auto"):
        return run_full(args, common)
    if command not in COMMANDS:
        print(f"{Colors.RED}Unknown command: {command}{Colors.RESET}\n")
        print_commands()
        return 2
    return run_command(command, args, common)


if __name__ == "__main__":
    raise SystemExit(main())
