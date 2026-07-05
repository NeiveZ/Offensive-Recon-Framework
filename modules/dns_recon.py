#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/dns_recon.py — DNS record enumeration (A, MX, NS, TXT, CNAME, SOA, AAAA).
"""

import subprocess
import shutil
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"]


class DNSRecon(BaseModule):

    NAME        = "recon/dns"
    DESCRIPTION = "DNS record enumeration: A, MX, NS, TXT, CNAME, SOA, AAAA"
    AUTHOR      = "NeiveZ"
    REFERENCES  = [
        "https://en.wikipedia.org/wiki/List_of_DNS_record_types",
        "https://dnsdumpster.com",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",         True,  "Target domain (e.g. example.com)")
        self._add_option("TYPES",    "all",      False, "Record types: all, or A,MX,NS,TXT")
        self._add_option("SERVER",   "",         False, "Custom DNS server (e.g. 8.8.8.8)")
        self._add_option("TIMEOUT",  "5",        False, "Query timeout in seconds")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        target  = self.get_option("TARGET").strip()
        types   = self._parse_types(self.get_option("TYPES") or "all")
        server  = self.get_option("SERVER") or ""
        timeout = int(self.get_option("TIMEOUT") or 5)

        print_section(f"DNS Recon → {Colors.CYAN}{target}{Colors.RESET}")
        print_status(f"Record types : {Colors.WHITE}{', '.join(types)}{Colors.RESET}", "info")
        if server:
            print_status(f"DNS server   : {Colors.WHITE}{server}{Colors.RESET}", "info")
        print()

        all_records: dict = {}

        for rtype in types:
            records = self._query(target, rtype, server, timeout)
            if records:
                all_records[rtype] = records
                self._print_records(rtype, records)

        if not all_records:
            print_status("No DNS records found or domain does not exist.", "warn")
        else:
            print_status(f"DNS enumeration complete. Found {Colors.WHITE}{sum(len(v) for v in all_records.values())}{Colors.RESET} records.", "ok")

        return {"target": target, "records": all_records}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _query(self, domain: str, rtype: str, server: str, timeout: int) -> list:
        """Query DNS using dig (preferred) or nslookup."""
        results = []

        if shutil.which("dig"):
            cmd = ["dig", "+noall", "+answer", f"+time={timeout}", domain, rtype]
            if server:
                cmd.insert(1, f"@{server}")
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 2)
                for line in out.decode().splitlines():
                    line = line.strip()
                    if line and not line.startswith(";"):
                        parts = line.split()
                        if len(parts) >= 5:
                            results.append({
                                "name": parts[0],
                                "ttl":  parts[1],
                                "type": parts[3],
                                "data": " ".join(parts[4:]),
                            })
            except Exception:
                pass

        elif shutil.which("nslookup"):
            cmd = ["nslookup", f"-type={rtype}", domain]
            if server:
                cmd.append(server)
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 2)
                lines = out.decode().splitlines()
                for line in lines:
                    if "=" in line or "address" in line.lower():
                        results.append({"name": domain, "ttl": "", "type": rtype, "data": line.strip()})
            except Exception:
                pass

        else:
            # Pure Python fallback using socket
            if rtype == "A":
                try:
                    import socket
                    ips = socket.gethostbyname_ex(domain)[2]
                    for ip in ips:
                        results.append({"name": domain, "ttl": "", "type": "A", "data": ip})
                except Exception:
                    pass

        return results

    def _print_records(self, rtype: str, records: list):
        type_colors = {
            "A":     Colors.GREEN,
            "AAAA":  Colors.CYAN,
            "MX":    Colors.YELLOW,
            "NS":    Colors.MAGENTA,
            "TXT":   Colors.WHITE,
            "CNAME": Colors.BLUE,
            "SOA":   Colors.ORANGE,
        }
        color = type_colors.get(rtype, Colors.WHITE)
        print(f"  {Colors.BOLD}{color}{rtype}{Colors.RESET}")
        for r in records:
            print(f"    {Colors.DARK_GRAY}•{Colors.RESET} {Colors.WHITE}{r['data']}{Colors.RESET}"
                  + (f"  {Colors.DARK_GRAY}(TTL {r['ttl']}){Colors.RESET}" if r.get("ttl") else ""))
        print()

    def _parse_types(self, spec: str) -> list:
        if spec.lower() == "all":
            return RECORD_TYPES
        return [t.strip().upper() for t in spec.split(",") if t.strip()]
