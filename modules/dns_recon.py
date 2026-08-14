#!/usr/bin/env python3
from __future__ import annotations

import shutil
import socket
import subprocess

from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section, print_table
from core.helpers import safe_int

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA"]


class DNSRecon(BaseModule):
    NAME = "recon/dns"
    DESCRIPTION = "DNS record enumeration with IPv4/IPv6 and resolver fallback"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://www.rfc-editor.org/rfc/rfc1035"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target domain")
        self._add_option("TYPES", "all", False, "all or comma-separated record types")
        self._add_option("SERVER", "", False, "DNS server")
        self._add_option("TIMEOUT", "5", False, "Query timeout")

    def run(self):
        if not self._validate():
            return {}
        target = self.get_option("TARGET").strip().lower().rstrip(".")
        types = self._parse_types(self.get_option("TYPES"))
        timeout = safe_int(self.get_option("TIMEOUT"), 5, 1, 30)
        server = (self.get_option("SERVER") or "").strip()
        print_section(f"DNS Recon → {Colors.CYAN}{target}{Colors.RESET}")
        records = {}
        errors = []
        for rtype in types:
            vals, error = self._query(target, rtype, server, timeout)
            if vals:
                records[rtype] = vals
            if error:
                errors.append({"type": rtype, "error": error})
        total = sum(len(v) for v in records.values())
        if total:
            print_table(["Type", "Name", "Data"], [(t, x.get("name", target), x.get("data", "")) for t, vals in records.items() for x in vals])
            print_status(f"DNS enumeration complete. Found {total} record(s).", "ok")
        else:
            print_status("No DNS records returned. Resolver availability or record type may be the cause.", "warn")
        return {"target": target, "records": records, "total_records": total, "errors": errors}

    def _parse_types(self, value):
        if not value or str(value).lower() == "all":
            return RECORD_TYPES
        return [x.strip().upper() for x in str(value).split(",") if x.strip().upper() in RECORD_TYPES]

    def _query(self, domain, rtype, server, timeout):
        if shutil.which("dig"):
            cmd = ["dig", "+noall", "+answer", f"+time={timeout}", f"+tries=1"]
            if server:
                cmd.append(f"@{server}")
            cmd += [domain, rtype]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 2).decode(errors="replace")
                vals = []
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5:
                        vals.append({"name": parts[0], "ttl": parts[1], "type": parts[3], "data": " ".join(parts[4:])})
                return vals, None
            except subprocess.TimeoutExpired:
                return [], "DNS query timed out"
            except Exception as exc:
                return [], str(exc)
        if server:
            return [], "dig is required for custom DNS server selection"
        if rtype == "A":
            try:
                return [{"name": domain, "ttl": "", "type": "A", "data": ip} for ip in sorted(set(socket.gethostbyname_ex(domain)[2]))], None
            except Exception as exc:
                return [], str(exc)
        if rtype == "AAAA":
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
                addrs = sorted({i[4][0] for i in infos})
                return [{"name": domain, "ttl": "", "type": "AAAA", "data": ip} for ip in addrs], None
            except Exception as exc:
                return [], str(exc)
        return [], "dig not installed; only A/AAAA fallback is available"
