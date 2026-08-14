#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import socket
import sys

from modules.base import BaseModule
from utils.colors import Colors, loading_bar, print_section, print_status, print_table
from core.helpers import resolve_addresses, safe_float, safe_int

COMMON_PORTS = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",69:"TFTP",80:"HTTP",88:"Kerberos",110:"POP3",111:"RPC",119:"NNTP",123:"NTP",135:"MSRPC",137:"NetBIOS-NS",138:"NetBIOS-DGM",139:"NetBIOS-SSN",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",500:"IKE",514:"Syslog",515:"LPD",587:"SMTP-Submission",636:"LDAPS",993:"IMAPS",995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",1723:"PPTP",2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",2181:"ZooKeeper",2375:"Docker",3000:"HTTP-Dev",3306:"MySQL",3389:"RDP",4000:"HTTP-Dev",4444:"Unknown",5000:"HTTP-Dev",5432:"Postgres",5900:"VNC",6379:"Redis",8000:"HTTP-Dev",8008:"HTTP-Alt",8009:"AJP",8080:"HTTP-Alt",8081:"HTTP-Alt",8088:"HTTP-Alt",8161:"ActiveMQ",8443:"HTTPS-Alt",8888:"Jupyter",9000:"HTTP-Dev",9090:"Prometheus",9100:"Node Exporter",9200:"Elasticsearch",9300:"Elasticsearch",10000:"Webmin",11211:"Memcached",27017:"MongoDB",50000:"DB2"}
TOP_100 = sorted(set(COMMON_PORTS.keys()))


class PortScanner(BaseModule):
    NAME = "recon/port_scan"
    DESCRIPTION = "TCP port discovery with IPv4/IPv6 support and optional banners"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://nmap.org/book/man-port-scanning-techniques.html"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target IP or hostname")
        self._add_option("PORTS", "top100", False, "top100, all, or 80,443,8080 / 1-1024")
        self._add_option("THREADS", "100", False, "Concurrent connections (1-200)")
        self._add_option("TIMEOUT", "1", False, "Connection timeout in seconds")
        self._add_option("BANNERS", "true", False, "Attempt limited banner grabbing (true/false)")

    def run(self):
        if not self._validate():
            return {}
        target = self.get_option("TARGET").strip()
        ports = self._parse_ports(self.get_option("PORTS") or "top100")
        threads = safe_int(self.get_option("THREADS"), 100, 1, 200)
        timeout = safe_float(self.get_option("TIMEOUT"), 1, 0.1, 10)
        banners = str(self.get_option("BANNERS")).lower() in ("1", "true", "yes", "on")
        if not ports:
            print_status("No valid ports were supplied.", "error")
            return {"target": target, "error": "No valid ports"}
        resolved = resolve_addresses(target)
        addresses = resolved["ipv4"] + resolved["ipv6"]
        if not addresses:
            print_status(f"Cannot resolve target: {target}", "error")
            return {"target": target, "addresses": [], "error": "Target resolution failed"}
        print_section(f"Port Scan → {Colors.CYAN}{target}{Colors.RESET}")
        print_status(f"Addresses: {', '.join(addresses)}", "info")
        print_status(f"Ports: {len(ports)} | Threads: {threads} | Timeout: {timeout}s | Banners: {banners}", "info")
        open_ports = []
        jobs = [(addr, p) for addr in addresses for p in ports]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._scan, addr, p, timeout, banners): (addr, p) for addr, p in jobs}
            total = len(futures)
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                loading_bar("Scanning", total, done)
                try:
                    result = future.result()
                except Exception as exc:
                    result = None
                    print_status(f"Port worker error: {exc}", "warn")
                if result:
                    open_ports.append(result)
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    print_status(f"{result['address']}:{result['port']} OPEN {result['service']}{(' | ' + result['banner'][:60]) if result.get('banner') else ''}", "found")
        if total:
            print()
        open_ports.sort(key=lambda x: (x["address"], x["port"]))
        print_status(f"Scan complete. {len(open_ports)} open port(s).", "ok")
        if open_ports:
            print_table(["Address", "Port", "Service", "Status", "Banner"], [(p["address"], p["port"], p["service"], "OPEN", p.get("banner", "")[:60]) for p in open_ports])
        return {"target": target, "addresses": addresses, "ipv4": resolved["ipv4"], "ipv6": resolved["ipv6"], "open_ports": open_ports, "total_open": len(open_ports)}

    def _scan(self, address, port, timeout, grab_banner):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((address, port, 0, 0) if family == socket.AF_INET6 else (address, port))
            if result != 0:
                return None
            banner = ""
            if grab_banner:
                try:
                    sock.settimeout(min(timeout, 1.5))
                    if port in {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000}:
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: ORFX\r\nConnection: close\r\n\r\n")
                    else:
                        sock.sendall(b"\r\n")
                    raw = sock.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip().splitlines()[0] if raw else ""
                except Exception:
                    pass
            return {"address": address, "port": port, "service": COMMON_PORTS.get(port, "unknown"), "banner": banner}

    def _parse_ports(self, spec):
        spec = str(spec).strip().lower()
        if spec == "top100":
            return TOP_100
        if spec == "all":
            # Full TCP scans are intentionally capped by design in this module.
            return list(range(1, 65536))
        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    lo, hi = map(int, part.split("-", 1))
                    if 1 <= lo <= hi <= 65535:
                        ports.update(range(lo, hi + 1))
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        return sorted(ports)
