#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/port_scanner.py — TCP port scanner with service detection and banner grabbing.
"""

import socket
import concurrent.futures
from modules.base import BaseModule
from utils.colors import Colors, print_status, loading_bar, print_section, print_table

# Common ports with service labels
COMMON_PORTS = {
    21: "FTP",      22: "SSH",      23: "Telnet",   25: "SMTP",
    53: "DNS",      80: "HTTP",     110: "POP3",     143: "IMAP",
    443: "HTTPS",   445: "SMB",     3306: "MySQL",   3389: "RDP",
    5432: "Postgres", 5900: "VNC",  6379: "Redis",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 27017: "MongoDB", 9200: "Elasticsearch",
}

TOP_100 = list(COMMON_PORTS.keys()) + [
    20, 69, 79, 88, 111, 119, 135, 137, 138, 139, 161, 162,
    389, 500, 514, 515, 587, 636, 993, 995, 1080, 1194, 1433,
    1521, 1723, 2049, 2082, 2083, 2222, 3000, 4000, 4444, 4848,
    5000, 5001, 5432, 5800, 6000, 6001, 7070, 8000, 8001, 8008,
    8009, 8081, 8082, 8083, 8161, 8880, 9000, 9090, 9100, 9300,
    10000, 11211, 27017, 50000,
]


class PortScanner(BaseModule):

    NAME        = "recon/port_scan"
    DESCRIPTION = "TCP port scanner with service detection and banner grabbing"
    AUTHOR      = "NeiveZ"
    REFERENCES  = ["https://nmap.org/book/man-port-scanning-techniques.html"]

    def _define_options(self):
        self._add_option("TARGET",    "",      True,  "Target IP or hostname")
        self._add_option("PORTS",     "top100",False, "Ports to scan: top100, all, or 80,443,8080")
        self._add_option("THREADS",   "100",   False, "Concurrent threads")
        self._add_option("TIMEOUT",   "1",     False, "Connection timeout in seconds")
        self._add_option("BANNERS",   "true",  False, "Attempt banner grabbing (true/false)")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        target   = self.get_option("TARGET").strip()
        ports    = self._parse_ports(self.get_option("PORTS") or "top100")
        threads  = int(self.get_option("THREADS") or 100)
        timeout  = float(self.get_option("TIMEOUT") or 1)
        banners  = self.get_option("BANNERS").lower() == "true"

        # Resolve hostname → IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            print_status(f"Cannot resolve target: {e}", "error")
            return {}

        print_section(f"Port Scan → {Colors.CYAN}{target}{Colors.RESET} ({ip})")
        print_status(f"Ports   : {Colors.WHITE}{len(ports)}{Colors.RESET}", "info")
        print_status(f"Threads : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print_status(f"Timeout : {Colors.WHITE}{timeout}s{Colors.RESET}", "info")
        print_status(f"Banners : {Colors.WHITE}{banners}{Colors.RESET}", "info")
        print()

        open_ports: list[dict] = []
        total = len(ports)
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(self._scan_port, ip, port, timeout, banners): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_map):
                completed += 1
                loading_bar("Scanning", total, completed)
                result = future.result()
                if result:
                    open_ports.append(result)
                    import sys
                    sys.stdout.write("\r" + " " * 70 + "\r")
                    svc   = result.get("service", "unknown")
                    ban   = result.get("banner", "")
                    banner_str = f"  {Colors.DARK_GRAY}│ {ban[:60]}{Colors.RESET}" if ban else ""
                    print_status(
                        f"{Colors.GREEN}{result['port']:<6}{Colors.RESET}"
                        f"{Colors.CYAN}{svc:<15}{Colors.RESET}"
                        f"{Colors.WHITE}OPEN{Colors.RESET}"
                        f"{banner_str}",
                        "found"
                    )

        print()
        print_status(f"Scan complete. {Colors.GREEN}{len(open_ports)}{Colors.RESET} open port(s) on {Colors.CYAN}{target}{Colors.RESET}.", "ok")

        if open_ports:
            print()
            print_table(
                ["Port", "Service", "Status", "Banner"],
                [(p["port"], p["service"], "OPEN", p.get("banner", "")[:50]) for p in open_ports]
            )

        return {
            "target":     target,
            "ip":         ip,
            "open_ports": open_ports,
            "total_open": len(open_ports),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _scan_port(self, ip: str, port: int, timeout: float, grab_banner: bool) -> dict | None:
        """Attempt TCP connection; optionally grab banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    banner = ""
                    if grab_banner:
                        try:
                            s.settimeout(1.0)
                            # Send a generic probe for HTTP
                            if port in (80, 8080, 8000, 8008, 8081):
                                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            else:
                                s.send(b"\r\n")
                            raw = s.recv(256)
                            banner = raw.decode("utf-8", errors="replace").strip().split("\n")[0]
                        except Exception:
                            pass
                    return {
                        "port":    port,
                        "service": COMMON_PORTS.get(port, "unknown"),
                        "banner":  banner,
                    }
        except Exception:
            pass
        return None

    def _parse_ports(self, spec: str) -> list[int]:
        """Parse port specification string into a list of integers."""
        spec = spec.strip().lower()
        if spec == "top100":
            return sorted(set(TOP_100))
        if spec == "all":
            return list(range(1, 65536))
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                try:
                    ports.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return sorted(set(ports))
