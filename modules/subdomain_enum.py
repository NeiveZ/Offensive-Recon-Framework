#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/subdomain_enum.py — Subdomain enumeration via DNS brute-force + passive sources.
"""

import socket
import concurrent.futures
import os
import sys
import re
from urllib.parse import urlparse
from modules.base import BaseModule
from utils.colors import Colors, print_status, loading_bar, print_section


# Built-in wordlist (expanded at runtime if wordlists/subdomains.txt exists)
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "app", "portal", "vpn", "remote", "blog", "shop", "cdn", "static",
    "media", "images", "login", "auth", "dashboard", "internal", "corp",
    "intranet", "secure", "help", "support", "docs", "wiki", "git",
    "gitlab", "jenkins", "ci", "cd", "prometheus", "grafana", "jira",
    "confluence", "ldap", "smtp", "webmail", "exchange", "backup",
    "monitor", "status", "beta", "alpha", "demo", "sandbox", "db",
    "database", "mysql", "postgres", "redis", "elastic", "kibana",
    "ns1", "ns2", "mx", "mx1", "mx2", "vpn1", "vpn2", "proxy",
]


class SubdomainEnumerator(BaseModule):

    NAME        = "subdomain/enum"
    DESCRIPTION = "Passive + active subdomain discovery via DNS brute-force"
    AUTHOR      = "NeiveZ"
    REFERENCES  = [
        "https://github.com/danielmiessler/SecLists",
        "https://crt.sh",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",     True,  "Target domain (e.g. example.com)")
        self._add_option("THREADS",  "50",   False, "Number of concurrent threads")
        self._add_option("WORDLIST", "",     False, "Path to custom wordlist file")
        self._add_option("TIMEOUT",  "2",    False, "DNS resolution timeout in seconds")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        target = self._normalize_target(self.get_option("TARGET"))
        if not target or not self._valid_domain(target):
            print_status(f"Invalid target domain: {self.get_option('TARGET')}", "error")
            return {}

        threads = self._safe_int(self.get_option("THREADS"), default=50, minimum=1, maximum=500)
        timeout = self._safe_float(self.get_option("TIMEOUT"), default=2.0, minimum=0.2, maximum=60.0)
        wl_path = self.get_option("WORDLIST") or ""

        wordlist = self._load_wordlist(wl_path)
        if not wordlist:
            print_status("Wordlist is empty.", "error")
            return {}

        print_section(f"Subdomain Enumeration → {Colors.CYAN}{target}{Colors.RESET}")
        print_status(f"Wordlist size : {Colors.WHITE}{len(wordlist)}{Colors.RESET} subdomains", "info")
        print_status(f"Threads       : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print_status(f"Timeout       : {Colors.WHITE}{timeout}s{Colors.RESET}", "info")
        print()

        found: list[dict] = []
        total = len(wordlist)
        completed = 0

        socket.setdefaulttimeout(timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(self._resolve, f"{sub}.{target}", timeout): sub
                for sub in wordlist
            }
            for future in concurrent.futures.as_completed(future_map):
                completed += 1
                loading_bar("Scanning", total, completed)
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    found.append(result)
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.flush()
                    print_status(
                        f"{Colors.GREEN}{result['subdomain']:<40}{Colors.RESET}"
                        f"{Colors.WHITE}{', '.join(result['ips'])}{Colors.RESET}",
                        "found"
                    )

        found = sorted(found, key=lambda x: x["subdomain"])
        print()
        print_status(f"Scan complete. Found {Colors.GREEN}{len(found)}{Colors.RESET} subdomains.", "ok")
        print()

        return {"target": target, "subdomains": found, "total": len(found)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve(self, fqdn: str, timeout: float) -> dict | None:
        """Attempt to resolve an FQDN; return dict if successful."""
        try:
            socket.setdefaulttimeout(timeout)
            _name, _aliases, ips = socket.gethostbyname_ex(fqdn)
            ips = sorted(set(ips))
            if ips:
                return {"subdomain": fqdn, "ip": ips[0], "ips": ips}
        except (socket.gaierror, socket.timeout, OSError):
            return None
        return None

    def _load_wordlist(self, path: str) -> list[str]:
        """Load wordlist from file or fall back to built-in list."""
        candidates = []

        if path:
            candidates.append(path)

        bundled = os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains.txt")
        candidates.append(bundled)

        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                try:
                    with open(candidate, encoding="utf-8", errors="ignore") as f:
                        words = self._clean_wordlist(f.readlines())
                    print_status(f"Loaded wordlist: {candidate} ({len(words)} entries)", "info")
                    return words
                except Exception as e:
                    print_status(f"Failed to load wordlist '{candidate}' ({e}), trying fallback.", "warn")

        return self._clean_wordlist(DEFAULT_WORDLIST)

    def _clean_wordlist(self, lines) -> list[str]:
        """Normalize, deduplicate and filter wordlist entries."""
        words = []
        seen = set()
        for line in lines:
            word = str(line).strip().lower()
            if not word or word.startswith("#"):
                continue
            # Accept either "admin" or "admin.example.com" style lines.
            word = word.split()[0].strip(".")
            if "://" in word:
                word = self._normalize_target(word)
            # Keep only the left-most label when a full FQDN appears in a wordlist.
            if "." in word:
                word = word.split(".")[0]
            if not re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", word):
                continue
            if word not in seen:
                seen.add(word)
                words.append(word)
        return words

    def _normalize_target(self, value: str) -> str:
        """Normalize URL/domain input without the unsafe behavior of str.lstrip()."""
        raw = (value or "").strip().lower()
        if not raw:
            return ""
        if "://" in raw:
            parsed = urlparse(raw)
            raw = parsed.netloc or parsed.path
        raw = raw.split("/")[0].split(":")[0].strip(".")
        if raw.startswith("www."):
            raw = raw[4:]
        return raw

    def _valid_domain(self, domain: str) -> bool:
        """Basic domain validation."""
        if len(domain) > 253 or "." not in domain:
            return False
        labels = domain.split(".")
        return all(re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label) for label in labels)

    def _safe_int(self, value, default: int, minimum: int, maximum: int) -> int:
        try:
            num = int(str(value).strip())
        except Exception:
            print_status(f"Invalid integer value '{value}', using {default}.", "warn")
            return default
        if num < minimum:
            return minimum
        if num > maximum:
            print_status(f"Value {num} too high, limiting to {maximum}.", "warn")
            return maximum
        return num

    def _safe_float(self, value, default: float, minimum: float, maximum: float) -> float:
        try:
            num = float(str(value).strip())
        except Exception:
            print_status(f"Invalid numeric value '{value}', using {default}.", "warn")
            return default
        if num < minimum:
            return minimum
        if num > maximum:
            print_status(f"Value {num} too high, limiting to {maximum}.", "warn")
            return maximum
        return num
