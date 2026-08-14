#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import urllib.parse
import urllib.request

from modules.base import BaseModule
from utils.colors import Colors, loading_bar, print_section, print_status, print_table
from core.helpers import as_bool, normalize_domain, resolve_addresses, safe_float, safe_int, valid_domain

DEFAULT_WORDLIST = ["www","mail","ftp","api","dev","staging","test","app","portal","vpn","remote","blog","shop","cdn","static","media","images","login","auth","dashboard","internal","corp","intranet","secure","help","support","docs","wiki","git","gitlab","jenkins","ci","monitor","status","beta","alpha","demo","sandbox","db","database","mysql","postgres","redis","elastic","kibana","ns1","ns2","mx","mx1","mx2","proxy"]


class SubdomainEnumerator(BaseModule):
    NAME = "subdomain/enum"
    DESCRIPTION = "Certificate-transparency discovery plus active DNS enumeration and IPv4/IPv6 resolution"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://crt.sh"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target domain")
        self._add_option("THREADS", "50", False, "Concurrent DNS lookups (1-200)")
        self._add_option("WORDLIST", "", False, "Custom subdomain wordlist")
        self._add_option("TIMEOUT", "3", False, "DNS timeout")
        self._add_option("RESOLVE", "false", False, "Resolve passive names too")
        self._add_option("PASSIVE", "true", False, "Query crt.sh")
        self._add_option("ACTIVE", "true", False, "Run wordlist enumeration")

    def run(self):
        if not self._validate():
            return {}
        target = normalize_domain(self.get_option("TARGET"))
        if not valid_domain(target):
            print_status(f"Invalid target domain: {target}", "error")
            return {"target": target, "error": "Invalid domain"}
        timeout = safe_float(self.get_option("TIMEOUT"), 3, 0.5, 30)
        threads = safe_int(self.get_option("THREADS"), 50, 1, 200)
        print_section(f"Subdomain Enumeration → {Colors.CYAN}{target}{Colors.RESET}")
        passive = self._crtsh(target, timeout) if as_bool(self.get_option("PASSIVE"), True) else []
        if as_bool(self.get_option("PASSIVE"), True):
            print_status(f"Passive discovery: {len(passive)} name(s)", "info")
        candidates = set(passive)
        active_names = []
        if as_bool(self.get_option("ACTIVE"), True):
            words = self._load_wordlist(self.get_option("WORDLIST") or "")
            active_names = [f"{word}.{target}" for word in words]
            candidates.update(active_names)
            print_status(f"Active wordlist: {len(words)} candidate(s)", "info")
        resolve_all = as_bool(self.get_option("RESOLVE"), False)
        to_resolve = sorted(x for x in candidates if resolve_all or x in active_names)
        resolved = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._resolve, host, timeout): host for host in to_resolve}
            total = len(futures)
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                loading_bar("Resolving", total, done)
                try:
                    item = future.result()
                except Exception:
                    item = None
                if item:
                    resolved.append(item)
        if to_resolve:
            print()
        resolved.sort(key=lambda x: x["subdomain"])
        print_status(f"Enumeration complete. Found {len(resolved)} resolved subdomain(s).", "ok")
        if resolved:
            print_table(["Subdomain", "IPv4", "IPv6"], [(x["subdomain"], ", ".join(x["ipv4"]), ", ".join(x["ipv6"])) for x in resolved])
        return {"target": target, "passive_subdomains": sorted(passive), "subdomains": resolved, "candidates": len(candidates), "total": len(resolved)}

    def _crtsh(self, target, timeout):
        url = "https://crt.sh/?q=%25." + urllib.parse.quote(target, safe="") + "&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ORFX/3.2"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            names = set()
            for row in data if isinstance(data, list) else []:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name == target or name.endswith("." + target):
                        names.add(name)
            return sorted(names)
        except Exception as exc:
            print_status(f"crt.sh unavailable: {exc}", "warn")
            return []

    def _resolve(self, fqdn, timeout):
        addresses = resolve_addresses(fqdn)
        if not addresses["ipv4"] and not addresses["ipv6"]:
            return None
        return {"subdomain": fqdn, "ipv4": addresses["ipv4"], "ipv6": addresses["ipv6"], "ips": addresses["ipv4"] + addresses["ipv6"]}

    def _load_wordlist(self, path):
        candidates = [path] if path else []
        candidates.append(os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains.txt"))
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                with open(candidate, encoding="utf-8", errors="ignore") as handle:
                    return self._clean(handle.read().splitlines())
        return DEFAULT_WORDLIST

    def _clean(self, lines):
        out, seen = [], set()
        for line in lines:
            word = str(line).strip().split()[0] if str(line).strip() else ""
            word = word.strip(".").lower()
            if "." in word:
                word = word.split(".")[0]
            if word and re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", word) and word not in seen:
                seen.add(word); out.append(word)
        return out
