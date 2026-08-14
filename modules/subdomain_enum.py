#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import urllib.parse
import urllib.request
import time
import random

from modules.base import BaseModule
from utils.colors import Colors, loading_bar, print_section, print_status, print_table
from core.helpers import as_bool, normalize_domain, resolve_addresses, safe_float, safe_int, valid_domain, choose_user_agent, load_user_agents

DEFAULT_WORDLIST = ["www","mail","ftp","api","dev","staging","test","app","portal","vpn","remote","blog","shop","cdn","static","media","images","login","auth","dashboard","internal","corp","intranet","secure","help","support","docs","wiki","git","gitlab","jenkins","ci","monitor","status","beta","alpha","demo","sandbox","db","database","mysql","postgres","redis","elastic","kibana","ns1","ns2","mx","mx1","mx2","proxy"]


class SubdomainEnumerator(BaseModule):
    NAME = "subdomain/enum"
    DESCRIPTION = "Certificate-transparency discovery plus active DNS enumeration and IPv4/IPv6 resolution"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://crt.sh"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target domain")
        self._add_option("THREADS", "auto", False, "Concurrent DNS lookups (1-100); profile controls the default")
        self._add_option("WORDLIST", "", False, "Custom subdomain wordlist")
        self._add_option("TIMEOUT", "auto", False, "DNS lookup timeout; profile controls the default")
        self._add_option("RETRIES", "auto", False, "Retries for transient DNS failures; profile controls the default")
        self._add_option("DELAY", "auto", False, "Per-candidate delay in seconds; profile controls the default")
        self._add_option("PROFILE", "accurate", False, "fast, balanced, or accurate scan profile")
        self._add_option("RESOLVE", "false", False, "Resolve passive names too")
        self._add_option("PASSIVE", "true", False, "Query crt.sh")
        self._add_option("ACTIVE", "true", False, "Run wordlist enumeration")
        self._add_option("USER_AGENT", "ORFX/3.2.3 (Authorized Recon)", False, "Passive HTTP User-Agent; use random/rotate or @/path/to/agents.txt for controlled rotation")

    def run(self):
        if not self._validate():
            return {}
        target = normalize_domain(self.get_option("TARGET"))
        if not valid_domain(target):
            print_status(f"Invalid target domain: {target}", "error")
            return {"target": target, "error": "Invalid domain"}
        profile = str(self.get_option("PROFILE") or "accurate").strip().lower()
        profile_defaults = {
            "fast": {"threads": 30, "timeout": 2.0, "retries": 1, "delay": 0.0},
            "balanced": {"threads": 15, "timeout": 3.0, "retries": 2, "delay": 0.01},
            "accurate": {"threads": 5, "timeout": 5.0, "retries": 3, "delay": 0.05},
        }
        profile_cfg = profile_defaults.get(profile, profile_defaults["accurate"])
        threads_value = self.get_option("THREADS")
        timeout_value = self.get_option("TIMEOUT")
        retries_value = self.get_option("RETRIES")
        delay_value = self.get_option("DELAY")
        threads = profile_cfg["threads"] if str(threads_value).lower() in {"", "auto", "default"} else safe_int(threads_value, profile_cfg["threads"], 1, 100)
        timeout = profile_cfg["timeout"] if str(timeout_value).lower() in {"", "auto", "default"} else safe_float(timeout_value, profile_cfg["timeout"], 0.5, 30)
        retries = profile_cfg["retries"] if str(retries_value).lower() in {"", "auto", "default"} else safe_int(retries_value, profile_cfg["retries"], 0, 5)
        delay = profile_cfg["delay"] if str(delay_value).lower() in {"", "auto", "default"} else safe_float(delay_value, profile_cfg["delay"], 0, 1.0)
        user_agent_value = str(self.get_option("USER_AGENT") or "")
        user_agent_pool = load_user_agents(user_agent_value[1:] if user_agent_value.startswith("@") else None)
        self._passive_error = ""
        passive = self._crtsh(target, timeout, user_agent_value, user_agent_pool) if as_bool(self.get_option("PASSIVE"), True) else []
        candidates = set(passive)
        active_names = []
        words = []
        if as_bool(self.get_option("ACTIVE"), True):
            words = self._load_wordlist(self.get_option("WORDLIST") or "")
            active_names = [word if word.endswith("." + target) else f"{word}.{target}" for word in words]
            candidates.update(active_names)
        resolve_all = as_bool(self.get_option("RESOLVE"), False)
        to_resolve = sorted(x for x in candidates if resolve_all or x in active_names)
        resolved = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._resolve_with_retries, host, timeout, retries, delay): host for host in to_resolve}
            total = len(futures)
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                loading_bar("Resolving candidates", total, done)
                try:
                    item = future.result()
                except Exception:
                    item = None
                if item:
                    resolved.append(item)
        if to_resolve:
            print()
        resolved.sort(key=lambda x: x["subdomain"])
        if resolved:
            display = resolved[:100]
            rows = []
            for item in display:
                ipv4 = item.get("ipv4", [])
                ipv6 = item.get("ipv6", [])
                rows.append((
                    item["subdomain"],
                    self._compact_addresses(ipv4),
                    self._compact_addresses(ipv6),
                ))
            print_table(["Subdomain", "IPv4", "IPv6"], rows)
            if len(resolved) > len(display):
                print_status(f"{len(resolved) - len(display)} additional results omitted from terminal view; use --json/--html for complete output.", "info")
        if self._passive_error:
            print_status("Passive source unavailable; active enumeration completed.", "warn")
        print_status(
            f"Complete | passive={len(passive)} | candidates={len(candidates)} | resolved={len(resolved)}",
            "ok",
        )
        return {
            "target": target,
            "passive_subdomains": sorted(passive),
            "subdomains": resolved,
            "candidates": len(candidates),
            "active_candidates": len(words),
            "total": len(resolved),
            "passive_error": self._passive_error,
            "profile": profile,
            "threads": threads,
            "timeout": timeout,
            "retries": retries,
            "delay": delay,
        }

    @staticmethod
    def _compact_addresses(addresses):
        values = [str(x) for x in addresses if x]
        if not values:
            return "-"
        preview = values[:2]
        extra = len(values) - len(preview)
        suffix = f" … +{extra}" if extra else ""
        return ", ".join(preview) + suffix

    def _crtsh(self, target, timeout, user_agent_value="", user_agent_pool=None):
        url = "https://crt.sh/?q=%25." + urllib.parse.quote(target, safe="") + "&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": choose_user_agent(user_agent_value, user_agent_pool)})
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
            self._passive_error = str(exc)
            return []

    def _resolve(self, fqdn, timeout):
        addresses = resolve_addresses(fqdn, timeout=timeout)
        if not addresses["ipv4"] and not addresses["ipv6"]:
            return None
        return {"subdomain": fqdn, "ipv4": addresses["ipv4"], "ipv6": addresses["ipv6"], "ips": addresses["ipv4"] + addresses["ipv6"]}

    def _resolve_with_retries(self, fqdn, timeout, retries, delay):
        attempts = retries + 1
        for attempt in range(attempts):
            if delay:
                time.sleep(delay)
            item = self._resolve(fqdn, timeout)
            if item:
                return item
            if attempt < attempts - 1:
                time.sleep(min(0.5, 0.05 * (attempt + 1) + random.random() * 0.02))
        return None

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
            word = word.strip(". ").lower()
            if word.endswith("@"):
                word = word[:-1]
            labels = word.split(".")
            if not word or any(not label or not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label) for label in labels):
                continue
            if word not in seen:
                seen.add(word); out.append(word)
        return out
