#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/whois_lookup.py — WHOIS lookup via system whois binary or python-whois.
"""

import subprocess
import shutil
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


class WhoisLookup(BaseModule):

    NAME        = "recon/whois"
    DESCRIPTION = "WHOIS domain/IP lookup and registrar information"
    AUTHOR      = "NeiveZ"
    REFERENCES  = ["https://www.whois.com"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Domain or IP address to query")

    def run(self) -> dict:
        if not self._validate():
            return {}

        target = self.get_option("TARGET").strip()
        print_section(f"WHOIS Lookup → {Colors.CYAN}{target}{Colors.RESET}")

        result = {}

        # Try system whois first
        if shutil.which("whois"):
            result = self._system_whois(target)
        else:
            # Try python-whois
            try:
                import whois
                w = whois.whois(target)
                result = {
                    "domain":     str(w.domain_name or ""),
                    "registrar":  str(w.registrar or ""),
                    "created":    str(w.creation_date or ""),
                    "expires":    str(w.expiration_date or ""),
                    "updated":    str(w.updated_date or ""),
                    "name_servers": ", ".join(w.name_servers or []),
                    "status":     str(w.status or ""),
                    "emails":     ", ".join(w.emails or []) if isinstance(w.emails, list) else str(w.emails or ""),
                    "org":        str(w.org or ""),
                    "country":    str(w.country or ""),
                }
            except ImportError:
                print_status("Neither 'whois' binary nor 'python-whois' package found.", "error")
                print_status("Install with: pip install python-whois --break-system-packages", "info")
                return {}
            except Exception as e:
                print_status(f"WHOIS query failed: {e}", "error")
                return {}

        if result:
            self._print_whois(result)
        return {"target": target, **result}

    def _system_whois(self, target: str) -> dict:
        """Run system whois binary and parse key fields."""
        try:
            out = subprocess.check_output(
                ["whois", target], stderr=subprocess.DEVNULL, timeout=10
            ).decode("utf-8", errors="replace")
        except Exception as e:
            print_status(f"whois command failed: {e}", "error")
            return {}

        fields = {
            "Domain Name":     "domain",
            "Registrar":       "registrar",
            "Creation Date":   "created",
            "Registry Expiry": "expires",
            "Updated Date":    "updated",
            "Name Server":     "name_servers",
            "Registrant Org":  "org",
            "Registrant Country": "country",
            "Registrant Email":   "email",
            "DNSSEC":          "dnssec",
        }
        result = {}
        for line in out.splitlines():
            for label, key in fields.items():
                if line.strip().startswith(label):
                    val = line.split(":", 1)[-1].strip()
                    if key in result:
                        result[key] += f", {val}"
                    else:
                        result[key] = val

        if not result:
            # Just dump raw output truncated
            result["raw"] = out[:2000]

        return result

    def _print_whois(self, data: dict):
        labels = {
            "domain":       "Domain",
            "registrar":    "Registrar",
            "created":      "Created",
            "expires":      "Expires",
            "updated":      "Updated",
            "name_servers": "Name Servers",
            "org":          "Organization",
            "country":      "Country",
            "email":        "Email",
            "dnssec":       "DNSSEC",
        }
        for key, label in labels.items():
            if data.get(key):
                print(f"  {Colors.DARK_GRAY}{label:<16}{Colors.RESET}: {Colors.WHITE}{data[key]}{Colors.RESET}")
        if "raw" in data:
            print(f"\n  {Colors.DARK_GRAY}Raw output:{Colors.RESET}\n")
            for line in data["raw"].splitlines():
                print(f"    {Colors.DARK_GRAY}{line}{Colors.RESET}")
        print()
        print_status("WHOIS lookup complete.", "ok")
