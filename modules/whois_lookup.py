#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess

from modules.base import BaseModule
from utils.colors import Colors, print_section, print_status


class WhoisLookup(BaseModule):
    NAME = "recon/whois"
    DESCRIPTION = "WHOIS lookup using the local client or python-whois fallback"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://www.iana.org/whois"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Domain or IP address")
        self._add_option("TIMEOUT", "15", False, "WHOIS timeout")

    def run(self):
        if not self._validate():
            return {}
        target = self.get_option("TARGET").strip()
        print_section(f"WHOIS Lookup → {Colors.CYAN}{target}{Colors.RESET}")
        if shutil.which("whois"):
            data = self._system(target)
            source = "system-whois"
        else:
            data = self._python(target)
            source = "python-whois" if data else "none"
        if not data:
            print_status("WHOIS returned no structured information.", "warn")
            return {"target": target, "source": source, "error": "No WHOIS data"}
        for key, value in data.items():
            if value:
                print(f"  {Colors.DARK_GRAY}{key:<18}{Colors.RESET}: {Colors.WHITE}{value}{Colors.RESET}")
        print_status("WHOIS lookup complete.", "ok")
        return {"target": target, "source": source, **data}

    def _system(self, target):
        try:
            out = subprocess.check_output(["whois", target], stderr=subprocess.DEVNULL, timeout=int(self.get_option("TIMEOUT") or 15)).decode("utf-8", errors="replace")
        except Exception as exc:
            print_status(f"whois command failed: {exc}", "warn")
            return {}
        labels = {
            "Domain Name":"domain", "Registrar":"registrar", "Creation Date":"created", "Registry Expiry Date":"expires", "Registrar Registration Expiration Date":"expires", "Updated Date":"updated", "Name Server":"name_servers", "Registrant Organization":"org", "Registrant Country":"country", "Registrant Email":"email", "DNSSEC":"dnssec"
        }
        result = {}
        for line in out.splitlines():
            if ":" not in line:
                continue
            label, value = [x.strip() for x in line.split(":", 1)]
            key = labels.get(label)
            if key and value:
                if key in result:
                    result[key] += ", " + value
                else:
                    result[key] = value
        if not result:
            result["raw"] = out[:4000]
        return result

    def _python(self, target):
        try:
            import whois
            w = whois.whois(target)
            return {"domain": str(w.domain_name or ""), "registrar": str(w.registrar or ""), "created": str(w.creation_date or ""), "expires": str(w.expiration_date or ""), "updated": str(w.updated_date or ""), "name_servers": ", ".join(w.name_servers or []), "org": str(w.org or ""), "country": str(w.country or "")}
        except ImportError:
            print_status("No WHOIS client is installed. Install 'whois' or python-whois.", "warn")
        except Exception as exc:
            print_status(f"python-whois failed: {exc}", "warn")
        return {}
