#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import socket
import ssl
import urllib.parse

from modules.base import BaseModule
from utils.colors import Colors, print_section, print_status, print_table
from core.helpers import as_bool, safe_float


class TLSProbe(BaseModule):
    NAME = "recon/tls"
    DESCRIPTION = "TLS certificate, protocol and certificate-expiry inspection"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://docs.python.org/3/library/ssl.html"]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Hostname or https:// URL")
        self._add_option("PORT", "443", False, "TLS TCP port")
        self._add_option("TIMEOUT", "8", False, "Connection timeout in seconds")
        self._add_option("VERIFY", "true", False, "Verify certificate chain (true/false)")

    def run(self) -> dict:
        if not self._validate():
            return {}
        target = self.get_option("TARGET").strip()
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = int(self.get_option("PORT") or (parsed.port or 443))
        timeout = safe_float(self.get_option("TIMEOUT"), 8, 1, 30)
        verify = as_bool(self.get_option("VERIFY"), True)
        print_section(f"TLS Analysis → {Colors.CYAN}{host}:{port}{Colors.RESET}")
        try:
            context = ssl.create_default_context() if verify else ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    cert = sock.getpeercert()
                    cipher = sock.cipher()
                    version = sock.version()
            result = self._result(target, host, port, version, cipher, cert, verified=verify)
            print_table(
                ["Field", "Value"],
                [("Protocol", result.get("protocol", "")), ("Cipher", result.get("cipher", "")),
                 ("Issuer", result.get("issuer", "")), ("Subject", result.get("subject", "")),
                 ("Expires", result.get("expires", "")), ("Days remaining", result.get("days_remaining", ""))]
            )
            if result.get("days_remaining") is not None and result["days_remaining"] < 0:
                print_status("Certificate is expired.", "error")
            elif result.get("days_remaining") is not None and result["days_remaining"] <= 30:
                print_status(f"Certificate expires in {result['days_remaining']} day(s).", "warn")
            else:
                print_status("TLS analysis complete.", "ok")
            return result
        except ssl.SSLCertVerificationError as exc:
            print_status(f"Certificate verification failed: {exc}", "error")
            return {"target": target, "host": host, "port": port, "error": str(exc), "verification_failed": True}
        except Exception as exc:
            print_status(f"TLS connection failed: {exc}", "error")
            return {"target": target, "host": host, "port": port, "error": str(exc)}

    def _result(self, target, host, port, version, cipher, cert, verified):
        def names(items):
            out = []
            for item in items or []:
                for _, value in item:
                    if value not in out:
                        out.append(value)
            return out

        subject = names(cert.get("subject"))
        issuer = names(cert.get("issuer"))
        expires = cert.get("notAfter", "")
        days_remaining = None
        if expires:
            try:
                expiry = dt.datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                days_remaining = int((expiry - dt.datetime.utcnow()).total_seconds() / 86400)
            except ValueError:
                pass
        return {
            "target": target,
            "host": host,
            "port": port,
            "protocol": version or "",
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else None,
            "subject": ", ".join(subject),
            "issuer": ", ".join(issuer),
            "expires": expires,
            "days_remaining": days_remaining,
            "sans": [value for typ, value in cert.get("subjectAltName", []) if typ == "DNS"],
            "verified": verified,
        }
