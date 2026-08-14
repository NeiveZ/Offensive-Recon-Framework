#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/http_probe.py — HTTP fingerprinting: headers, technologies, redirects, cookies.

Updated behavior:
- If TARGET has no scheme, try HTTPS first and automatically fallback to HTTP.
- If FALLBACK is true, try the alternate scheme when the first one is refused/times out.
- Treat HTTP status errors like 403/404 as valid probe results, because headers still matter.
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


# Technology fingerprints (header → tech name)
HEADER_FINGERPRINTS = {
    "server": {
        "nginx":           "Nginx",
        "apache":          "Apache",
        "microsoft-iis":   "IIS",
        "cloudflare":      "Cloudflare",
        "lighttpd":        "Lighttpd",
        "openresty":       "OpenResty",
        "litespeed":       "LiteSpeed",
        "gunicorn":        "Gunicorn",
        "express":         "Express.js",
        "jetty":           "Jetty",
        "tomcat":          "Tomcat",
        "kestrel":         "Kestrel (.NET)",
    },
    "x-powered-by": {
        "php":             "PHP",
        "asp.net":         "ASP.NET",
        "express":         "Express.js",
        "next.js":         "Next.js",
        "ruby":            "Ruby",
    },
    "x-generator": {
        "drupal":          "Drupal",
        "wordpress":       "WordPress",
        "joomla":          "Joomla",
    },
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


class HTTPProbe(BaseModule):

    NAME        = "recon/http_probe"
    DESCRIPTION = "HTTP header analysis, technology fingerprinting & security header check"
    AUTHOR      = "NeiveZ"
    REFERENCES  = [
        "https://owasp.org/www-project-secure-headers/",
        "https://securityheaders.com",
    ]

    def _define_options(self):
        self._add_option("TARGET",     "",       False, "Target URL/domain (e.g. https://example.com or example.com)")
        self._add_option("INPUT",      "",       False, "File containing URLs/hostnames, one per line")
        self._add_option("SCHEME",     "auto",   False, "Scheme if TARGET has none: auto, http, or https")
        self._add_option("FALLBACK",   "true",   False, "Try alternate scheme if request fails (true/false)")
        self._add_option("FOLLOW",     "true",   False, "Follow redirects (true/false)")
        self._add_option("TIMEOUT",    "10",     False, "Request timeout in seconds")
        self._add_option("USER_AGENT", "ORFX/1.0 (Security Assessment)", False, "HTTP User-Agent string")

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _as_bool(value, default=True) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in ("1", "yes", "y", "true", "on")

    @staticmethod
    def _as_timeout(value, default=10) -> float:
        try:
            timeout = float(value)
            return timeout if timeout > 0 else default
        except Exception:
            return default

    @staticmethod
    def _replace_scheme(url: str, scheme: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment))

    def _build_candidates(self, raw_target: str, scheme_opt: str, fallback: bool) -> list:
        """Build a prioritized URL list to try."""
        target = raw_target.strip()
        scheme_opt = (scheme_opt or "auto").strip().lower()
        if scheme_opt not in ("auto", "http", "https"):
            scheme_opt = "auto"

        # Explicit scheme supplied by the user.
        if target.startswith(("http://", "https://")):
            candidates = [target]
            if fallback:
                parsed = urllib.parse.urlsplit(target)
                if parsed.scheme == "https":
                    candidates.append(self._replace_scheme(target, "http"))
                elif parsed.scheme == "http":
                    candidates.append(self._replace_scheme(target, "https"))
            return list(dict.fromkeys(candidates))

        # Bare host/domain supplied by the user.
        target = target.strip("/")
        if scheme_opt == "http":
            candidates = [f"http://{target}"]
            if fallback:
                candidates.append(f"https://{target}")
        elif scheme_opt == "https":
            candidates = [f"https://{target}"]
            if fallback:
                candidates.append(f"http://{target}")
        else:
            # Default keeps HTTPS preference, but falls back to HTTP for labs/legacy hosts.
            candidates = [f"https://{target}", f"http://{target}"]

        return list(dict.fromkeys(candidates))

    def _make_opener(self, follow: bool):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        handlers = [
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPHandler(),
        ]
        if not follow:
            handlers.append(NoRedirectHandler())
        return urllib.request.build_opener(*handlers)

    def _request_once(self, url: str, ua: str, follow: bool, timeout: float):
        opener = self._make_opener(follow)
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        try:
            resp = opener.open(req, timeout=timeout)
            return {
                "ok": True,
                "url": url,
                "headers": dict(resp.headers),
                "status": getattr(resp, "status", resp.getcode()),
                "final_url": resp.url,
                "error": None,
            }
        except urllib.error.HTTPError as e:
            # HTTP 403/404/500 still gives useful headers; keep it as a valid probe result.
            return {
                "ok": True,
                "url": url,
                "headers": dict(e.headers),
                "status": e.code,
                "final_url": getattr(e, "url", url),
                "error": None,
            }
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as e:
            return {
                "ok": False,
                "url": url,
                "headers": {},
                "status": None,
                "final_url": url,
                "error": str(e),
            }

    # ── Run ──────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        raw_target = self.get_option("TARGET").strip()
        input_file = self.get_option("INPUT") or ""
        if input_file:
            return self._run_input_file(input_file)
        if not raw_target:
            print_status("TARGET or INPUT is required.", "error")
            return {}
        scheme     = self.get_option("SCHEME") or "auto"
        fallback   = self._as_bool(self.get_option("FALLBACK"), True)
        follow     = self._as_bool(self.get_option("FOLLOW"), True)
        timeout    = self._as_timeout(self.get_option("TIMEOUT"), 10)
        ua         = self.get_option("USER_AGENT") or "ORFX/1.0 (Security Assessment)"

        candidates = self._build_candidates(raw_target, scheme, fallback)
        print_section(f"HTTP Probe → {Colors.CYAN}{candidates[0]}{Colors.RESET}")
        if len(candidates) > 1:
            print_status(f"Fallback candidates: {Colors.WHITE}{', '.join(candidates)}{Colors.RESET}", "info")

        attempts = []
        response = None
        for idx, url in enumerate(candidates, 1):
            if idx > 1:
                print_status(f"Trying fallback: {Colors.CYAN}{url}{Colors.RESET}", "info")
            current = self._request_once(url, ua, follow, timeout)
            attempts.append({"url": url, "ok": current["ok"], "error": current["error"]})
            if current["ok"]:
                response = current
                break
            print_status(f"Request failed on {url}: {current['error']}", "warn")

        if not response:
            print_status("Request failed for all candidates.", "error")
            return {
                "target": raw_target,
                "attempts": attempts,
                "error": "all candidates failed",
            }

        url = response["url"]
        headers = response["headers"]
        status = response["status"]
        final_url = response["final_url"]

        result = {
            "target":           raw_target,
            "resolved_url":     url,
            "final_url":        final_url,
            "status_code":      status,
            "headers":          headers,
            "technologies":     [],
            "security_headers": {},
            "attempts":         attempts,
        }

        # ── Status ───────────────────────────────────────────────────────────
        sc = str(status)
        sc_color = Colors.GREEN if sc.startswith("2") else Colors.YELLOW if sc.startswith("3") else Colors.RED
        print_status(f"Resolved   : {Colors.CYAN}{url}{Colors.RESET}", "result")
        print_status(f"Status     : {sc_color}{Colors.BOLD}{status}{Colors.RESET}", "result")

        if final_url != url:
            print_status(f"Redirect   : {Colors.CYAN}{final_url}{Colors.RESET}", "result")

        # ── All Headers ──────────────────────────────────────────────────────
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Response Headers{Colors.RESET}")
        for name, val in sorted(headers.items()):
            val = str(val)
            truncated = val[:100] + "…" if len(val) > 100 else val
            print(f"  {Colors.DARK_GRAY}{name:<35}{Colors.RESET}{Colors.WHITE}{truncated}{Colors.RESET}")

        # ── Technology Detection ─────────────────────────────────────────────
        techs = []
        lower_headers = {k.lower(): str(v).lower() for k, v in headers.items()}
        for header, patterns in HEADER_FINGERPRINTS.items():
            hval = lower_headers.get(header, "")
            for pattern, tech in patterns.items():
                if pattern in hval and tech not in techs:
                    techs.append(tech)

        if techs:
            result["technologies"] = techs
            print()
            print(f"  {Colors.BOLD}{Colors.WHITE}Detected Technologies{Colors.RESET}")
            for t in techs:
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {Colors.CYAN}{t}{Colors.RESET}")

        # ── Security Headers Audit ───────────────────────────────────────────
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Security Header Audit{Colors.RESET}")
        for sh in SECURITY_HEADERS:
            present = sh in lower_headers
            status_str = f"{Colors.GREEN}PRESENT{Colors.RESET}" if present else f"{Colors.RED}MISSING{Colors.RESET}"
            icon = f"{Colors.GREEN}[✓]{Colors.RESET}" if present else f"{Colors.RED}[✗]{Colors.RESET}"
            print(f"  {icon} {Colors.DARK_GRAY}{sh}{Colors.RESET} : {status_str}")
            result["security_headers"][sh] = present

        print()
        print_status("HTTP probe complete.", "ok")
        return result

    def _run_input_file(self, path: str) -> dict:
        """Probe one target per line from a previous ORFX report/list."""
        try:
            lines=open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError as e:
            print_status(f"Cannot read input file: {e}", "error")
            return {"input": path, "error": str(e), "targets": []}
        targets=[]
        for line in lines:
            value=line.strip()
            if not value or value.startswith("#"):
                continue
            # Accept plain hostnames, URLs, and simple whitespace-delimited report rows.
            if "|" in value:
                parts=[x.strip() for x in value.split("|")]
                value=parts[1] if len(parts) > 1 else parts[0]
            else:
                value=value.split()[0].strip()
            if value and value.lower() not in ("target","example.com"):
                targets.append(value)
        results=[]
        print_section(f"HTTP Probe → input file ({len(targets)} targets)")
        for target in list(dict.fromkeys(targets)):
            child=HTTPProbe()
            for key in ("SCHEME","FALLBACK","FOLLOW","TIMEOUT","USER_AGENT"):
                child.set_option(key,self.get_option(key))
            child.set_option("TARGET",target)
            results.append(child.run())
        return {"input":path,"targets":targets,"results":results,"total":len(results)}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that suppresses all redirects."""
    def redirect_request(self, *args, **kwargs):
        return None
