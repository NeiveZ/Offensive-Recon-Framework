#!/usr/bin/env python3
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from modules.base import BaseModule
from utils.colors import Colors, print_section, print_status, print_table
from core.helpers import as_bool, safe_float

HEADER_FINGERPRINTS = {
    "server": {"nginx":"Nginx","apache":"Apache","microsoft-iis":"IIS","cloudflare":"Cloudflare","lighttpd":"Lighttpd","openresty":"OpenResty","litespeed":"LiteSpeed","gunicorn":"Gunicorn","express":"Express.js","jetty":"Jetty","tomcat":"Tomcat","kestrel":"Kestrel (.NET)"},
    "x-powered-by": {"php":"PHP","asp.net":"ASP.NET","express":"Express.js","next.js":"Next.js","ruby":"Ruby"},
    "x-generator": {"drupal":"Drupal","wordpress":"WordPress","joomla":"Joomla"},
    "via": {"cloudflare":"Cloudflare"},
}
SECURITY_HEADERS = ["strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy","permissions-policy"]


class HTTPProbe(BaseModule):
    NAME = "recon/http_probe"
    DESCRIPTION = "HTTP/HTTPS probing, redirects, headers, technologies and security headers"
    AUTHOR = "NeiveZ"
    REFERENCES = ["https://owasp.org/www-project-secure-headers/"]

    def _define_options(self):
        self._add_option("TARGET", "", False, "Target URL or hostname")
        self._add_option("INPUT", "", False, "File containing URLs/hostnames")
        self._add_option("SCHEME", "auto", False, "auto, http or https")
        self._add_option("FALLBACK", "true", False, "Try alternate scheme if the first fails")
        self._add_option("FOLLOW", "true", False, "Follow redirects")
        self._add_option("TIMEOUT", "10", False, "Request timeout")
        self._add_option("USER_AGENT", "ORFX/3.2 (Security Assessment)", False, "HTTP User-Agent")

    def run(self):
        targets = self._targets()
        if not targets:
            print_status("No HTTP target was supplied. Use -u or -i.", "error")
            return {"error": "No HTTP target supplied", "results": []}
        results = []
        for target in targets:
            results.append(self._probe(target))
        if len(results) == 1:
            return results[0]
        return {"target": targets[0], "results": results, "total": len(results)}

    def _targets(self):
        vals = []
        target = str(self.get_option("TARGET") or "").strip()
        if target:
            vals.append(target)
        path = str(self.get_option("INPUT") or "").strip()
        if path:
            try:
                for line in open(path, encoding="utf-8", errors="ignore"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    candidate = line
                    if "|" in line:
                        parts = [part.strip() for part in line.split("|") if part.strip()]
                        candidate = next((part for part in parts[1:] if "." in part or part.startswith(("http://", "https://"))), parts[0])
                    if candidate.startswith(("http://", "https://")) or "." in candidate or candidate.replace(".", "").isdigit():
                        vals.append(candidate)
            except OSError as exc:
                print_status(f"Could not read input file: {exc}", "error")
        seen = set()
        return [x for x in vals if not (x.lower() in seen or seen.add(x.lower()))]

    def _probe(self, raw):
        candidates = self._candidates(raw)
        timeout = safe_float(self.get_option("TIMEOUT"), 10, 1, 30)
        follow = as_bool(self.get_option("FOLLOW"), True)
        user_agent = str(self.get_option("USER_AGENT"))
        last_error = ""
        for url in candidates:
            try:
                context = ssl.create_default_context()
                request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"}, method="GET")
                handlers = [_NoRedirect()] if not follow else [urllib.request.HTTPRedirectHandler()]
                handlers.append(urllib.request.HTTPSHandler(context=context))
                opener = urllib.request.build_opener(*handlers)
                with opener.open(request, timeout=timeout) as response:
                    result = self._result_from_response(raw, response, url)
                    print_section(f"HTTP Probe → {Colors.CYAN}{url}{Colors.RESET}")
                    self._display(result)
                    return result
            except urllib.error.HTTPError as exc:
                headers = dict(exc.headers.items()) if exc.headers else {}
                result = self._result_from_headers(raw, exc.geturl(), exc.code, headers)
                print_section(f"HTTP Probe → {Colors.CYAN}{url}{Colors.RESET}")
                print_status(f"HTTP {exc.code} returned; response remains a valid reconnaissance result.", "warn")
                self._display(result)
                return result
            except Exception as exc:
                last_error = str(exc)
                continue
        print_status(f"HTTP probe failed: {last_error or 'unknown error'}", "error")
        return {"target": raw, "host": raw, "error": last_error or "HTTP probe failed"}

    def _candidates(self, raw):
        target = raw.strip()
        scheme = str(self.get_option("SCHEME") or "auto").lower()
        fallback = as_bool(self.get_option("FALLBACK"), True)
        if not target.startswith(("http://", "https://")):
            target = target.rstrip("/")
            first = "https://" if scheme in ("auto", "https") else "http://"
            second = "http://" if first == "https://" else "https://"
            return [first + target] + ([second + target] if fallback and scheme == "auto" else ([second + target] if fallback else []))
        parsed = urllib.parse.urlsplit(target)
        candidates = [target]
        if fallback:
            other = "http" if parsed.scheme == "https" else "https"
            candidates.append(urllib.parse.urlunsplit((other, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment)))
        return candidates

    def _result_from_response(self, raw, response, url):
        return self._result_from_headers(raw, response.geturl(), response.status, dict(response.headers.items()), body=response.read(2048))

    def _result_from_headers(self, raw, final_url, status, headers, body=b""):
        tech = set()
        low = {str(k).lower(): str(v) for k, v in headers.items()}
        for header, mapping in HEADER_FINGERPRINTS.items():
            value = low.get(header, "").lower()
            for needle, name in mapping.items():
                if needle in value:
                    tech.add(name)
        body_text = body.decode("utf-8", errors="ignore").lower()
        if "wp-content" in body_text:
            tech.add("WordPress")
        return {
            "target": raw,
            "host": urllib.parse.urlsplit(final_url).hostname or raw,
            "url": raw if "://" in raw else None,
            "final_url": final_url,
            "status_code": status,
            "headers": headers,
            "technologies": sorted(tech),
            "security_headers": {name: name in low for name in SECURITY_HEADERS},
        }

    @staticmethod
    def _display(result):
        if result.get("error"):
            return
        rows = [("Status", result.get("status_code", "")), ("Final URL", result.get("final_url", "")), ("Server", result.get("headers", {}).get("Server", "")), ("Technologies", ", ".join(result.get("technologies", [])) or "none")]
        print_table(["Field", "Value"], rows)
        print("  Security Headers")
        for name, present in result.get("security_headers", {}).items():
            print_status(f"{name}: {'PRESENT' if present else 'MISSING'}", "ok" if present else "warn")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
