#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from typing import Any


class Correlator:
    """Normalize module output into one simple reconnaissance model."""

    def __init__(self, target: str):
        self.target = target
        self.model: dict[str, Any] = {
            "target": target,
            "assets": [],
            "dns": {},
            "subdomains": [],
            "http": [],
            "ports": [],
            "tls": [],
            "whois": {},
            "findings": [],
            "errors": [],
        }

    def add(self, module: str, result: Any) -> None:
        if not isinstance(result, dict):
            return
        if result.get("error"):
            self.model["errors"].append({"module": module, "error": result["error"]})

        if module == "dns":
            self.model["dns"] = result.get("records", result)
        elif module == "subdomains":
            self.model["subdomains"] = result.get("subdomains", [])
            passive = result.get("passive_subdomains", [])
            resolved = result.get("subdomains", [])
            for item in resolved:
                self._asset(item.get("subdomain"), ips=item.get("ips", []))
            for host in passive:
                self._asset(host)
        elif module == "http":
            self.model["http"].append(result)
            self._asset(result.get("host") or result.get("target"), urls=[result.get("final_url") or result.get("url")])
        elif module == "ports":
            self.model["ports"].append(result)
            self._asset(result.get("target"), ports=result.get("open_ports", []), ips=result.get("addresses", []))
        elif module == "tls":
            self.model["tls"].append(result)
            self._asset(result.get("target"), tls=[result])
        elif module == "whois":
            self.model["whois"] = result
        else:
            self.model.setdefault(module, []).append(result)

    def _asset(self, host: str | None, ips=None, urls=None, ports=None, tls=None) -> None:
        if not host:
            return
        host = str(host)
        found = next((a for a in self.model["assets"] if a["host"].lower() == host.lower()), None)
        if not found:
            found = {"host": host, "ips": [], "urls": [], "ports": [], "tls": []}
            self.model["assets"].append(found)
        for key, values in (("ips", ips), ("urls", urls), ("ports", ports), ("tls", tls)):
            if values:
                if not isinstance(values, list):
                    values = [values]
                for value in values:
                    if value not in found[key]:
                        found[key].append(value)

    def finalize(self) -> dict[str, Any]:
        tech = []
        for result in self.model["http"]:
            tech.extend(result.get("technologies", []))
        self.model["summary"] = {
            "assets": len(self.model["assets"]),
            "subdomains": len(self.model["subdomains"]),
            "http_services": len(self.model["http"]),
            "open_ports": sum(len(x.get("open_ports", [])) for x in self.model["ports"]),
            "tls_services": len(self.model["tls"]),
            "technologies": sorted(Counter(tech).keys()),
            "errors": len(self.model["errors"]),
        }
        return self.model
