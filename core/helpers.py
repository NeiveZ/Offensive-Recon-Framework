#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Any


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        return max(minimum, min(maximum, float(value)))
    except (TypeError, ValueError):
        return default


def normalize_domain(value: str) -> str:
    raw = (value or "").strip().lower()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        raw = parsed.hostname or parsed.path
    return (raw or "").split("/")[0].strip(".")


def valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.rstrip(".").split(".")
    return all(
        label and len(label) <= 63 and label[0].isalnum() and label[-1].isalnum()
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    )


def resolve_addresses(target: str) -> dict[str, list[str]]:
    """Resolve hostname into deduplicated IPv4/IPv6 addresses."""
    v4, v6 = set(), set()
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return {"ipv4": [], "ipv6": []}
    for family, _type, _proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if family == socket.AF_INET and ip.version == 4:
            v4.add(str(ip))
        elif family == socket.AF_INET6 and ip.version == 6:
            v6.add(str(ip))
    return {"ipv4": sorted(v4), "ipv6": sorted(v6)}


def flatten_hosts(value: Any) -> list[str]:
    """Extract host/URL-like strings from common ORFX result shapes."""
    hosts: list[str] = []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        for key in ("subdomain", "host", "url", "target", "final_url"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                hosts.append(item.strip())
        for key in ("subdomains", "hosts", "http", "results"):
            hosts.extend(flatten_hosts(value.get(key)))
    elif isinstance(value, list):
        for item in value:
            hosts.extend(flatten_hosts(item))
    seen = set()
    return [h for h in hosts if not (h.lower() in seen or seen.add(h.lower()))]
