#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from pathlib import Path
from typing import Any

try:
    import dns.resolver as dns_resolver
except Exception:  # optional dependency; socket fallback remains available
    dns_resolver = None


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


def resolve_addresses(target: str, timeout: float = 5.0, server: str | None = None) -> dict[str, list[str]]:
    """Resolve hostname into deduplicated IPv4/IPv6 addresses with a bounded timeout.

    dnspython is preferred when installed because it exposes an actual DNS query
    lifetime. The standard-library resolver remains the fallback for minimal
    environments.
    """
    v4, v6 = set(), set()
    if dns_resolver is not None:
        try:
            resolver = dns_resolver.Resolver()
            resolver.lifetime = max(0.5, float(timeout))
            resolver.timeout = max(0.5, min(float(timeout), 5.0))
            if server:
                resolver.nameservers = [server]
            for rtype, bucket in (("A", v4), ("AAAA", v6)):
                try:
                    answers = resolver.resolve(target, rtype, raise_on_no_answer=False)
                    for answer in answers:
                        try:
                            bucket.add(str(answer))
                        except Exception:
                            continue
                except Exception:
                    continue
            if v4 or v6:
                return {"ipv4": sorted(v4), "ipv6": sorted(v6)}
        except Exception:
            pass

    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
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




# Conservative browser-style User-Agent pool for authorized HTTP reconnaissance.
# The pool changes only the User-Agent header; it does not attempt to spoof
# unrelated browser headers, cookies, fingerprints, or client IP information.
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
]

def load_user_agents(path: str | None = None) -> list[str]:
    """Load non-empty User-Agent lines from a custom file, with a safe default pool."""
    if path:
        try:
            values = []
            for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
            if values:
                return list(dict.fromkeys(values))
        except OSError:
            pass
    return list(DEFAULT_USER_AGENTS)

def choose_user_agent(value: str | None, pool: list[str] | None = None) -> str:
    """Resolve an explicit UA, random rotation, or custom @file source."""
    import random
    raw = str(value or "").strip()
    if raw.startswith("@"):
        agents = load_user_agents(raw[1:])
        return random.choice(agents)
    if raw.lower() in {"random", "rotate", "rotating"}:
        agents = pool or DEFAULT_USER_AGENTS
        return random.choice(agents)
    if raw:
        return raw
    return DEFAULT_USER_AGENTS[0]


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
