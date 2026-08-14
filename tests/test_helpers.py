import socket

from core.helpers import normalize_domain, valid_domain, resolve_addresses


def test_normalize_domain():
    assert normalize_domain("https://Example.COM/path") == "example.com"


def test_valid_domain():
    assert valid_domain("example.com")
    assert not valid_domain("example")


def test_resolve_localhost():
    result = resolve_addresses("localhost")
    assert result["ipv4"] or result["ipv6"]
