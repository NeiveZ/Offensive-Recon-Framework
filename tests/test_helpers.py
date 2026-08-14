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


def test_user_agent_modes(tmp_path):
    from core.helpers import choose_user_agent, load_user_agents
    assert choose_user_agent("UA-EXACT") == "UA-EXACT"
    assert choose_user_agent("random") in load_user_agents()
    custom = tmp_path / "ua.txt"
    custom.write_text("UA-A\nUA-B\n", encoding="utf-8")
    pool = load_user_agents(str(custom))
    assert pool == ["UA-A", "UA-B"]
    assert choose_user_agent("@" + str(custom), pool) in pool
