from core.correlator import Correlator


def test_correlator_summary():
    c = Correlator("example.com")
    c.add("subdomains", {"target":"example.com", "subdomains":[{"subdomain":"www.example.com","ipv4":["127.0.0.1"],"ipv6":[]}]})
    c.add("http", {"target":"www.example.com", "final_url":"https://www.example.com", "technologies":["nginx"]})
    model = c.finalize()
    assert model["summary"]["subdomains"] == 1
    assert model["summary"]["http_services"] == 1
    assert "nginx" in model["summary"]["technologies"]
