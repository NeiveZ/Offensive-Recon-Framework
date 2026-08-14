from modules.http_probe import HTTPProbe


def test_http_candidates():
    probe = HTTPProbe()
    assert probe._candidates("example.com")[0].startswith("https://")
