from modules.tls_probe import TLSProbe


def test_tls_options():
    probe = TLSProbe()
    assert probe.get_option("VERIFY") == "true"
