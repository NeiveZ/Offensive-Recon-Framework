from modules.subdomain_enum import SubdomainEnumerator


def test_wordlist_preserves_nested_labels():
    mod = SubdomainEnumerator()
    values = mod._clean(["www", "dev.api", "dev.api", "api.example.com"])
    assert "dev.api" in values
    assert "api.example.com" in values
    assert len(values) == 3


def test_profile_defaults_are_reliability_oriented():
    mod = SubdomainEnumerator()
    mod.set_option("PROFILE", "accurate")
    assert mod.get_option("PROFILE") == "accurate"
    assert mod.get_option("THREADS") == "auto"
