"""Тесты domain_utils: split_domain / base_domain / registered_label / matches_suffix."""
from paradox.domain_utils import (
    base_domain,
    matches_suffix,
    registered_label,
    split_domain,
)


# ---------- split_domain ----------

def test_split_simple():
    assert split_domain("example.com") == ("example.com", "")


def test_split_subdomain():
    assert split_domain("api.example.com") == ("example.com", "api")


def test_split_deep_subdomain():
    assert split_domain("a.b.c.example.com") == ("example.com", "a.b.c")


def test_split_two_level_uk():
    assert split_domain("foo.co.uk") == ("foo.co.uk", "")


def test_split_two_level_uk_with_sub():
    assert split_domain("api.foo.co.uk") == ("foo.co.uk", "api")


def test_split_two_level_au():
    assert split_domain("a.b.example.com.au") == ("example.com.au", "a.b")


def test_split_two_level_jp():
    assert split_domain("www.example.co.jp") == ("example.co.jp", "www")


def test_split_two_level_br():
    assert split_domain("x.y.z.com.br") == ("z.com.br", "x.y")


def test_split_single_label():
    assert split_domain("localhost") == ("localhost", "")


def test_split_empty():
    assert split_domain("") == ("", "")


def test_split_trailing_dot():
    assert split_domain("example.com.") == ("example.com", "")


def test_split_case_insensitive():
    assert split_domain("API.Example.COM") == ("example.com", "api")


# ---------- base_domain ----------

def test_base_simple():
    assert base_domain("api.example.com") == "example.com"


def test_base_uk():
    assert base_domain("a.b.foo.co.uk") == "foo.co.uk"


def test_base_no_sub():
    assert base_domain("attacker.com") == "attacker.com"


def test_base_uk_no_sub():
    assert base_domain("foo.co.uk") == "foo.co.uk"


def test_base_different_organisations_uk():
    """foo.co.uk и bar.co.uk — РАЗНЫЕ организации. Ключевой кейс."""
    assert base_domain("foo.co.uk") != base_domain("bar.co.uk")


# ---------- registered_label ----------

def test_label_simple():
    assert registered_label("api.example.com") == "example"


def test_label_uk():
    assert registered_label("a.b.foo.co.uk") == "foo"


def test_label_doubleclick():
    assert (
        registered_label("googleads.g.doubleclick.net") == "doubleclick"
    )


def test_label_no_dot():
    assert registered_label("localhost") == "localhost"


# ---------- matches_suffix ----------

def test_suffix_exact():
    assert matches_suffix("example.com", {"example.com"})


def test_suffix_subdomain():
    assert matches_suffix("api.example.com", {"example.com"})


def test_suffix_no_partial_label():
    """notexample.com НЕ должно матчиться по example.com."""
    assert not matches_suffix("notexample.com", {"example.com"})


def test_suffix_empty_host():
    assert not matches_suffix("", {"example.com"})


def test_suffix_two_level():
    assert matches_suffix("api.foo.co.uk", {"foo.co.uk"})


def test_suffix_two_level_not_sibling():
    assert not matches_suffix("bar.co.uk", {"foo.co.uk"})


def test_suffix_multiple():
    assert matches_suffix("x.google-analytics.com",
                          {"cloudfront.net", "google-analytics.com"})
