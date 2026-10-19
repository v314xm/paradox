"""Тесты определения типа IOC и ссылок."""
from pcap_triage_gui.ioc_utils import detect_ioc_type, provider_link


def test_detect_ipv4():
    assert detect_ioc_type("8.8.8.8") == "ip"


def test_detect_ipv6():
    assert detect_ioc_type("::1") == "ip"


def test_detect_domain():
    assert detect_ioc_type("evil.com") == "domain"


def test_detect_url():
    assert detect_ioc_type("https://evil.com/x") == "url"
    assert detect_ioc_type("http://evil.com") == "url"


def test_detect_hash_sha256():
    assert detect_ioc_type("a" * 64) == "hash"


def test_detect_hash_md5():
    assert detect_ioc_type("a" * 32) == "hash"


def test_detect_empty():
    assert detect_ioc_type("") is None
    assert detect_ioc_type("   ") is None


def test_detect_garbage():
    assert detect_ioc_type("not an ioc !!!") is None


def test_provider_link_ip():
    assert "8.8.8.8" in provider_link("shodan_internetdb", "8.8.8.8", "ip")


def test_provider_link_returns_none_for_unsupported():
    assert provider_link("shodan_internetdb", "evil.com", "domain") is None


def test_provider_link_unknown_provider():
    assert provider_link("nonexistent", "x", "ip") is None


def test_provider_link_virustotal_domain():
    url = provider_link("virustotal", "evil.com", "domain")
    assert url is not None
    assert "evil.com" in url
