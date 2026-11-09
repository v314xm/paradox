"""
Unit-тесты net_utils.

Проверяем классификацию direction для всех четырёх комбинаций
и единую классификацию internal/external.
"""
from paradox.config import Config
from paradox.net_utils import (
    classify_direction,
    ip_scope,
    is_internal_ip,
    is_public_ip,
)


def test_is_internal_private():
    c = Config()
    assert is_internal_ip("192.168.1.1", c)
    assert is_internal_ip("10.0.0.5", c)
    assert is_internal_ip("172.16.5.5", c)
    assert is_internal_ip("127.0.0.1", c)


def test_is_internal_external():
    c = Config()
    assert not is_internal_ip("8.8.8.8", c)
    assert not is_internal_ip("203.0.113.5", c)
    assert not is_internal_ip("80.64.102.71", c)


def test_cgnat_is_internal():
    c = Config()
    assert is_internal_ip("100.64.1.1", c)
    assert ip_scope("100.64.1.1", c) == "internal"


def test_ipv6_forms_are_internal():
    c = Config()
    # Регистр и длинная форма не должны ломать классификацию.
    assert is_internal_ip("FE80::1", c)
    assert is_internal_ip("fc00:0:0:0:0:0:0:1", c)
    assert is_internal_ip("::ffff:10.0.0.1", c)
    assert is_internal_ip("::1", c)


def test_broken_ip_is_special():
    assert ip_scope("not-an-ip") == "special"
    assert ip_scope("") == "special"
    assert is_public_ip("not-an-ip") is False


def test_documentation_ranges_stay_external():
    c = Config()
    assert is_public_ip("203.0.113.5", c)
    assert is_public_ip("192.0.2.10", c)


def test_custom_private_network_is_honoured():
    c = Config(private_networks=("10.", "203.0.113."))
    assert is_internal_ip("203.0.113.9", c)


def test_direction_outbound():
    c = Config()
    assert classify_direction("192.168.1.5", "8.8.8.8", c) == "outbound"


def test_direction_inbound():
    c = Config()
    assert classify_direction("8.8.8.8", "192.168.1.5", c) == "inbound"


def test_direction_internal():
    c = Config()
    assert classify_direction("192.168.1.5", "192.168.1.10", c) == "internal"


def test_direction_external():
    c = Config()
    assert classify_direction("8.8.8.8", "1.1.1.1", c) == "external"
