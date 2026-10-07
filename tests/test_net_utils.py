"""
Unit-тесты net_utils.

Проверяем классификацию direction для всех четырёх комбинаций.
"""
from pcap_triage.config import Config
from pcap_triage.net_utils import classify_direction, is_internal_ip


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