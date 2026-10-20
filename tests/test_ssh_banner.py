"""Тесты SSH banner экстрактора."""
from paradox.extractors.ssh_banner import (
    SSHBannerExtractor,
    parse_ssh_banner,
)
from paradox.models import CaptureState


class _Rec:
    """Заглушка PacketRecord."""
    def __init__(self, payload: bytes, src_port: int, dst_port: int,
                 src_ip: str = "192.168.1.1",
                 dst_ip: str = "10.0.0.5"):
        self.payload = payload
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip


# ---------- parse_ssh_banner ----------

def test_parse_simple_banner():
    payload = b"SSH-2.0-OpenSSH_8.2p1\r\n"
    assert parse_ssh_banner(payload) == "OpenSSH_8.2p1"


def test_parse_banner_with_comments():
    payload = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    assert parse_ssh_banner(payload) == "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"


def test_parse_banner_lf_only():
    payload = b"SSH-2.0-OpenSSH_9.0\n"
    assert parse_ssh_banner(payload) == "OpenSSH_9.0"


def test_parse_banner_199():
    """Сервер может объявить 1.99 для совместимости с обеими версиями."""
    payload = b"SSH-1.99-Cisco-1.25\r\n"
    assert parse_ssh_banner(payload) == "Cisco-1.25"


def test_parse_not_ssh():
    payload = b"GET / HTTP/1.1\r\n"
    assert parse_ssh_banner(payload) is None


def test_parse_empty():
    assert parse_ssh_banner(b"") is None


def test_parse_short():
    assert parse_ssh_banner(b"SSH-") is None


def test_parse_malformed():
    assert parse_ssh_banner(b"SSH-noprefix\r\n") is None


def test_parse_banner_with_extra_data_after_newline():
    """SSH баннер часто приходит вместе с началом KEXINIT."""
    payload = b"SSH-2.0-OpenSSH_8.2p1\r\n\x00\x00\x01\x00binary kex"
    assert parse_ssh_banner(payload) == "OpenSSH_8.2p1"


# ---------- SSHBannerExtractor ----------

def test_extractor_server_banner():
    """Баннер от сервера (src_port=22)."""
    rec = _Rec(
        b"SSH-2.0-OpenSSH_8.2p1\r\n",
        src_port=22, dst_port=54321,
        src_ip="10.0.0.5", dst_ip="192.168.1.1",
    )
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert state.ssh_server_versions[("10.0.0.5", 22)] == "OpenSSH_8.2p1"
    assert not state.ssh_client_versions


def test_extractor_client_banner():
    """Баннер от клиента (dst_port=22)."""
    rec = _Rec(
        b"SSH-2.0-OpenSSH_9.0p1\r\n",
        src_port=54321, dst_port=22,
        src_ip="192.168.1.1", dst_ip="10.0.0.5",
    )
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert "OpenSSH_9.0p1" in state.ssh_client_versions["192.168.1.1"]
    assert not state.ssh_server_versions


def test_extractor_alt_port():
    """Нестандартный порт 2222 в списке серверных."""
    rec = _Rec(
        b"SSH-2.0-OpenSSH_7.4\r\n",
        src_port=2222, dst_port=54321,
        src_ip="10.0.0.5", dst_ip="192.168.1.1",
    )
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert state.ssh_server_versions[("10.0.0.5", 2222)] == "OpenSSH_7.4"


def test_extractor_ignores_non_ssh_port():
    """Payload SSH-, но порт не SSH-серверный."""
    rec = _Rec(
        b"SSH-2.0-OpenSSH_8.2\r\n",
        src_port=8080, dst_port=9090,
    )
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert not state.ssh_server_versions
    assert not state.ssh_client_versions


def test_extractor_ignores_http():
    rec = _Rec(b"GET / HTTP/1.1\r\n", src_port=80, dst_port=54321)
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert not state.ssh_server_versions


def test_extractor_empty_payload():
    rec = _Rec(b"", src_port=22, dst_port=54321)
    state = CaptureState()
    SSHBannerExtractor().process(rec, state)
    assert not state.ssh_server_versions


def test_extractor_client_multiple_versions():
    """С одного IP с разными клиентами — набор версий."""
    state = CaptureState()
    SSHBannerExtractor().process(
        _Rec(b"SSH-2.0-OpenSSH_8.9p1\r\n", 54321, 22), state,
    )
    SSHBannerExtractor().process(
        _Rec(b"SSH-2.0-libssh-0.10.4\r\n", 54322, 22), state,
    )
    assert state.ssh_client_versions["192.168.1.1"] == {
        "OpenSSH_8.9p1", "libssh-0.10.4",
    }


def test_extractor_server_multiple_ports():
    """Один сервер на двух портах — две записи."""
    state = CaptureState()
    SSHBannerExtractor().process(
        _Rec(b"SSH-2.0-OpenSSH_8.2p1\r\n", 22, 54321,
             src_ip="10.0.0.5"), state,
    )
    SSHBannerExtractor().process(
        _Rec(b"SSH-2.0-OpenSSH_8.2p1\r\n", 2222, 54322,
             src_ip="10.0.0.5"), state,
    )
    assert state.ssh_server_versions[("10.0.0.5", 22)] == "OpenSSH_8.2p1"
    assert state.ssh_server_versions[("10.0.0.5", 2222)] == "OpenSSH_8.2p1"
