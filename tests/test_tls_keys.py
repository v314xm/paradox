"""SSLKEYLOGFILE и расшифровка TLS 1.2/1.3 на реальной сессии OpenSSL."""
from pathlib import Path

import pytest

from paradox.tls_decrypt import (
    decrypt_tls_pair,
    is_tls_client_hello,
    is_tls_server_hello,
    looks_like_tls,
)
from paradox.tls_keys import load_keylog, parse_keylog
from tests._tls_session import make_tls_session


def test_parse_keylog_labels():
    client_random = "aa" * 32
    text = (
        "# TLS secrets log\n"
        f"CLIENT_RANDOM {client_random} {'bb' * 48}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random} {'cc' * 32}\n"
        "broken line\n"
        "CLIENT_RANDOM not-hex zz\n"
    )

    log = parse_keylog(text)

    assert log.master_secret(bytes.fromhex(client_random)) == bytes.fromhex("bb" * 48)
    assert log.traffic_secret(
        "CLIENT_TRAFFIC_SECRET_0", bytes.fromhex(client_random),
    ) == bytes.fromhex("cc" * 32)


def test_load_keylog(tmp_path: Path):
    path = tmp_path / "keys.log"
    path.write_text(
        f"CLIENT_RANDOM {'11' * 32} {'22' * 48}\n", encoding="utf-8",
    )

    assert load_keylog(path).master_secret(bytes.fromhex("11" * 32))


def test_keylog_empty_is_falsy():
    log = parse_keylog("")

    assert not log
    assert log.master_secret(b"\x00" * 32) is None


@pytest.mark.parametrize(
    ("tls13", "cipher"),
    [
        (True, None),
        (False, "ECDHE-ECDSA-AES128-GCM-SHA256"),
        (False, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    ],
)
def test_decrypt_real_tls_session(tmp_path: Path, tls13, cipher):
    session = make_tls_session(
        tmp_path,
        tls13=tls13,
        cipher=cipher,
        client_payload=b"GET /secret HTTP/1.1\r\nHost: h\r\n\r\n",
        server_payload=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    )

    assert looks_like_tls(session.client_raw)
    assert is_tls_client_hello(session.client_raw)
    assert is_tls_server_hello(session.server_raw)

    result = decrypt_tls_pair(
        session.client_raw,
        session.server_raw,
        parse_keylog(session.keylog_text),
    )

    assert result.error is None, result.error
    assert result.tls13 is tls13
    assert result.decrypted_records > 0
    assert b"GET /secret HTTP/1.1" in result.client_plaintext
    assert b"HTTP/1.1 200 OK" in result.server_plaintext


def test_decrypt_without_keylog_entry(tmp_path: Path):
    session = make_tls_session(tmp_path, tls13=False)

    result = decrypt_tls_pair(
        session.client_raw, session.server_raw, parse_keylog(""),
    )

    assert result.error == "no_keylog_entry"
    assert result.decrypted_records == 0


def test_decrypt_garbage_is_not_tls():
    assert not looks_like_tls(b"GET / HTTP/1.1\r\n")
    assert not is_tls_client_hello(b"")
