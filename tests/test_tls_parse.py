"""
Unit-тесты парсера TLS ClientHello.

Эталонные ClientHello собраны вручную из реальных hex-дампов.
Проверяем извлечение SNI и edge cases.
"""
from pcap_triage.tls_parse import extract_sni


def _build_client_hello(sni: str | None) -> bytes:
    """Собрать минимальный валидный ClientHello с заданным SNI."""
    # --- extensions ---
    if sni is not None:
        sni_bytes = sni.encode("ascii")
        server_name_data = (
            len(sni_bytes + b"").to_bytes(2, "big")  # placeholder, ниже поправим
        )
        # server_name list: name_type(1) + name_len(2) + name
        name_entry = (
            b"\x00"                                   # name_type = host_name
            + len(sni_bytes).to_bytes(2, "big")
            + sni_bytes
        )
        server_name_list = len(name_entry).to_bytes(2, "big") + name_entry
        server_name_ext = (
            b"\x00\x00"                               # ext type = server_name
            + len(server_name_list).to_bytes(2, "big")
            + server_name_list
        )
    else:
        server_name_ext = b""

    extensions = server_name_ext
    extensions_block = len(extensions).to_bytes(2, "big") + extensions

    # --- ClientHello body ---
    body = (
        b"\x03\x03"                 # client_version = TLS 1.2
        + b"\x00" * 32              # random
        + b"\x00"                   # session_id_len = 0
        + b"\x00\x02\x13\x01"       # cipher_suites: len=2, TLS_AES_128_GCM_SHA256
        + b"\x01\x00"               # compression: len=1, null
        + extensions_block
    )

    # --- handshake ---
    handshake = (
        b"\x01"                                   # msg_type = ClientHello
        + len(body).to_bytes(3, "big")
        + body
    )

    # --- TLS record ---
    record = (
        b"\x16"                                   # content_type = handshake
        + b"\x03\x01"                             # record version
        + len(handshake).to_bytes(2, "big")
        + handshake
    )

    return record


# ---------- основной сценарий ----------

def test_extract_simple_sni():
    payload = _build_client_hello("example.com")
    assert extract_sni(payload) == "example.com"


def test_extract_sni_lowercases():
    payload = _build_client_hello("EXAMPLE.COM")
    assert extract_sni(payload) == "example.com"


def test_extract_long_sni():
    sni = "very-long-subdomain.example-cdn-provider.com"
    payload = _build_client_hello(sni)
    assert extract_sni(payload) == sni


# ---------- edge cases ----------

def test_empty_payload():
    assert extract_sni(b"") is None


def test_too_short():
    assert extract_sni(b"\x16") is None


def test_not_handshake():
    """Не handshake-запись (например, application data 0x17)."""
    payload = b"\x17\x03\x03\x00\x05" + b"\x00" * 5
    assert extract_sni(payload) is None


def test_not_client_hello():
    """Handshake, но не ClientHello (например, ServerHello 0x02)."""
    body = b"\x00" * 10
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    assert extract_sni(record) is None


def test_client_hello_without_sni():
    """Валидный ClientHello, но без server_name extension."""
    payload = _build_client_hello(None)
    assert extract_sni(payload) is None


def test_truncated_record():
    """Запись заявляет длину больше, чем есть в payload."""
    payload = b"\x16\x03\x03\xff\xff" + b"\x00" * 10
    assert extract_sni(payload) is None


def test_truncated_handshake():
    """Handshake заявляет длину больше, чем есть."""
    payload = b"\x16\x03\x03\x00\x0a" + b"\x01\xff\xff\xff" + b"\x00" * 2
    assert extract_sni(payload) is None