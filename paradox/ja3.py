"""
JA3 / JA3S fingerprinting (Salesforce).

JA3 = MD5 от строки:
    SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
Пример:
    771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13,29-23-24,0
    → cd08e31494f9531f560d64c695473da9

JA3S (для ServerHello) = MD5 от:
    SSLVersion,Cipher,Extensions

Что даёт:
- Client fingerprint. Tor, Cobalt Strike, Metasploit, python-requests
  дают характерные JA3.
- Server fingerprint (JA3S). Некоторые C2-фреймворки известны по серверу.
- Расхождение между UA и JA3 — сильный признак подмены.

Ограничение: ClientHello/ServerHello должны уместиться в один
TCP-сегмент. Полная сборка требует StreamReassembler — TODO.

Источники: https://github.com/salesforce/ja3
"""
import hashlib
import struct


_TLS_CONTENT_HANDSHAKE = 0x16
_TLS_HANDSHAKE_CLIENT_HELLO = 0x01
_TLS_HANDSHAKE_SERVER_HELLO = 0x02

_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_GROUPS = 10
_EXT_EC_POINT_FORMATS = 11


def parse_client_hello(payload: bytes) -> dict | None:
    """
    Разобрать TLS ClientHello.

    Возвращает dict:
      {
        "sni": str | None,
        "ja3_raw": str,
        "ja3": str,        # md5 hex
      }
    или None, если payload не ClientHello.
    """
    try:
        return _parse_client_hello(payload)
    except (IndexError, struct.error, ValueError):
        return None


def parse_server_hello(payload: bytes) -> dict | None:
    """
    Разобрать TLS ServerHello.

    Возвращает dict:
      {
        "ja3s_raw": str,
        "ja3s": str,       # md5 hex
      }
    или None.
    """
    try:
        return _parse_server_hello(payload)
    except (IndexError, struct.error, ValueError):
        return None


def _parse_client_hello(payload: bytes) -> dict | None:
    # Мин: 5 (record) + 4 (hs) + 2 + 32 + 1 + 2 + 0 + 1 + 0 = 47
    if len(payload) < 43:
        return None
    if payload[0] != _TLS_CONTENT_HANDSHAKE:
        return None
    if payload[5] != _TLS_HANDSHAKE_CLIENT_HELLO:
        return None

    pos = 5 + 4

    # client_version
    if pos + 2 > len(payload):
        return None
    client_version = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2

    # random
    pos += 32
    if pos > len(payload):
        return None

    # session_id
    sid_len = payload[pos]
    pos += 1 + sid_len

    # cipher suites
    if pos + 2 > len(payload):
        return None
    cs_len = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2
    cs_end = pos + cs_len
    if cs_end > len(payload):
        return None

    ciphers: list[int] = []
    while pos + 2 <= cs_end:
        ciphers.append(struct.unpack(">H", payload[pos:pos + 2])[0])
        pos += 2
    pos = cs_end

    # compression methods
    if pos >= len(payload):
        return None
    cm_len = payload[pos]
    pos += 1 + cm_len

    # extensions (могут отсутствовать в старых hello)
    extensions: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    sni: str | None = None

    if pos + 2 <= len(payload):
        ext_total_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total_len
        if ext_end > len(payload):
            ext_end = len(payload)

        while pos + 4 <= ext_end:
            ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
            pos += 4
            ext_data = payload[pos:pos + ext_len]
            pos += ext_len
            extensions.append(ext_type)

            if ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                n = struct.unpack(">H", ext_data[0:2])[0]
                for i in range(0, n - 1, 2):
                    if 2 + i + 2 <= len(ext_data):
                        curves.append(struct.unpack(
                            ">H", ext_data[2 + i:2 + i + 2]
                        )[0])

            elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                n = ext_data[0]
                for i in range(n):
                    if 1 + i < len(ext_data):
                        point_formats.append(ext_data[1 + i])

            elif ext_type == _EXT_SERVER_NAME and len(ext_data) >= 5:
                # SNI list: 2 байта len + entry(1 тип + 2 len + name)
                if ext_data[2] == 0:
                    name_len = struct.unpack(">H", ext_data[3:5])[0]
                    name_bytes = ext_data[5:5 + name_len]
                    try:
                        sni = name_bytes.decode("ascii")
                    except UnicodeDecodeError:
                        sni = None

    ja3_raw = "{},{},{},{},{}".format(
        client_version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    )
    ja3 = hashlib.md5(ja3_raw.encode("ascii")).hexdigest()

    return {"sni": sni, "ja3_raw": ja3_raw, "ja3": ja3}


def _parse_server_hello(payload: bytes) -> dict | None:
    if len(payload) < 5 + 4 + 2 + 32 + 1 + 2 + 1:
        return None
    if payload[0] != _TLS_CONTENT_HANDSHAKE:
        return None
    if payload[5] != _TLS_HANDSHAKE_SERVER_HELLO:
        return None

    pos = 5 + 4
    server_version = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2 + 32

    if pos >= len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len

    if pos + 2 > len(payload):
        return None
    cipher = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2

    # compression method
    pos += 1

    extensions: list[int] = []
    if pos + 2 <= len(payload):
        ext_total_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total_len
        if ext_end > len(payload):
            ext_end = len(payload)
        while pos + 4 <= ext_end:
            ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
            extensions.append(ext_type)
            pos += 4 + ext_len

    ja3s_raw = "{},{},{}".format(
        server_version,
        cipher,
        "-".join(str(e) for e in extensions),
    )
    ja3s = hashlib.md5(ja3s_raw.encode("ascii")).hexdigest()

    return {"ja3s_raw": ja3s_raw, "ja3s": ja3s}