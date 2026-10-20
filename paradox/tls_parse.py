"""
Парсер TLS ClientHello.

Извлекает SNI (Server Name Indication) — домен, к которому клиент
устанавливает TLS-соединение. Работает на сырых байтах TLS-записи.

Формат (RFC 8446, раздел 4):

  TLS record:
    content_type    1 байт   (0x16 = handshake)
    version         2 байта  (0x0301, 0x0303, ...)
    length          2 байта

  Handshake:
    msg_type        1 байт   (0x01 = ClientHello)
    length          3 байта
    body            ...

  ClientHello body:
    client_version  2 байта
    random          32 байта
    session_id_len  1 байт
    session_id      N байт
    cipher_suites_len 2 байта
    cipher_suites   N байт
    compression_len 1 байт
    compression     N байт
    extensions_len  2 байта
    extensions      N байт

  server_name extension (type 0x0000):
    server_name_list_len  2 байта
    name_type             1 байт   (0x00 = host_name)
    name_len              2 байта
    name                  N байт   ← это SNI

Ограничения:
- Не собирает фрагментированные TLS-записи (следующий шаг —
  StreamReassembler).
- Не поддерживает TLS 1.3 ECH (Encrypted Client Hello).
- Работает только с первой TLS-записью в payload.
"""
from __future__ import annotations

# content types
TLS_CONTENT_HANDSHAKE = 0x16

# handshake types
TLS_HANDSHAKE_CLIENT_HELLO = 0x01

# extension types
TLS_EXTENSION_SERVER_NAME = 0x0000

# server name types
TLS_SERVER_NAME_HOST = 0x00


def extract_sni(payload: bytes) -> str | None:
    """Извлечь SNI из payload TCP-пакета.

    Возвращает домен в lower case или None, если payload не содержит
    ClientHello с валидной server_name extension.
    """
    if not payload or len(payload) < 5:
        return None

    # --- TLS record ---
    if payload[0] != TLS_CONTENT_HANDSHAKE:
        return None
    # payload[1:3] — версия записи, не проверяем строго (может быть 0x0301)
    record_len = int.from_bytes(payload[3:5], "big")
    record_end = 5 + record_len
    if record_end > len(payload):
        # Запись обрезана — не наш случай (нужен reassembly)
        return None

    # --- handshake ---
    if len(payload) < 9:
        return None
    if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
        return None
    handshake_len = int.from_bytes(payload[6:9], "big")
    body_start = 9
    body_end = body_start + handshake_len
    if body_end > len(payload):
        return None

    # --- ClientHello body ---
    pos = body_start
    if pos + 2 + 32 > body_end:
        return None
    pos += 2          # client_version
    pos += 32         # random

    # session_id
    if pos >= body_end:
        return None
    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos > body_end:
        return None

    # cipher_suites
    if pos + 2 > body_end:
        return None
    cipher_suites_len = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos > body_end:
        return None

    # compression_methods
    if pos >= body_end:
        return None
    compression_len = payload[pos]
    pos += 1 + compression_len
    if pos > body_end:
        return None

    # extensions
    if pos + 2 > body_end:
        return None
    extensions_len = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    extensions_end = pos + extensions_len
    if extensions_end > body_end:
        return None

    return _find_sni_extension(payload, pos, extensions_end)


def _find_sni_extension(
    data: bytes, start: int, end: int,
) -> str | None:
    """Пройти по extensions, найти server_name (0x0000)."""
    pos = start
    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        ext_data_start = pos + 4
        ext_data_end = ext_data_start + ext_len
        if ext_data_end > end:
            return None

        if ext_type == TLS_EXTENSION_SERVER_NAME:
            return _parse_server_name(data, ext_data_start, ext_data_end)

        pos = ext_data_end

    return None


def _parse_server_name(
    data: bytes, start: int, end: int,
) -> str | None:
    """Разобрать server_name extension."""
    if start + 2 > end:
        return None
    list_len = int.from_bytes(data[start:start + 2], "big")
    pos = start + 2
    list_end = pos + list_len
    if list_end > end:
        return None

    while pos + 3 <= list_end:
        name_type = data[pos]
        name_len = int.from_bytes(data[pos + 1:pos + 3], "big")
        name_start = pos + 3
        name_end = name_start + name_len
        if name_end > list_end:
            return None

        if name_type == TLS_SERVER_NAME_HOST:
            try:
                name = data[name_start:name_end].decode("ascii")
            except UnicodeDecodeError:
                return None
            return name.lower()

        pos = name_end

    return None