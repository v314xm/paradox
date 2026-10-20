"""
Минимальный парсер NBNS (NetBIOS Name Service).

Извлекает имена хостов из NBNS-пакетов на UDP/137.

Формат (RFC 1002):
  Header (12 байт): transaction_id, flags, qdcount, ancount, nscount, arcount
  Question: encoded_name (34 байта) + qtype(2) + qclass(2)
  Answer: encoded_name + type + class + ttl(4) + rdlength(2) + rdata

NetBIOS-имя (34 байта):
  1 байт длины (0x20)
  32 байта — имя, закодированное попарно: каждая пара байт
    (b1, b2) → (b1 - 0x41) << 4 | (b2 - 0x41).
    Последний символ — суффикс типа ресурса (0x00 workstation, 0x20 server,
    0x1C domain controller и т.п.)
  1 байт — 0x00 (terminator)

Возвращает первую найденную пару (name, suffix). Если имя пустое — None.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NBNSName:
    """Имя хоста из NBNS."""
    name: str               # без суффикса
    suffix: int             # байт типа ресурса (0x00, 0x20, 0x1C, ...)
    name_type: int | None = None   # qtype/type из пакета (0x0020 = NB, 0x0021 = NBSTAT)


def decode_nbns_name(encoded: bytes) -> tuple[str, int] | None:
    """
    Декодировать 32-байтовое NetBIOS-имя в (name, suffix).

    encoded — ровно 32 байта (без length-байта и terminator).
    Возвращает (name, suffix) или None, если данные битые.
    """
    if len(encoded) != 32:
        return None

    decoded = bytearray()
    for i in range(0, 32, 2):
        hi = encoded[i] - 0x41
        lo = encoded[i + 1] - 0x41
        if hi < 0 or hi > 15 or lo < 0 or lo > 15:
            return None
        decoded.append((hi << 4) | lo)

    if not decoded:
        return None

    # Последний символ — суффикс типа ресурса
    suffix = decoded[-1]
    name_bytes = bytes(decoded[:-1]).rstrip(b" ")

    try:
        name = name_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None

    return name, suffix


def parse_nbns(payload: bytes) -> NBNSName | None:
    """
    Разобрать NBNS-пакет.

    Ищет имя в Question section (qdcount) или, если qdcount == 0,
    пробует Answer section.
    """
    if not payload or len(payload) < 12:
        return None

    # Header
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")

    pos = 12
    first: NBNSName | None = None

    # Question section
    for _ in range(qdcount):
        result = _read_question(payload, pos)
        if result is None:
            break
        name, suffix, name_type, pos = result
        if first is None and name:
            first = NBNSName(name=name, suffix=suffix, name_type=name_type)

    # Если в Question не нашли — пробуем Answer
    if first is None:
        for _ in range(ancount):
            result = _read_answer(payload, pos)
            if result is None:
                break
            name, suffix, name_type, pos = result
            if name:
                first = NBNSName(name=name, suffix=suffix, name_type=name_type)
                break

    return first


def _read_name(payload: bytes, pos: int) -> tuple[str, int, int] | None:
    """
    Прочитать NetBIOS-имя из NBNS. Поддерживает только несжатые имена
    (без pointer 0xC0). Для compressed names возвращаем None.

    Возвращает (name, suffix, new_pos) или None.
    """
    if pos >= len(payload):
        return None

    length = payload[pos]
    if length != 0x20:
        # либо compressed pointer (0xC0), либо нестандартная длина
        return None

    if pos + 1 + 32 + 1 > len(payload):
        return None

    encoded = payload[pos + 1:pos + 33]
    terminator = payload[pos + 33]
    if terminator != 0x00:
        return None

    decoded = decode_nbns_name(encoded)
    if decoded is None:
        return None

    name, suffix = decoded
    return name, suffix, pos + 34


def _read_question(
    payload: bytes, pos: int,
) -> tuple[str, int, int, int] | None:
    """Прочитать Question: name + qtype(2) + qclass(2)."""
    result = _read_name(payload, pos)
    if result is None:
        return None
    name, suffix, pos = result

    if pos + 4 > len(payload):
        return None

    name_type = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 4  # type + class

    return name, suffix, name_type, pos


def _read_answer(
    payload: bytes, pos: int,
) -> tuple[str, int, int, int] | None:
    """Прочитать Answer: name + type + class + ttl + rdlength + rdata."""
    result = _read_name(payload, pos)
    if result is None:
        return None
    name, suffix, pos = result

    if pos + 10 > len(payload):
        return None

    name_type = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2  # type
    pos += 2  # class
    pos += 4  # ttl
    rdlength = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2

    if pos + rdlength > len(payload):
        return None
    pos += rdlength

    return name, suffix, name_type, pos