"""
Работа с телом HTTP-объекта: распаковка и критерий текстовости.

Три потребителя:
  - command_injection  — распаковать тело и искать shell-паттерны
                         только в тексте (в бинаре они случайны);
  - php_payload        — распаковать и искать маркер `<?php`;
  - http_binary_upload — наоборот, важно, что тело БИНАРНОЕ на
                         проводе; распаковка здесь не применяется.

Поддерживается gzip/x-gzip и deflate (zlib-wrapped и raw).
brotli/zstd не поддерживаются — для них нужны внешние зависимости,
такие тела считаются нераспаковываемыми.

Защита:
  - лимит распакованного размера (zip-бомба) —
    config.http_body_max_decoded_bytes;
  - обрезанное тело (obj.truncated) распаковывается частично,
    сколько успело прийти;
  - ошибка распаковки → b"", детекторы просто ничего не находят.
"""
import zlib

from paradox.config import Config

BINARY_CONTENT_ENCODINGS = frozenset({
    "gzip", "x-gzip", "deflate", "br", "compress", "zstd",
})

BINARY_CONTENT_TYPES = frozenset({
    "application/octet-stream",
    "application/ocsp-request",
    "application/x-ocsp-request",
    "application/zip",
    "application/gzip",
    "application/pdf",
    "application/x-protobuf",
    "application/wasm",
})

BINARY_TYPE_PREFIXES = ("image/", "audio/", "video/", "font/")


def printable_ratio(data: bytes) -> float:
    """Доля байт, которые выглядят как текст (ASCII + табы/переводы)."""
    if not data:
        return 1.0
    printable = sum(
        1 for b in data if 32 <= b < 127 or b in (9, 10, 13)
    )
    return printable / len(data)


def content_type_of(obj) -> str:
    return (
        (obj.headers or {}).get("content-type") or ""
    ).split(";", 1)[0].strip().lower()


def content_encodings(obj) -> list[str]:
    """content-encoding как список (может быть "gzip, br")."""
    raw = (obj.headers or {}).get("content-encoding") or ""
    return [e.strip().lower() for e in raw.split(",") if e.strip()]


def _gunzip(data: bytes, limit: int) -> bytes | None:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(data, limit)
    except zlib.error:
        return None


def _inflate(data: bytes, limit: int) -> bytes | None:
    """deflate: сначала zlib-обёртка (RFC 1950), затем raw (RFC 1951)."""
    wrapped = (
        len(data) >= 2
        and data[0] & 0x0F == 8
        and (data[0] << 8 | data[1]) % 31 == 0
    )
    order = (zlib.MAX_WBITS, -zlib.MAX_WBITS)
    if not wrapped:
        order = (-zlib.MAX_WBITS, zlib.MAX_WBITS)
    for wbits in order:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data, limit)
        except zlib.error:
            continue
        if out:
            return out
    return None


def decoded_body(obj, config: Config) -> bytes:
    """
    Тело после снятия content-encoding (в обратном порядке).

    b"" — если распаковать не удалось или кодировка неизвестна.
    Размер ограничен config.http_body_max_decoded_bytes.
    """
    data = obj.body or b""
    if not data:
        return b""

    encodings = content_encodings(obj)
    if not encodings:
        # Малое зло любит слать gzip без content-encoding: формат
        # виден по magic-байтам 1f 8b. Если распаковать не вышло —
        # возвращаем как есть, дальше решит критерий текстовости.
        if (
            config.http_body_decompress
            and data[:2] == b"\x1f\x8b"
        ):
            decoded = _gunzip(data, config.http_body_max_decoded_bytes)
            if decoded:
                return decoded
        return data
    if not config.http_body_decompress:
        return b""

    limit = config.http_body_max_decoded_bytes
    for encoding in reversed(encodings):
        if encoding == "identity":
            continue
        if encoding in ("gzip", "x-gzip"):
            data = _gunzip(data, limit)
        elif encoding == "deflate":
            data = _inflate(data, limit)
        else:
            return b""
        if data is None:
            return b""

    return data


def payload_is_text(data: bytes, content_type: str, config: Config) -> bool:
    """Текстовое ли содержимое с учётом content-type."""
    if content_type.startswith("text/"):
        return True
    if content_type in config.http_text_content_types:
        return True
    if content_type in BINARY_CONTENT_TYPES:
        return False
    if content_type.startswith(BINARY_TYPE_PREFIXES):
        return False
    return (
        printable_ratio(data)
        >= config.command_injection_min_printable_ratio
    )


def body_for_scan(obj, config: Config) -> bytes | None:
    """
    Распакованное текстовое тело для поиска паттернов, или None.

    None означает: распаковать не удалось, тело бинарное или
    пустое — искать в нём команды/маркеры бессмысленно.

    Если тело было сжато, а content-type врёт про
    application/octet-stream, смотрим на распакованное содержимое:
    зловред часто ставит octet-stream на gzip-обёртку JSON'а.
    """
    data = decoded_body(obj, config)
    if not data:
        return None

    content_type = content_type_of(obj)
    if payload_is_text(data, content_type, config):
        return data

    compressed = bool(content_encodings(obj)) or obj.body[:2] == b"\x1f\x8b"
    if compressed and (
        printable_ratio(data)
        >= config.command_injection_min_printable_ratio
    ):
        return data

    return None


def is_text_body(obj, config: Config) -> bool:
    """
    Текстовое ли тело НА ПРОВОДЕ (без распаковки).

    Используется только http_binary_upload: для него сжатое тело —
    это всё равно бинарная выгрузка. Детекторы, которые ищут
    паттерны, должны использовать body_for_scan().
    """
    if content_encodings(obj):
        return False
    return payload_is_text(obj.body, content_type_of(obj), config)
