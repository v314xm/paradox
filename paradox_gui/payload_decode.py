"""Слои декодирования payload'а: URL → Base64 → Gzip/deflate.

Одна и та же инъекция приходит в разных обёртках: form-urlencoded
(`%0d`, `%3d`), base64 в параметре, gzip поверх JSON. Вместо ручного
декодирования в консоли строим цепочку и отдаём её вариантами:
«как пришло», «URL-декод», «URL → Base64», «Gzip» и т. п.

Правила:
  - каждый шаг применяется только если результат осмысленный
    (текст или сжатый поток), иначе вариант не появляется;
  - каждый тип шага — не больше одного раза (защита от циклов);
  - распаковка ограничена по размеру;
  - ничего не пишется на диск и не исполняется.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

#: Потолок распаковки: защита от zip-бомбы в payload'е.
_MAX_DECODED = 1 << 20
#: Минимальная длина base64-строки, которую вообще пробуем.
_MIN_B64 = 16
#: Доля печатных байт, при которой считаем результат текстом.
_TEXT_RATIO = 0.85

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_WS_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class Variant:
    """Представление payload'а: цепочка шагов и байты."""

    steps: tuple[str, ...]
    data: bytes
    label: str | None = None

    def is_raw(self) -> bool:
        return not self.steps


def _is_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(
        1 for b in data if 32 <= b < 127 or b in (9, 10, 13)
    )
    return printable / len(data) >= _TEXT_RATIO


def _as_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("iso-8859-1", errors="replace")


def _percent_like(text: str) -> bool:
    return bool(_PERCENT_RE.search(text))


def _try_url(data: bytes) -> bytes | None:
    text = _as_text(data)
    if not _percent_like(text):
        return None
    decoded = unquote_to_bytes(text.replace("+", " "))
    return decoded if decoded and decoded != data else None


def _try_base64(data: bytes) -> bytes | None:
    if not _is_text(data):
        return None
    compact = _WS_RE.sub("", _as_text(data))
    if len(compact) < _MIN_B64 or len(compact) % 4:
        return None
    if not _B64_RE.match(compact):
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    if _is_text(raw) or _compression_kind(raw) is not None:
        return raw
    return None


def _compression_kind(data: bytes) -> str | None:
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if (
        len(data) >= 2
        and data[0] & 0x0F == 8
        and (data[0] << 8 | data[1]) % 31 == 0
    ):
        return "deflate"
    return None


def _try_decompress(data: bytes, kind: str) -> bytes | None:
    wbits = 16 + zlib.MAX_WBITS if kind == "gzip" else zlib.MAX_WBITS
    try:
        inflater = zlib.decompressobj(wbits)
        out = inflater.decompress(data, _MAX_DECODED)
    except zlib.error:
        return None
    return out or None


def build_variants(data: bytes) -> list[Variant]:
    """Цепочка представлений: от «как пришло» до самого разобранного."""
    variants = [Variant((), data)]
    steps: list[str] = []
    current = data

    for _ in range(4):
        step = _next_step(current, steps)
        if step is None:
            break
        name, value = step
        steps.append(name)
        current = value
        variants.append(Variant(tuple(steps), current))

    return variants


def _next_step(data: bytes, done: list[str]) -> tuple[str, bytes] | None:
    if "url" not in done:
        decoded = _try_url(data)
        if decoded is not None:
            return "url", decoded

    if "base64" not in done:
        decoded = _try_base64(data)
        if decoded is not None:
            return "base64", decoded

    kind = _compression_kind(data)
    if kind is not None and kind not in done:
        unpacked = _try_decompress(data, kind)
        if unpacked is not None:
            return kind, unpacked

    return None
