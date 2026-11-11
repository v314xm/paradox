"""Деобфускация скриптов без исполнения кода.

Инжекты приходят в обёртках: `gzinflate(base64_decode('…'))` в PHP,
`eval(atob('…'))` в JS, `powershell -EncodedCommand …` в Windows.
Здесь мы ищем такие литералы и прогоняем их через безопасные
преобразования, пока результат не станет читаемым текстом.

Правила:
  - ни одна функция не исполняет код и не пишет на диск;
  - каждый шаг ограничен размером (`_MAX_DECODED`);
  - цепочка не длиннее `_MAX_DEPTH`, повторные результаты
    отбрасываются по хешу;
  - если преобразование дало бинарь — оно не считается полезным
    слоем, кроме случая, когда бинарь распаковался в текст.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import re
import zlib
from dataclasses import dataclass

_MAX_DECODED = 1 << 20
_MAX_DEPTH = 4
_MIN_B64 = 16

_POWERSHELL_RE = re.compile(
    r"-EncodedCommand\s+([A-Za-z0-9+/=]{16,})", re.I,
)
_FROM_CHAR_CODE_RE = re.compile(
    r"String\.fromCharCode\(\s*([\d,\s]+)\)", re.I,
)
_ROT13_RE = re.compile(
    r"str_rot13\s*\(\s*(['\"])(.*?)\1\s*\)", re.I | re.S,
)
_JS_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_UTF16_TEXT_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_CODE_WORDS = (
    "eval", "system", "exec", "shell", "http", "cmd", "powershell",
    "<?php", "function", "document", "window", "base64",
)


@dataclass(frozen=True)
class Layer:
    label: str
    data: bytes


def _text_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(
        1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13)
    )
    return printable / len(data)


def _as_utf8(data: bytes) -> bytes:
    """UTF-16LE-текст из PowerShell/JS привести к UTF-8."""
    if b"\x00" not in data:
        return data
    matches = _UTF16_TEXT_RE.findall(data)
    if not matches:
        return data
    try:
        return data.decode("utf-16-le").encode("utf-8")
    except UnicodeDecodeError:
        return data


def _is_good(data: bytes) -> bool:
    if not data or len(data) > _MAX_DECODED:
        return False
    return _text_ratio(data) >= 0.75


def _score(data: bytes) -> float:
    if not data or len(data) > _MAX_DECODED:
        return -1.0
    text = data.decode("utf-8", "replace").lower()
    score = _text_ratio(data) * 2.0 + min(len(data) / 2000.0, 1.0)
    score += sum(0.15 for word in _CODE_WORDS if word in text)
    return score


def _decompress(data: bytes) -> tuple[str, bytes] | None:
    attempts = (
        ("Gzip", 16 + zlib.MAX_WBITS),
        ("Deflate", zlib.MAX_WBITS),
        ("Deflate (raw)", -zlib.MAX_WBITS),
    )
    for label, wbits in attempts:
        try:
            unpacked = zlib.decompress(data, wbits)
        except zlib.error:
            continue
        if unpacked and len(unpacked) <= _MAX_DECODED:
            return label, unpacked
    return None


def _base64_candidates(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for match in _B64_RE.finditer(text):
        value = match.group(0)
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        unpacked = _decompress(raw)
        if unpacked is not None:
            out.append(unpacked)
        elif _is_good(raw):
            out.append(("Base64", _as_utf8(raw)))
    return out


def _explicit_steps(text: str, data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []

    for match in _POWERSHELL_RE.finditer(text):
        try:
            raw = base64.b64decode(match.group(1), validate=True)
        except (binascii.Error, ValueError):
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding).encode("utf-8")
            except UnicodeDecodeError:
                continue
            if _is_good(decoded):
                out.append(("PowerShell -EncodedCommand", decoded))
                break

    for match in _FROM_CHAR_CODE_RE.finditer(text):
        try:
            codes = [
                int(part) for part in re.findall(r"\d+", match.group(1))
            ]
        except ValueError:
            continue
        raw = bytes(code for code in codes if 0 <= code <= 0x10FFFF)
        if _is_good(raw):
            out.append(("JS String.fromCharCode", raw))

    for match in _ROT13_RE.finditer(text):
        raw = _rot13(match.group(2)).encode("utf-8")
        out.append(("PHP str_rot13", raw))

    escapes = _JS_ESCAPE_RE.findall(text)
    if len(escapes) >= 2:
        def replace(match: re.Match) -> str:
            code = match.group(1) or match.group(2)
            return chr(int(code, 16))

        raw = _JS_ESCAPE_RE.sub(replace, text).encode("utf-8")
        if _is_good(raw):
            out.append(("JS \\x/\\u escapes", raw))

    if re.search(r"&#x?[0-9a-fA-F]+;|&[a-z]+;", text, re.I):
        raw = html.unescape(text).encode("utf-8")
        if raw != data and _is_good(raw):
            out.append(("HTML entities", raw))

    return out


def _rot13(value: str) -> str:
    table = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    return value.translate(table)


def _hex_candidates(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for match in _HEX_RE.finditer(text):
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        unpacked = _decompress(raw)
        if unpacked is not None:
            out.append(unpacked)
        elif _is_good(raw):
            out.append(("Hex", _as_utf8(raw)))
    return out


def _next_layer(data: bytes) -> Layer | None:
    text = data.decode("utf-8", "replace")
    candidates: list[Layer] = []
    for label, value in _explicit_steps(text, data):
        candidates.append(Layer(label, value))
    for label, value in _base64_candidates(text):
        candidates.append(Layer(label, value))
    for label, value in _hex_candidates(text):
        candidates.append(Layer(label, value))

    gzip_index = data.find(b"\x1f\x8b")
    if gzip_index >= 0:
        try:
            unpacked = gzip.decompress(data[gzip_index:])
        except (OSError, EOFError):
            unpacked = b""
        if unpacked and len(unpacked) <= _MAX_DECODED:
            candidates.append(Layer("Gzip", unpacked))

    if not candidates:
        return None
    return max(candidates, key=lambda layer: _score(layer.data))


def deobfuscate(data: bytes) -> list[Layer]:
    """Цепочка безопасных преобразований от исходных байт к тексту."""
    layers: list[Layer] = []
    seen = {hashlib.sha256(data).digest()}
    current = data
    for _ in range(_MAX_DEPTH):
        layer = _next_layer(current)
        if layer is None:
            break
        key = hashlib.sha256(layer.data).digest()
        if key in seen:
            break
        seen.add(key)
        layers.append(layer)
        current = layer.data
    return layers
