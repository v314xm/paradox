"""Статический разбор payload'а для «Кода инжекта».

Ничего не исполняет и не пишет на диск: только байты, которые уже
есть в выдержке. Даёт то, что нужно аналитику до ручного разбора:
тип файла, хеши, строки, IOC, энтропию, вложенные файлы и части
multipart/form-data.

Функции чистые и вызываются из GUI на каждый выбранный sample;
тяжёлые операции ограничены по размеру и количеству.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import math
import re
import zipfile
from dataclasses import dataclass, field

_MAX_STRINGS = 120
_MAX_IOCS = 80
_MAX_EMBEDDED = 24
_MAX_ZIP_ENTRIES = 50

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}\b",
)
_HEX64_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
_HEX40_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_HEX32_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_TRAILING_PUNCT = ".,;:!?)]}'\""

_SIGNATURES = (
    (b"MZ", "PE", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "ELF", "application/x-elf"),
    (b"PK\x03\x04", "ZIP", "application/zip"),
    (b"%PDF", "PDF", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
    (b"GIF87a", "GIF", "image/gif"),
    (b"GIF89a", "GIF", "image/gif"),
    (b"\x1f\x8b", "GZIP", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7Z", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "RAR", "application/vnd.rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE", "application/x-ole-storage"),
    (b"SQLite format 3\x00", "SQLite", "application/vnd.sqlite3"),
)


@dataclass(frozen=True)
class PayloadPart:
    index: int
    kind: str            # "field" | "file"
    name: str
    filename: str
    content_type: str
    offset: int
    size: int
    data: bytes


@dataclass(frozen=True)
class EmbeddedFile:
    offset: int
    kind: str
    mime: str
    size: int | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class PayloadAnalysis:
    size: int
    sha256: str
    md5: str
    is_text: bool
    file_kind: str
    mime: str
    entropy: float
    entropy_blocks: list[tuple[int, float]]
    strings: list[str]
    urls: list[str]
    domains: list[str]
    ips: list[str]
    emails: list[str]
    hashes: list[str]
    embedded: list[EmbeddedFile]
    pe: dict | None
    parts: list[PayloadPart]


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts if count
    )


def entropy_blocks(
    data: bytes, block_size: int = 256, limit: int = 128,
) -> list[tuple[int, float]]:
    out: list[tuple[int, float]] = []
    for offset in range(0, min(len(data), block_size * limit), block_size):
        out.append((offset, round(entropy(data[offset:offset + block_size]), 3)))
    return out


def is_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(
        1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13)
    )
    return printable / len(data) >= 0.85


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("iso-8859-1", errors="replace")


def strings(data: bytes, limit: int = _MAX_STRINGS) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in _PRINTABLE_RE.finditer(data):
        value = match.group(0).decode("ascii", "replace")
        if value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= limit:
            return out
    for match in _UTF16_RE.finditer(data):
        value = match.group(0).decode("utf-16-le", "replace")
        if value not in seen and value.strip():
            seen.add(value)
            out.append(value)
        if len(out) >= limit:
            break
    return out


def _dedupe(values, limit: int = _MAX_IOCS) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = [
        url.rstrip(_TRAILING_PUNCT) for url in _URL_RE.findall(text)
    ]
    emails = _EMAIL_RE.findall(text)
    ips = []
    for candidate in _IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.append(candidate)
    domains = []
    for candidate in _DOMAIN_RE.findall(text):
        if _IPV4_RE.fullmatch(candidate):
            continue
        if candidate.lower().endswith((".png", ".jpg", ".gif", ".css", ".js")):
            continue
        domains.append(candidate.lower())
    hashes = (
        _HEX64_RE.findall(text)
        + _HEX40_RE.findall(text)
        + _HEX32_RE.findall(text)
    )
    return {
        "urls": _dedupe(urls),
        "domains": _dedupe(domains),
        "ips": _dedupe(ips),
        "emails": _dedupe(emails),
        "hashes": _dedupe(hashes),
    }


def _guess_type(data: bytes) -> tuple[str, str]:
    for signature, kind, mime in _SIGNATURES:
        if data.startswith(signature):
            return kind, mime
    if is_text(data):
        return "text", "text/plain"
    return "binary", "application/octet-stream"


def _parse_pe(data: bytes) -> dict | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    sections_count = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    optional = coff + 20
    magic = _u16(data, optional) if optional + 2 <= len(data) else 0
    subsystem = (
        _u16(data, optional + 68)
        if optional + 70 <= len(data) else 0
    )
    sections = []
    section_offset = optional + opt_size
    for index in range(min(sections_count, 32)):
        start = section_offset + index * 40
        if start + 40 > len(data):
            break
        name = data[start:start + 8].rstrip(b"\0").decode(
            "ascii", "replace",
        )
        raw_size = _u32(data, start + 16)
        raw_ptr = _u32(data, start + 20)
        raw = data[raw_ptr:raw_ptr + raw_size] if raw_ptr else b""
        sections.append({
            "name": name,
            "virtual_size": _u32(data, start + 8),
            "raw_size": raw_size,
            "entropy": round(entropy(raw), 3) if raw else 0.0,
        })
    return {
        "machine": machine,
        "magic": "PE32+" if magic == 0x20B else "PE32",
        "timestamp": timestamp,
        "subsystem": subsystem,
        "sections": sections,
    }


def _zip_size(data: bytes) -> int | None:
    index = data.rfind(b"PK\x05\x06")
    if index < 0 or index + 22 > len(data):
        return None
    cd_size = _u32(data, index + 12)
    cd_offset = _u32(data, index + 16)
    total = cd_offset + cd_size + 22
    return total if 0 < total <= len(data) else None


def _zip_entries(data: bytes, size: int | None) -> list[str]:
    if size is None:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(data[:size])) as archive:
            return [info.filename for info in archive.infolist()][
                :_MAX_ZIP_ENTRIES
            ]
    except (zipfile.BadZipFile, OSError, ValueError):
        return []


def find_embedded(data: bytes) -> list[EmbeddedFile]:
    found: list[EmbeddedFile] = []
    seen: set[int] = set()
    for signature, kind, mime in _SIGNATURES:
        pos = 0
        while len(found) < _MAX_EMBEDDED:
            index = data.find(signature, pos)
            if index < 0:
                break
            pos = index + 1
            if index in seen:
                continue
            detail: dict = {}
            size: int | None = None
            if kind == "PE":
                pe = _parse_pe(data[index:])
                if pe is None:
                    continue
                detail = pe
            elif kind == "ZIP":
                size = _zip_size(data[index:])
                entries = _zip_entries(data[index:], size)
                if entries:
                    detail = {"entries": entries}
            seen.add(index)
            found.append(EmbeddedFile(
                offset=index,
                kind=kind,
                mime=mime,
                size=size,
                detail=detail,
            ))
    found.sort(key=lambda item: item.offset)
    return found


def _part_headers(raw: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.strip().decode("latin-1").lower()] = (
            value.strip().decode("utf-8", "replace")
        )
    return headers


def _disposition_value(header: str, key: str) -> str:
    match = re.search(
        rf'{key}\*?=(?:"([^"]*)"|([^;\s]+))', header, re.I,
    )
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def split_multipart(
    data: bytes, max_parts: int = 32,
) -> list[PayloadPart]:
    """Разобрать multipart/form-data на поля и файлы.

    Границы ищем по строкам целиком, поэтому смещения частей точные
    даже когда файл начинается далеко за первой выдержкой.
    """
    first = re.search(rb"(?m)^--([^\r\n]+)\r?$", data)
    if first is None:
        return []
    token = first.group(1)
    boundary = rb"--" + token
    line_re = re.compile(
        rb"(?m)^" + re.escape(boundary) + rb"(--)?[ \t]*(?:\r?\n|$)",
    )
    matches = list(line_re.finditer(data))
    if not matches:
        return []

    parts: list[PayloadPart] = []
    for index, match in enumerate(matches):
        if match.group(1):
            break
        if index + 1 >= len(matches):
            break
        end = matches[index + 1].start()
        start = match.end()
        block = data[start:end]
        separator = b"\r\n\r\n" if b"\r\n\r\n" in block else b"\n\n"
        split = block.find(separator)
        if split < 0:
            continue
        headers = _part_headers(block[:split])
        body_offset = start + split + len(separator)
        body = data[body_offset:end]
        if body.endswith(b"\r\n"):
            body = body[:-2]
        elif body.endswith(b"\n"):
            body = body[:-1]
        disposition = headers.get("content-disposition", "")
        if "form-data" not in disposition.lower():
            continue
        name = _disposition_value(disposition, "name")
        filename = _disposition_value(disposition, "filename")
        parts.append(PayloadPart(
            index=index,
            kind="file" if filename else "field",
            name=name,
            filename=filename,
            content_type=headers.get("content-type", "").split(";", 1)[0],
            offset=body_offset,
            size=len(body),
            data=body,
        ))
        if len(parts) >= max_parts:
            break
    return parts


def analyze_payload(
    data: bytes,
    parts: list[PayloadPart] | None = None,
) -> PayloadAnalysis:
    if parts is None:
        parts = split_multipart(data)
    kind, mime = _guess_type(data)
    text = _decode(data)
    iocs = extract_iocs(text)
    return PayloadAnalysis(
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        is_text=is_text(data),
        file_kind=kind,
        mime=mime,
        entropy=round(entropy(data), 3),
        entropy_blocks=entropy_blocks(data),
        strings=strings(data),
        urls=iocs["urls"],
        domains=iocs["domains"],
        ips=iocs["ips"],
        emails=iocs["emails"],
        hashes=iocs["hashes"],
        embedded=find_embedded(data),
        pe=_parse_pe(data),
        parts=parts,
    )
