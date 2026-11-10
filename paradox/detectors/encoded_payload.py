"""
EncodedPayloadDetector — URL или домен, спрятанный в base64/hex.

Сигнал: параметр query-строки или тела
`application/x-www-form-urlencoded` декодируется из base64 (в том числе
urlsafe) или hex в абсолютный URL либо домен.

Так прячут:
  - адрес C2 в «безобидном» параметре телеметрии;
  - редирект (`?next=aHR0cHM6...`);
  - сайт-источник при отправке статистики наружу (пример:
    `site=aHR0cHM6Ly9taW5maW4uc2FtcmVnaW9uLnJ1` в POST
    `/wpfilebase-pro/stats-sink.php`).

Почему отдельный детектор: `command_injection` раскрывает percent-
encoding и ищет инъекции, но base64 не трогает; остальные правила
смотрят либо на тело, либо на DNS/TLS. Значение из одного URL в
query не покрыто ничем.

Чтобы не ловить случайные токены, декодированный текст должен быть
именно URL или доменом, а исходное значение — не короче
`encoded_payload_min_value_len`. Тело читается только у форм и только
если оно не обрезано.
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qsl, urlsplit

from paradox.config import Config
from paradox.models import CaptureState, Finding

_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s\"'<>]+$", re.IGNORECASE)
_PROTO_REL_RE = re.compile(r"^//[^\s\"'<>]+$")
_HOST_RE = re.compile(
    r"^(?=.{4,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?:/[^\s]*)?$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _printable(text: str) -> bool:
    return bool(text) and text.isprintable()


def _looks_like_location(text: str) -> bool:
    return bool(
        _URL_RE.match(text)
        or _PROTO_REL_RE.match(text)
        or _HOST_RE.match(text)
    )


def _decode_base64(value: str, max_len: int) -> str | None:
    if len(value) % 4 == 1:
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(
            padded, altchars=b"-_", validate=True,
        )
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > max_len:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _printable(text) else None


def _decode_hex(value: str, max_len: int) -> str | None:
    if len(value) % 2 or not _HEX_RE.match(value):
        return None
    if len(value) // 2 > max_len:
        return None
    try:
        text = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text) else None


def _decode(value: str, max_len: int) -> tuple[str, str] | None:
    decoded = _decode_base64(value, max_len)
    if decoded:
        return decoded, "base64"
    decoded = _decode_hex(value, max_len)
    if decoded:
        return decoded, "hex"
    return None


class EncodedPayloadDetector:
    name = "encoded_payload"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_len = config.encoded_payload_min_value_len
        max_len = config.encoded_payload_max_decoded_len

        findings: list[Finding] = []
        seen: set[tuple] = set()

        for key, obj in state.http_objects:
            if obj.kind != "request":
                continue
            params: list[tuple[str, str, bool]] = []

            query = urlsplit(obj.uri or "").query
            if query:
                params.extend(
                    (name, value, False)
                    for name, value in parse_qsl(
                        query, keep_blank_values=False,
                    )
                )

            content_type = (
                obj.headers.get("content-type", "")
                if obj.headers else ""
            ).lower()
            if (
                obj.body
                and not obj.truncated
                and content_type.startswith(
                    "application/x-www-form-urlencoded",
                )
            ):
                params.extend(
                    (name, value, True)
                    for name, value in parse_qsl(
                        obj.body.decode("utf-8", "replace"),
                        keep_blank_values=False,
                    )
                )

            for param, raw_value, in_body in params:
                if len(raw_value) < min_len:
                    continue
                decoded = _decode(raw_value, max_len)
                if decoded is None:
                    continue
                text, encoding = decoded
                if not _looks_like_location(text):
                    continue

                dedup = (key, param, text, in_body)
                if dedup in seen:
                    continue
                seen.add(dedup)

                findings.append(Finding(
                    type="encoded_payload",
                    value=f"{param}={text}",
                    src_ip=key.src_ip,
                    dst_ip=key.dst_ip,
                    dst_port=key.dst_port,
                    confidence=0.6,
                    evidence={
                        "method": obj.method,
                        "uri_path": urlsplit(obj.uri or "").path,
                        "http_host": (obj.headers or {}).get("host"),
                        "param": param,
                        "encoding": encoding,
                        "decoded": text,
                        "decoded_length": len(text),
                        "encoded_value": raw_value[:120],
                        "in_body": in_body,
                    },
                    first_seen=None,
                    last_seen=None,
                ))

        findings.sort(key=lambda f: (f.dst_ip or "", f.value))
        return findings
