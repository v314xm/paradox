"""Выдержка тела HTTP, в котором найдена инъекция или веб-шелл.

Зачем base64: отчёт — обычный файл на диске, и его может сканировать
антивирус. Цельные сигнатуры шеллов (`eval(` + `$_POST`) в JSON
рискуют быть помеченными и закарантиненными, поэтому выдержка хранится
в base64, а читаемый текст собирает GUI уже в памяти.

Тело берётся после снятия content-encoding — ровно то, что видел
детектор. Размер выдержки ограничен `payload_excerpt_bytes`.

Схема записи (лежит в finding["evidence"]["payload_samples"]):
    direction, method, host, uri, content_type, status_code,
    size (полный размер тела), sha256, truncated, is_text, text_b64
"""
from __future__ import annotations

import base64
import hashlib

from paradox.config import Config
from paradox.payload_analysis import split_multipart

#: Доля печатных байт, при которой выдержку показываем текстом.
TEXT_RATIO = 0.85


def is_text(data: bytes) -> bool:
    """Похожа ли выдержка на текст (а не на бинарь)."""
    if not data:
        return True
    printable = sum(
        1 for b in data if 32 <= b < 127 or b in (9, 10, 13)
    )
    return printable / len(data) >= TEXT_RATIO


def make_sample(
    data: bytes,
    *,
    obj=None,
    direction: str,
    config: Config,
) -> dict | None:
    """Запись о выдержке тела или None, если тела нет.

    obj — HttpObject, из которого взято тело (нужен для метаданных).
    direction — "request" | "response".
    """
    if not data:
        return None

    limit = max(1, int(getattr(config, "payload_excerpt_bytes", 8192)))
    excerpt = data[:limit]
    headers = (getattr(obj, "headers", None) or {})

    sample = {
        "direction": direction,
        "method": getattr(obj, "method", None) or "",
        "host": headers.get("host") or "",
        "uri": getattr(obj, "uri", None) or "",
        "content_type": (headers.get("content-type") or "").split(
            ";", 1
        )[0].strip(),
        "status_code": getattr(obj, "status_code", None),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": len(data) > limit,
        "is_text": is_text(excerpt),
        "text_b64": base64.b64encode(excerpt).decode("ascii"),
    }
    parts = _multipart_parts(data, config)
    if parts:
        sample["parts"] = parts
    return sample


def _multipart_parts(data: bytes, config: Config) -> list[dict]:
    """Части multipart/form-data с выдержкой каждого файла.

    Общая выдержка — первые N байт тела, поэтому файл из формы может
    начинаться уже за её границей. Здесь каждый файл сохраняется
    отдельно, с собственным offset и префиксом, а общий бюджет
    ограничен `payload_multipart_total_bytes`.
    """
    if not getattr(config, "payload_multipart_enabled", True):
        return []
    parts = split_multipart(
        data,
        max_parts=max(
            1, int(getattr(config, "payload_multipart_max_parts", 32)),
        ),
    )
    if not parts:
        return []

    field_limit = max(1, int(getattr(config, "payload_excerpt_bytes", 8192)))
    file_limit = max(
        1, int(getattr(config, "payload_multipart_file_bytes", 65536)),
    )
    budget = max(
        1, int(getattr(config, "payload_multipart_total_bytes", 262144)),
    )

    out: list[dict] = []
    for part in parts:
        limit = file_limit if part.kind == "file" else field_limit
        excerpt = part.data[:limit]
        if len(excerpt) > budget:
            excerpt = excerpt[:budget]
        out.append({
            "kind": part.kind,
            "name": part.name,
            "filename": part.filename,
            "content_type": part.content_type,
            "offset": part.offset,
            "size": part.size,
            "sha256": hashlib.sha256(part.data).hexdigest(),
            "excerpt_size": len(excerpt),
            "excerpt_truncated": len(excerpt) < part.size,
            "excerpt_b64": base64.b64encode(excerpt).decode("ascii"),
        })
        budget -= len(excerpt)
        if budget <= 0:
            break
    return out


def decode_sample(sample: dict) -> bytes:
    """Обратное к make_sample: байты выдержки для показа."""
    raw = sample.get("text_b64") or ""
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        return b""
