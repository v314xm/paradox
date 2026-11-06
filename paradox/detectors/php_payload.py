"""
PhpPayloadDetector — PHP-исходник в HTTP-трафике.

Два сигнала по одному маркеру `<?php`:

  php_download    — ответ сервера, тело которого начинается с `<?php`.
                    Это не страница (страница начинается с <html>),
                    а скачанный PHP-скрипт: веб-шелл, дроппер,
                    загрузчик следующего этапа.

  webshell_upload — запрос POST/PUT/PATCH, в теле которого есть
                    `<?php`. Атакующий заливает веб-шелл на сервер.

Почему по телу, а не по расширению:
  `path.endswith(".php")` — это каждый /index.php и /wp-login.php
  в любом захвате. Расширение ничего не говорит; говорит
  содержимое. `<?php` в начале ответа — признак исходника, а не
  результата его выполнения.

Ограничения:
  - brotli/zstd-ответы не распаковываются (нет зависимостей);
    gzip/deflate распаковываются (см. _http_body.decoded_body);
  - HTML-ответы не проверяются: код в статье/туториале — не дроппер;
  - тело запроса сканируется в первых 64 КБ после распаковки
    (multipart сохраняется целиком, маркер обычно в начале).

Confidence: php_download 0.85; webshell_upload 0.8,
multipart/form-data 0.85. Severity: high / critical.
"""
from dataclasses import dataclass, field

from paradox.config import Config
from paradox.detectors._http_body import decoded_body
from paradox.models import CaptureState, Finding

PHP_OPEN = b"<?php"
_BOM_WS = b"\xef\xbb\xbf\x00 \t\r\n"
_HEAD_LIMIT = 64                # для ответа: маркер только в начале
_REQUEST_SCAN_LIMIT = 64 * 1024  # для запроса: ищем в первых 64 КБ
_UPLOAD_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _content_type(obj) -> str:
    return (
        (obj.headers or {}).get("content-type") or ""
    ).split(";", 1)[0].strip().lower()


def _starts_with_php(body: bytes) -> bool:
    """Тело начинается с `<?php` (допускаем BOM и пробелы)."""
    head = body[:_HEAD_LIMIT].lstrip(_BOM_WS)
    return head.startswith(PHP_OPEN)


def _contains_php(body: bytes) -> bool:
    return PHP_OPEN in body[:_REQUEST_SCAN_LIMIT]


@dataclass
class _Bucket:
    kind: str
    host: str
    uri: str
    count: int = 0
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    content_types: set[str] = field(default_factory=set)
    status_codes: set[int] = field(default_factory=set)
    max_body_size: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


class PhpPayloadDetector:
    name = "php_payload"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        buckets: dict[tuple[str, str, str], _Bucket] = {}

        def bucket_for(kind: str, host: str, uri: str) -> _Bucket:
            key = (kind, host, uri)
            b = buckets.get(key)
            if b is None:
                b = _Bucket(kind=kind, host=host, uri=uri)
                buckets[key] = b
            return b

        for key, obj in (state.http_objects or []):
            if not obj.body:
                continue
            # gzip/deflate: PHP-исходник может прийти сжатым.
            data = decoded_body(obj, config)
            if not data:
                continue

            content_type = _content_type(obj)
            if obj.kind == "response":
                if obj.status_code is not None and not (
                    200 <= obj.status_code < 300
                ):
                    continue
                if content_type.startswith("text/html"):
                    continue
                if not _starts_with_php(data):
                    continue
                kind = "php_download"
                host = (obj.headers or {}).get("host") or key.src_ip
            else:
                if (obj.method or "").upper() not in _UPLOAD_METHODS:
                    continue
                if not _contains_php(data):
                    continue
                kind = "webshell_upload"
                host = (obj.headers or {}).get("host") or key.dst_ip

            b = bucket_for(kind, host or "", obj.uri or "")
            b.count += 1
            b.src_ips.add(key.src_ip)
            b.dst_ips.add(key.dst_ip)
            if content_type:
                b.content_types.add(content_type)
            if obj.status_code is not None:
                b.status_codes.add(obj.status_code)
            b.max_body_size = max(b.max_body_size, len(data))

            flow = state.flows.get(key)
            if flow is not None:
                b.touch(flow.first_ts)
                b.touch(flow.last_ts)

        findings: list[Finding] = []
        for b in buckets.values():
            if b.kind == "php_download":
                confidence = 0.85
            else:
                confidence = (
                    0.85 if "multipart/form-data" in b.content_types else 0.8
                )

            evidence = {
                "kind": (
                    "download" if b.kind == "php_download" else "upload"
                ),
                "host": b.host,
                "uri": b.uri,
                "count": b.count,
                "src_ips": sorted(b.src_ips),
                "dst_ips": sorted(b.dst_ips),
                "content_types": sorted(b.content_types),
                "status_codes": sorted(b.status_codes),
                "max_body_size": b.max_body_size,
                "marker": "<?php",
            }

            findings.append(Finding(
                type=b.kind,
                value=f"{b.host}{b.uri}" if b.host else b.uri,
                confidence=confidence,
                evidence=evidence,
                first_seen=b.first_seen,
                last_seen=b.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
