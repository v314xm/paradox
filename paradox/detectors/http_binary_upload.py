"""
HttpBinaryUploadDetector — серия бинарных POST'ов на внешний хост.

Признак RAT/stealer'а: заражённый хост отправляет на внешний
сервер серию POST'ов с бинарным телом (application/octet-stream,
gzip, зашифрованный блоб) по случайным URI.

Почему отдельный детектор, а не command_injection:
  бинарное тело — это не RCE, и совпадения "$("/"`" в сжатых
  байтах к командам отношения не имеют. Здесь сигнал другой:
  регулярная выгрузка данных на внешний хост.

Логика:
  1. Только HTTP-запросы (kind="request") с методом POST.
  2. Только outbound (внутренний src → внешний dst).
  3. Тело бинарное (см. is_text_body) и не меньше
     http_binary_upload_min_body_bytes.
  4. Агрегация по (src_ip, Host).
  5. Порог: count >= http_binary_upload_min_posts.
  6. Хост из http_binary_upload_allowlist_suffixes пропускается.

Что отсеивается:
  - OCSP-запросы (content-type application/ocsp-request) — норма.
  - Формы, JSON, XML, multipart — текст, это не этот детектор.
  - Одиночная загрузка файла (count < 3) — обычно легитимно.

Confidence: 0.55 (3 поста) → 0.75 (20+ постов).
"""
from collections import defaultdict
from dataclasses import dataclass, field

from paradox.config import Config
from paradox.detectors._http_body import is_text_body, printable_ratio
from paradox.models import CaptureState, Finding
from paradox.net_utils import classify_direction


@dataclass
class _Bucket:
    count: int = 0
    total_body_bytes: int = 0
    uris: set[str] = field(default_factory=set)
    content_types: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    weight: float = 0.0
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def _suffix_match(value: str, suffixes: frozenset[str]) -> bool:
    if not value or not suffixes:
        return False
    v = value.lower().rstrip(".")
    return any(v == s or v.endswith("." + s) for s in suffixes)


class HttpBinaryUploadDetector:
    name = "http_binary_upload"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_posts = config.http_binary_upload_min_posts
        min_bytes = config.http_binary_upload_min_body_bytes
        allow_suffixes = config.http_binary_upload_allowlist_suffixes
        ignored_types = config.http_binary_upload_ignored_content_types

        buckets: dict[tuple[str, str], _Bucket] = defaultdict(_Bucket)

        for key, obj in (state.http_objects or []):
            if obj.kind != "request":
                continue
            if (obj.method or "").upper() != "POST":
                continue
            if not obj.body or obj.body_size < min_bytes:
                continue
            if classify_direction(key.src_ip, key.dst_ip, config) != "outbound":
                continue
            if is_text_body(obj, config):
                continue

            headers = obj.headers or {}
            host = (headers.get("host") or "").strip().lower()
            if _suffix_match(host, allow_suffixes):
                continue

            content_type = (headers.get("content-type") or "").split(
                ";", 1,
            )[0].strip().lower()
            if content_type in ignored_types:
                continue

            b = buckets[(key.src_ip, host or key.dst_ip)]
            b.count += 1
            b.total_body_bytes += obj.body_size
            b.weight += printable_ratio(obj.body)
            if obj.uri:
                b.uris.add(obj.uri)
            if content_type:
                b.content_types.add(content_type)
            if key.dst_ip:
                b.dst_ips.add(key.dst_ip)
            if key.dst_port is not None:
                b.dst_ports.add(key.dst_port)

            flow = state.flows.get(key)
            if flow is not None:
                b.touch(flow.first_ts)
                b.touch(flow.last_ts)

        findings: list[Finding] = []
        for (src_ip, host), b in buckets.items():
            if b.count < min_posts:
                continue

            avg_body = b.total_body_bytes / b.count
            avg_printable = b.weight / b.count
            score = min(1.0, b.count / 20.0)
            confidence = round(0.55 + 0.2 * score, 3)

            findings.append(Finding(
                type="http_binary_upload",
                value=f"{src_ip} → {host}",
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=sorted(b.dst_ips)[0] if b.dst_ips else None,
                dst_port=(
                    sorted(b.dst_ports)[0] if b.dst_ports else None
                ),
                evidence={
                    "src_ip": src_ip,
                    "host": host,
                    "dst_ips": sorted(b.dst_ips),
                    "dst_ports": sorted(b.dst_ports),
                    "post_count": b.count,
                    "unique_uris": len(b.uris),
                    "uri_samples": sorted(b.uris)[:5],
                    "total_body_bytes": b.total_body_bytes,
                    "avg_body_bytes": round(avg_body, 1),
                    "avg_printable_ratio": round(avg_printable, 3),
                    "content_types": sorted(b.content_types),
                },
                first_seen=b.first_seen,
                last_seen=b.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
