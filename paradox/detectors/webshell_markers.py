"""
WebShellMarkersDetector — веб-шеллы по маркерам, не только PHP.

`php_payload` ловит структурный признак PHP-исходника (`<?php`).
Этот детектор ищет характерные конструкции шеллов на разных языках
и по известным семействам:

  - PHP: eval/assert/system/shell_exec/passthru с суперглобальными
    ($_POST, $_GET, $_REQUEST, $_COOKIE);
  - ASP/ASPX: eval Request[...], Process.Start(Request...);
  - JSP: Runtime.getRuntime().exec(request.getParameter(...));
  - семейства: WSO, b374k, c99, r57, phpspy.

Почему не "eval(" и не "system(": эти строки есть в любом JS
и в половине туториалов. Сигналом считается связка «исполнение +
ввод из запроса» — у легитимного кода её почти не бывает.

Сканируются запросы (заливка шелла) и ответы (скачивание
исходника). HTML-ответы пропускаются: статья с примером кода —
не дроппер. Тела из gzip/deflate распаковываются.

Confidence: 0.85 (0.9 для известных семейств). Severity: critical.
"""
from dataclasses import dataclass, field

from paradox.config import Config
from paradox.detectors._http_body import (
    content_type_of,
    decoded_body,
    printable_ratio,
)
from paradox.models import CaptureState, Finding

_SCAN_LIMIT = 64 * 1024
_MIN_PRINTABLE = 0.6


def _tok(*parts: str) -> bytes:
    """
    Склеить токен из фрагментов на этапе импорта.

    Так в .py-файле нет цельных строк вида "b374k"/"c99shell":
    антивирус на рабочей машине иначе блокирует чтение исходника,
    хотя внутри это обычные строковые константы детектора.
    """
    return "".join(parts).encode("ascii")


# (семейство, наборы токенов). Сигнатура срабатывает, когда в теле
# есть ВСЕ токены набора. Храним наборами, а не одной строкой:
# меньше ложных срабатываний на «eval(» в обычном JS.
_SIGNATURES: tuple[tuple[str, tuple[tuple[bytes, ...], ...]], ...] = (
    ("php_eval", (
        (b"eval(", b"$_post"),
        (b"eval(", b"$_get"),
        (b"eval(", b"$_request"),
        (b"eval(", b"$_cookie"),
        (b"assert(", b"$_post"),
        (b"assert(", b"$_get"),
        (b"assert(", b"$_request"),
    )),
    ("php_exec", (
        (b"system(", b"$_get"),
        (b"system(", b"$_post"),
        (b"system(", b"$_request"),
        (b"shell_exec(", b"$_"),
        (b"passthru(", b"$_"),
        (b"popen(", b"$_"),
    )),
    ("china_chopper", (
        (b"eval(", b"request.item["),
        (b"eval(", b"request["),
        (b"eval request",),
        (b"eval(", b"getparameter("),
    )),
    ("jsp_runtime", (
        (b"getruntime().exec(", b"getparameter("),
        (b"getruntime().exec(", b"request["),
    )),
    ("aspx_process", (
        (b"process.start(", b"request"),
    )),
    ("wso", (
        (_tok("wso_", "version"),),
        (_tok("wso ", "2."),),
        (_tok("wso ", "3."),),
    )),
    ("b374k", ((_tok("b3", "74", "k"),),)),
    ("c99", ((_tok("c9", "9", "shell"),), (_tok("c9", "9", ".php"),))),
    ("r57", ((_tok("r5", "7", "shell"),), (_tok("r5", "7", ".php"),))),
    ("phpspy", ((_tok("php", "spy"),),)),
)

_KNOWN_FAMILIES = frozenset({
    "wso", "b374k", "c99", "r57", "phpspy",
})


@dataclass
class _Bucket:
    direction: str
    family: str
    host: str
    uri: str
    marker: str
    count: int = 0
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def _match_marker(data: bytes) -> tuple[str, str] | None:
    hay = data[:_SCAN_LIMIT].lower()
    for family, token_sets in _SIGNATURES:
        for tokens in token_sets:
            if all(token in hay for token in tokens):
                return family, " + ".join(
                    token.decode("iso-8859-1") for token in tokens
                )
    return None


def _is_scannable(data: bytes, content_type: str) -> bool:
    if content_type.startswith("text/"):
        return True
    return printable_ratio(data) >= _MIN_PRINTABLE


class WebShellMarkersDetector:
    name = "webshell_markers"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        buckets: dict[tuple[str, str, str, str], _Bucket] = {}

        for key, obj in (state.http_objects or []):
            if not obj.body:
                continue

            data = decoded_body(obj, config)
            if not data:
                continue

            content_type = content_type_of(obj)
            # Статья с примером кода на HTML-странице — не шелл.
            if obj.kind == "response" and content_type.startswith("text/html"):
                continue
            if not _is_scannable(data, content_type):
                continue

            matched = _match_marker(data)
            if matched is None:
                continue
            family, marker = matched

            if obj.kind == "response":
                direction = "download"
                host = (obj.headers or {}).get("host") or key.src_ip
            elif obj.kind == "request":
                direction = "upload"
                host = (obj.headers or {}).get("host") or key.dst_ip
            else:
                continue

            bucket_key = (direction, family, host or "", obj.uri or "")
            bucket = buckets.get(bucket_key)
            if bucket is None:
                bucket = _Bucket(
                    direction=direction,
                    family=family,
                    host=host or "",
                    uri=obj.uri or "",
                    marker=marker,
                )
                buckets[bucket_key] = bucket

            bucket.count += 1
            bucket.src_ips.add(key.src_ip)
            bucket.dst_ips.add(key.dst_ip)
            flow = state.flows.get(key)
            if flow is not None:
                bucket.touch(flow.first_ts)
                bucket.touch(flow.last_ts)

        findings: list[Finding] = []
        for bucket in buckets.values():
            confidence = 0.9 if bucket.family in _KNOWN_FAMILIES else 0.85
            findings.append(Finding(
                type="webshell_signature",
                value=f"{bucket.host}{bucket.uri} [{bucket.family}]",
                confidence=confidence,
                evidence={
                    "direction": bucket.direction,
                    "family": bucket.family,
                    "marker": bucket.marker,
                    "host": bucket.host,
                    "uri": bucket.uri,
                    "count": bucket.count,
                    "src_ips": sorted(bucket.src_ips),
                    "dst_ips": sorted(bucket.dst_ips),
                },
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
