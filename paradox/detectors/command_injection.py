"""
CommandInjectionDetector — RCE через HTTP URI или POST body.

Работает поверх state.http_objects (заполняется HTTPObjectExtractor
из склеенных TCP-потоков). Ищет паттерны команд и языковые
конструкции в:
  - URI запроса (query string, path)
  - body запроса (form-urlencoded декодируется)

Признаки RCE:
  - io.popen / os.execute (Lua)
  - system( / exec( / shell_exec( (PHP)
  - os.system / subprocess (Python)
  - $(...) / backticks (shell)
  - cmd.exe / /bin/sh + wget/curl (классика)

Агрегация по (src_ip, uri). Один запрос с RCE = один finding.
Если паттерн найден в N телах — count = N, но finding один.

Ложные срабатывания:
  - HTML/JS в body содержит eval() — фильтруем по kind="request"
  - JSON с "system" в значении — может пройти, если нет "(".
    Поэтому "system(" (со скобкой) — high confidence.

Confidence:
  - high-паттерн → 0.9
  - только medium-паттерны (≥2) → 0.75
  - только один medium → 0.6
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote


from paradox.config import Config
from paradox.models import CaptureState, Finding


@dataclass
class _Bucket:
    count: int = 0
    matched_high: Counter = field(default_factory=Counter)
    matched_medium: Counter = field(default_factory=Counter)
    body_samples: list[bytes] = field(default_factory=list)
    methods: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    first_seen: float | None = None
    last_seen: float | None = None


class CommandInjectionDetector:
    name = "command_injection"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        high = config.command_injection_patterns_high
        medium = config.command_injection_patterns_medium
        min_patterns = config.command_injection_min_patterns

        buckets: dict[tuple[str, str], _Bucket] = defaultdict(_Bucket)

        for key, obj in (state.http_objects or []):
            if obj.kind != "request":
                continue

            # Текст для поиска: URI + body (декодированный)
            haystack_parts: list[str] = []
            if obj.uri:
                haystack_parts.append(obj.uri)
                # декодированный вариант — %3d → "=", %2f → "/"
                try:
                    haystack_parts.append(unquote(obj.uri))
                except Exception:
                    pass

            if obj.body:
                # iso-8859-1 — все 256 байт → символы, безопасно для поиска
                raw_text = obj.body.decode("iso-8859-1", errors="ignore")
                haystack_parts.append(raw_text)
                # url-decode (form-urlencoded)
                try:
                    haystack_parts.append(unquote(raw_text))
                except Exception:
                    pass

            if not haystack_parts:
                continue

            haystack = "\n".join(haystack_parts)
            haystack_lc = haystack.lower()

            found_high: list[str] = [
                p for p in high if p.lower() in haystack_lc
            ]
            found_medium: list[str] = [
                p for p in medium if p.lower() in haystack_lc
            ]

            total = len(found_high) + len(found_medium)
            if total < min_patterns:
                continue
            # Если ни одного high, требуем хотя бы 2 medium —
            # одна подозрительная строка слишком шумно.
            if not found_high and len(found_medium) < 2:
                continue

            # Ключ агрегации: (src_ip, uri)
            agg_key = (key.src_ip, obj.uri or "")
            b = buckets[agg_key]
            b.count += 1
            for p in found_high:
                b.matched_high[p] += 1
            for p in found_medium:
                b.matched_medium[p] += 1
            if len(b.body_samples) < 3 and obj.body:
                b.body_samples.append(obj.body[:256])
            if obj.method:
                b.methods.add(obj.method)
            if obj.headers and obj.headers.get("host"):
                b.hosts.add(obj.headers["host"])
            if key.dst_ip:
                b.dst_ips.add(key.dst_ip)
            if key.dst_port is not None:
                b.dst_ports.add(key.dst_port)

            # Заполняем timestamps из flow.
            # Один URI может прийти через несколько flows —
            # берём min(first_ts) и max(last_ts).
            flow = state.flows.get(key)
            if flow is not None:
                if flow.first_ts is not None:
                    if b.first_seen is None or flow.first_ts < b.first_seen:
                        b.first_seen = flow.first_ts
                if flow.last_ts is not None:
                    if b.last_seen is None or flow.last_ts > b.last_seen:
                        b.last_seen = flow.last_ts

        findings: list[Finding] = []
        for (src_ip, uri), b in buckets.items():
            if b.matched_high:
                confidence = 0.9
            elif sum(b.matched_medium.values()) >= 2:
                confidence = 0.75
            else:
                confidence = 0.6

            all_patterns: list[str] = sorted(
                set(b.matched_high) | set(b.matched_medium)
            )
            dst_ips_sorted = sorted(b.dst_ips)
            evidence = {
                "src_ip": src_ip,
                "uri": uri,
                "count": b.count,
                "matched_high": sorted(b.matched_high.keys()),
                "matched_medium": sorted(b.matched_medium.keys()),
                "matched_patterns": all_patterns,
                "methods": sorted(b.methods),
                "hosts": sorted(b.hosts)[:5],
                "dst_ip": dst_ips_sorted[0] if dst_ips_sorted else None,
                "dst_ips": dst_ips_sorted,
                "dst_ports": sorted(b.dst_ports),
            }
            if b.body_samples:
                evidence["body_samples"] = [
                    s.decode("iso-8859-1", errors="replace")[:200]
                    for s in b.body_samples
                ]

            findings.append(Finding(
                type="command_injection",
                value=f"{src_ip} → {uri}",
                confidence=confidence,
                evidence=evidence,
                first_seen=b.first_seen,
                last_seen=b.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings