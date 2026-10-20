"""
VulnerablePathDetector — обращения к уязвимым путям в HTTP и скачивание
потенциально опасных файлов.

Работает поверх FlowStats.http_uri (заполняется HTTPExtractor).

Два сигнала:
  - vulnerable_path: URI содержит известный уязвимый путь
  - script_download: URI заканчивается на подозрительное расширение

Две стратегии агрегации (зависят от того, что делает src):

  1. Individual — если src обратился к < N разным URI к одной цели.
     Каждый URI → отдельный finding. Это может быть одиночное
     скачивание или единичная проверка /wp-login.php.

  2. Web scanner — если src обратился к >= N разным URI к одной цели.
     Это не N атак, это один сканер. Один finding web_scanner
     с тремя десятками путей в evidence.

Так 290 URI от одного IP превращаются в 1 finding, а не 290.
Нормальные одиночные обращения (единичный /wp-login.php) остаются
как individual findings.

Confidence:
  - vulnerable_path individual: 0.5 / 0.7 / 0.85 (по count)
  - script_download individual: 0.65 / 0.8 / 0.9 (по distinct srcs)
  - web_scanner: 0.9 (несколько десятков разных URI — почти
    наверняка автоматизированный инструмент)
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from paradox.config import Config
from paradox.models import CaptureState, Finding

_EVIDENCE_SAMPLE_SIZE = 5


@dataclass
class _UriBucket:
    """Агрегат flows по нормализованному пути в рамках (src, dst)."""
    kind: str
    path_key: str
    count: int = 0
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    uri_samples: set[str] = field(default_factory=set)
    matched_paths: set[str] = field(default_factory=set)
    extension: str | None = None
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, first_ts: float | None, last_ts: float | None) -> None:
        if first_ts is not None:
            if self.first_seen is None or first_ts < self.first_seen:
                self.first_seen = first_ts
        if last_ts is not None:
            if self.last_seen is None or last_ts > self.last_seen:
                self.last_seen = last_ts


def _confidence_vulnerable_path(count: int, distinct_srcs: int) -> float:
    if count >= 100 or distinct_srcs >= 10:
        return 0.85
    if count >= 10 or distinct_srcs >= 3:
        return 0.7
    return 0.5


def _confidence_script_download(count: int, distinct_srcs: int) -> float:
    if distinct_srcs >= 5:
        return 0.9
    if distinct_srcs >= 2:
        return 0.8
    if count >= 3:
        return 0.75
    return 0.65


class VulnerablePathDetector:
    name = "vulnerable_path"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        vulnerable_paths = config.vulnerable_paths
        script_exts = config.suspicious_download_extensions
        scanner_threshold = config.web_scanner_min_distinct_paths

        # (kind, path_key) → bucket для individual findings
        per_uri: dict[tuple[str, str], _UriBucket] = {}

        # (src_ip, dst_ip) → set[path_key] для детекции scanner
        pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
        pair_ts: dict[tuple[str, str], dict] = defaultdict(
            lambda: {"first": None, "last": None, "count": 0,
                     "src_ports": set(), "hosts": set(),
                     "methods": set(), "user_agents": set()}
        )

        # (src_ip, dst_ip) → kind → list[(path, count)] для scanner finding
        pair_paths: dict[tuple[str, str], dict[str, list[tuple[str, int]]]] = (
            defaultdict(lambda: defaultdict(list))
        )

        for key, flow in state.flows.items():
            uri = flow.http_uri
            if not uri:
                continue

            try:
                parsed = urlsplit(uri)
            except ValueError:
                continue
            raw_path = parsed.path or ""
            if not raw_path:
                continue
            path_key = unquote(raw_path).lower()

            matched_paths: list[str] = [
                vp for vp in vulnerable_paths if vp.lower() in path_key
            ]
            ext_matched: str | None = None
            for ext in script_exts:
                if path_key.endswith(ext):
                    ext_matched = ext
                    break

            kinds: list[str] = []
            if matched_paths:
                kinds.append("vulnerable_path")
            if ext_matched:
                kinds.append("script_download")
            if not kinds:
                continue

            pair_key = (key.src_ip, key.dst_ip)
            pairs[pair_key].add(path_key)

            pt = pair_ts[pair_key]
            pt["count"] += 1
            if key.src_port is not None:
                pt["src_ports"].add(key.src_port)
            if flow.http_host:
                pt["hosts"].add(flow.http_host)
            if flow.http_method:
                pt["methods"].add(flow.http_method)
            if flow.http_user_agent:
                pt["user_agents"].add(flow.http_user_agent)
            ts = flow.first_ts
            if ts is not None:
                if pt["first"] is None or ts < pt["first"]:
                    pt["first"] = ts
                if pt["last"] is None or ts > pt["last"]:
                    pt["last"] = ts

            for kind in kinds:
                pair_paths[pair_key][kind].append((path_key, 1))

                agg_key = (kind, path_key)
                bucket = per_uri.get(agg_key)
                if bucket is None:
                    bucket = _UriBucket(kind=kind, path_key=path_key)
                    per_uri[agg_key] = bucket

                bucket.count += 1
                bucket.src_ips[key.src_ip] += 1

                if len(bucket.dst_ips) < _EVIDENCE_SAMPLE_SIZE:
                    bucket.dst_ips.add(key.dst_ip)
                if (key.dst_port is not None
                        and len(bucket.dst_ports) < _EVIDENCE_SAMPLE_SIZE):
                    bucket.dst_ports.add(key.dst_port)
                if (flow.http_host
                        and len(bucket.hosts) < _EVIDENCE_SAMPLE_SIZE):
                    bucket.hosts.add(flow.http_host)
                if flow.http_method:
                    bucket.methods.add(flow.http_method)
                if (flow.http_user_agent
                        and len(bucket.user_agents) < _EVIDENCE_SAMPLE_SIZE):
                    bucket.user_agents.add(flow.http_user_agent)
                if len(bucket.uri_samples) < _EVIDENCE_SAMPLE_SIZE:
                    bucket.uri_samples.add(uri)

                if kind == "vulnerable_path":
                    for vp in matched_paths:
                        bucket.matched_paths.add(vp)
                else:
                    if bucket.extension is None:
                        bucket.extension = ext_matched

                bucket.touch(flow.first_ts, flow.last_ts)

        # --- Фаза 1: определяем scanner-пары ---
        scanner_pairs: set[tuple[str, str]] = set()
        for pair_key, paths in pairs.items():
            if len(paths) >= scanner_threshold:
                scanner_pairs.add(pair_key)

        # --- Фаза 2: individual findings (только для не-scanner пар) ---
        findings: list[Finding] = []
        suppressed_pairs: set[tuple[str, str]] = set()

        for (kind, path_key), bucket in per_uri.items():
            # Если для этой path_key ВСЕ src-пары — scanner, пропускаем.
            # Если хоть одна пара не scanner — оставляем individual.
            src_ips_in_bucket = set(bucket.src_ips.keys())
            dst_ips_in_bucket = bucket.dst_ips
            still_relevant = False
            for src in src_ips_in_bucket:
                for dst in dst_ips_in_bucket:
                    if (src, dst) not in scanner_pairs:
                        still_relevant = True
                        break
                if still_relevant:
                    break
            if not still_relevant:
                continue

            distinct_srcs = len(bucket.src_ips)
            evidence = {
                "path": path_key,
                "uri_samples": sorted(bucket.uri_samples),
                "count": bucket.count,
                "distinct_src_ips": distinct_srcs,
                "top_src_ips": [
                    {"ip": ip, "count": c}
                    for ip, c in bucket.src_ips.most_common(_EVIDENCE_SAMPLE_SIZE)
                ],
                "dst_ips": sorted(bucket.dst_ips),
                "dst_ports": sorted(bucket.dst_ports),
                "hosts": sorted(bucket.hosts),
                "methods": sorted(bucket.methods),
                "user_agents": sorted(bucket.user_agents),
            }

            if kind == "vulnerable_path":
                evidence["matched_paths"] = [
                    {"path": p, "description": vulnerable_paths[p]}
                    for p in sorted(bucket.matched_paths)
                ]
                confidence = _confidence_vulnerable_path(
                    bucket.count, distinct_srcs,
                )
            else:
                evidence["extension"] = bucket.extension
                confidence = _confidence_script_download(
                    bucket.count, distinct_srcs,
                )

            findings.append(Finding(
                type=kind,
                value=path_key,
                confidence=confidence,
                evidence=evidence,
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        # --- Фаза 3: web_scanner findings ---
        for pair_key in scanner_pairs:
            src_ip, dst_ip = pair_key
            pt = pair_ts[pair_key]

            kind_paths: dict[str, list[str]] = {}
            for kind, lst in pair_paths[pair_key].items():
                # уникальные path_key
                seen: dict[str, int] = {}
                for path_key, _ in lst:
                    seen[path_key] = seen.get(path_key, 0) + 1
                kind_paths[kind] = seen

            distinct_paths = len(pairs[pair_key])
            # Топ-10 путей по count
            all_paths: Counter = Counter()
            for d in kind_paths.values():
                for path_key, c in d.items():
                    all_paths[path_key] += c

            findings.append(Finding(
                type="web_scanner",
                value=f"{src_ip} -> {dst_ip}",
                confidence=0.9,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "distinct_paths": distinct_paths,
                    "total_requests": pt["count"],
                    "top_paths": [
                        {"path": p, "count": c}
                        for p, c in all_paths.most_common(20)
                    ],
                    "hosts": sorted(pt["hosts"])[:_EVIDENCE_SAMPLE_SIZE],
                    "methods": sorted(pt["methods"]),
                    "user_agents": sorted(pt["user_agents"])[:_EVIDENCE_SAMPLE_SIZE],
                    "threshold": scanner_threshold,
                },
                first_seen=pt["first"],
                last_seen=pt["last"],
            ))

        findings.sort(
            key=lambda f: (f.type, -f.evidence.get("count",
                          f.evidence.get("total_requests", 0)),
                          f.value)
        )
        return findings