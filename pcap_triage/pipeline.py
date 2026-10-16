import hashlib
import logging
from pathlib import Path
from typing import Callable

from scapy.utils import RawPcapReader

from pcap_triage import __version__
from pcap_triage.aggregators.entities import build_entities
from pcap_triage.config import Config
from pcap_triage.contradictions import run_all as run_contradictions
from pcap_triage.detectors.cloud_tunnel import CloudTunnelDetector
from pcap_triage.detectors.dga import DGADetector
from pcap_triage.detectors.ip_check_service import IPCheckServiceDetector
from pcap_triage.detectors.nxdomain_burst import NXDOMAINBurstDetector
from pcap_triage.detectors.sni_mismatch import SNIMismatchDetector
from pcap_triage.detectors.ja3_malware import JA3MalwareDetector
from pcap_triage.detectors.port_scan import PortScanDetector
from pcap_triage.detectors.suspicious_port import SuspiciousPortDetector
from pcap_triage.detectors.typosquatting import TyposquattingDetector
from pcap_triage.extractors.dns import DNSExtractor
from pcap_triage.extractors.flow import FlowExtractor
from pcap_triage.extractors.tls import TLSExtractor
from pcap_triage.extractors.arp_history import ARPMacHistoryExtractor
from pcap_triage.models import CaptureState
from pcap_triage.parsers import parse_packet
from pcap_triage.reassembler import TCPReassembler
from pcap_triage.timeline import build_timeline
from pcap_triage.file_carve import carve_files
from pcap_triage.reporters.flow_report import (
    build_dns_report,
    build_flow_report,
    build_http_object_report,
    build_http_report,
)
from pcap_triage.detectors.brute_force import BruteForceDetector
from pcap_triage.extractors.http import HTTPExtractor
from pcap_triage.extractors.http_object import HTTPObjectExtractor
from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector
from pcap_triage.extractors.host_identity import HostIdentityExtractor
from pcap_triage.extractors.nbns import NBNSExtractor
from pcap_triage.extractors.kerberos import KerberosExtractor
from pcap_triage.detectors.lateral_movement import LateralMovementDetector
from pcap_triage.detectors.large_transfer import LargeTransferDetector
from pcap_triage.detectors.ftp_brute_force import FTPBruteForceDetector
from pcap_triage.detectors.command_injection import CommandInjectionDetector
from pcap_triage.detectors.beaconing import BeaconingDetector
from pcap_triage.detectors.dns_tunneling import DNSTunnelingDetector


# Порядок экстракторов важен: FlowExtractor ДОЛЖЕН идти первым,
# остальные экстракторы, пишущие в FlowStats, ищут существующий flow.
#
# Контракт: экстракторы STATELESS. Работают только через параметры
# (record, state). Между прогонами run_pipeline в одном процессе
# (важно для GUI) внутреннего мусора не остаётся.
#
# Если добавляешь stateful экстрактор (буфер, кэш, счётчик в self) —
# замени список на фабрику build_extractors() и вызывай её в _extract().
EXTRACTORS = [
    FlowExtractor(),
    DNSExtractor(),
    TLSExtractor(),
    HTTPExtractor(),
    HostIdentityExtractor(),
    ARPMacHistoryExtractor(),
    NBNSExtractor(),
    KerberosExtractor(),
]

# Порядок детекторов не важен — они независимы.
DETECTORS = [
    DGADetector(),
    PortScanDetector(),
    SuspiciousPortDetector(),
    NXDOMAINBurstDetector(),
    CloudTunnelDetector(),
    IPCheckServiceDetector(),
    TyposquattingDetector(),
    SNIMismatchDetector(),
    JA3MalwareDetector(),
    BruteForceDetector(),
    FTPBruteForceDetector(),
    BeaconingDetector(),
    DNSTunnelingDetector(),
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
    CommandInjectionDetector(),
]


class PipelineCancelled(Exception):
    """Raised when cooperative cancellation was requested mid-run."""


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _extract(
    pcap_path: Path,
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> None:
    import sys
    import time

    file_size = pcap_path.stat().st_size
    last_update = time.monotonic()
    update_interval = 2.0
    start = last_update
    show_progress = sys.stdout.isatty()

    # TCP reassembly — опционально
    reassembler: TCPReassembler | None = None
    if config.tcp_reassembly_enabled:
        reassembler = TCPReassembler(
            max_bytes_per_flow=config.tcp_reassembly_max_bytes_per_flow,
            max_total_bytes=config.tcp_reassembly_max_total_bytes,
        )

    reader = RawPcapReader(str(pcap_path))
    try:
        for raw_data, metadata in reader:
            state.packet_count += 1

            if (
                should_stop is not None
                and state.packet_count % 10_000 == 0
                and should_stop()
            ):
                raise PipelineCancelled()

            bytes_read = reader.f.tell()

            ts = metadata.sec + metadata.usec / 1_000_000
            record = parse_packet(raw_data, ts)

            # Reassembly до экстракторов
            if reassembler is not None:
                reassembler.feed(record)

            now = time.monotonic()
            if now - last_update >= update_interval:
                if show_progress:
                    pct = (
                        min(100.0, bytes_read * 100.0 / file_size)
                        if file_size else 0.0
                    )
                    elapsed = now - start
                    print(
                        f"\r  {pct:5.1f}%  "
                        f"{state.packet_count:>10,} packets  "
                        f"{elapsed:6.1f}s",
                        end="",
                        flush=True,
                    )
                if on_progress is not None:
                    on_progress(bytes_read, file_size)
                last_update = now

            for ex in EXTRACTORS:
                try:
                    ex.process(record, state)
                except Exception:
                    prev = state.extractor_errors[ex.name]
                    state.extractor_errors[ex.name] = prev + 1
                    if config.debug_log_extractor_errors and prev == 0:
                        logging.exception(
                            "extractor %s failed (first occurrence)",
                            ex.name,
                        )
    finally:
        reader.close()

    # Финализация потоков + HTTP-объекты
    if reassembler is not None:
        reassembler.finalize_all()
        state.tcp_streams = reassembler.all_streams()
        state.tcp_streams_truncated = reassembler.truncated_flows()

        try:
            HTTPObjectExtractor().run_post_extract(state, config)
        except Exception:
            state.extractor_errors["http_object"] += 1

        # X.509 сертификаты из TLS-хендшейков. Требуют reassembly,
        # потому что сертификат часто больше одного TCP-сегмента.
        try:
            from pcap_triage.extractors.tls_cert import (
                TlsCertificateExtractor,
            )
            TlsCertificateExtractor().run_post_extract(state, config)
        except Exception:
            state.extractor_errors["tls_cert"] += 1

        # FileCarve — метаданные payload'ов (без записи на диск по умолчанию)
        if config.file_carve_enabled:
            try:
                state.carved_files = carve_files(state, config, output_dir=None)
            except Exception:
                state.extractor_errors["file_carve"] += 1

    if on_progress is not None:
        on_progress(file_size, file_size)

    if show_progress:
        elapsed = time.monotonic() - start
        print(
            f"\r  done: {state.packet_count:,} packets in {elapsed:.1f}s"
            + " " * 20
        )


_SEVERITY_BY_TYPE: dict[str, str] = {
    # v0.8.0: временный маппинг тип finding → severity.
    #
    # Уйдёт в v0.9, когда детекторы начнут задавать severity сами.
    # Пока — мост: заполняем через _normalize_finding.
    #
    # Принцип деления:
    #   high   — активная атака / установленный malware-признак
    #   medium — подозрительный паттерн, требует валидации
    #   low    — шум / контекстная информация
    #
    # Типы вне этого словаря остаются на дефолтной "medium".
    # Если добавляешь детектор — реши, нужна ли ему строка здесь,
    # или пусть падает в default.
    "command_injection": "high",
    "brute_force": "high",
    "ftp_brute_force": "high",
    "lateral_movement": "high",
    "ja3_malware": "high",
    "script_download": "high",

    "port_scan": "medium",
    "web_scanner": "medium",
    "vulnerable_path": "medium",
    "beaconing": "medium",
    "dns_tunneling": "medium",
    "suspicious_port": "medium",
    "cloud_tunnel": "medium",
    "sni_mismatch": "medium",
    "dga_domain": "medium",
    "large_transfer": "medium",
    "carved_file": "medium",

    "nxdomain_burst": "low",
    "typosquatting": "low",
    "ip_check_service": "low",
}


def _first_from_list(v):
    """
    Первый элемент списка/кортежа или None.

    v0.8.0: используется для агрегированных evidence-ключей:
      dst_ips:   ["10.0.1.152"]
      dst_ports: [80]
    """
    if isinstance(v, (list, tuple)) and v:
        return v[0]
    return None


def _first_ip_from_aggregated(v):
    """
    Первый IP из агрегированного списка.

    v0.8.0: vulnerable_path / script_download кладут источник в виде
    top_src_ips: [{"ip": "192.168.1.12", "count": 1}, ...]
    Первый элемент — самый значимый (детектор сортирует по count).

    Толерантно к строкам: если прилетит ["1.2.3.4"], тоже подойдёт.
    """
    if isinstance(v, (list, tuple)) and v:
        first = v[0]
        if isinstance(first, dict):
            return first.get("ip")
        if isinstance(first, str):
            return first
    return None


def _normalize_finding(f) -> None:
    """
    v0.8.0: поднять top-level поля Finding из evidence.

    Существующие детекторы пишут src_ip / dst_ip / dst_port только в
    evidence. Этот шаг вытаскивает их наверх, чтобы потребители
    (contradictions/facts, aggregators/entities, reporters) могли
    читать единообразно.

    Два формата evidence:
      1. Одиночный — src_ip / dst_ip / dst_port (большинство детекторов).
      2. Агрегированный — top_src_ips / dst_ips / dst_ports (vulnerable_path,
         script_download). Один finding сворачивает несколько flow,
         поля — списки.

    Приоритет: одиночные ключи → агрегированные. Первый элемент
    агрегированного списка — самый значимый (детектор сортирует по
    count / байтам).

    Правила:
      - src_ip / dst_ip / dst_port: только если None. Пустая строка
        "" не перетирается — детектор мог сознательно её поставить.
      - severity: только если осталось дефолтное "medium" и тип в
        _SEVERITY_BY_TYPE. Как только детектор начнёт задавать
        severity сам — эта ветка не сработает, и её можно удалить
        вместе со словарём.

    НЕ трогаем first_seen / last_seen: они уже top-level с v0.7.0,
    если детектор их не заполнил — это отдельный долг, не здесь.
    """
    ev = f.evidence or {}
    if f.src_ip is None:
        f.src_ip = (
            ev.get("src_ip")
            or _first_ip_from_aggregated(ev.get("top_src_ips"))
        )
    if f.dst_ip is None:
        f.dst_ip = ev.get("dst_ip") or _first_from_list(ev.get("dst_ips"))
    if f.dst_port is None:
        f.dst_port = (
            ev.get("dst_port") or _first_from_list(ev.get("dst_ports"))
        )
    if f.severity == "medium" and f.type in _SEVERITY_BY_TYPE:
        f.severity = _SEVERITY_BY_TYPE[f.type]


def _detect(
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str, int, int], None] | None = None,
):
    findings = []
    total = len(DETECTORS)
    for i, det in enumerate(DETECTORS):
        if should_stop is not None and should_stop():
            raise PipelineCancelled()
        if on_phase is not None:
            on_phase("detect", i, total, det.name)
        findings.extend(det.run(state, config))
        if on_phase is not None:
            on_phase("detect", i + 1, total, det.name)

    # Обогащение MITRE-техниками. Instance-level (detector заполнил сам —
    # например large_transfer с direction) приоритетнее type-map.
    from pcap_triage.detectors.mitre_map import get_techniques
    for f in findings:
        if not f.mitre_techniques:
            f.mitre_techniques = get_techniques(f.type)

    # v0.8.0: normalize finding — вытаскиваем src_ip / dst_ip / dst_port /
    # severity из evidence наверх. Делается ПОСЛЕ MITRE и ДО возврата
    # findings, чтобы run_contradictions и build_entities в run_pipeline
    # видели уже нормализованный контракт.
    for f in findings:
        _normalize_finding(f)

    return findings


def _summarize_direction(state: CaptureState, config: Config) -> dict:
    """Суммы байт по направлениям: uploaded / downloaded / internal."""
    from pcap_triage.net_utils import classify_direction

    uploaded = 0     # internal → external
    downloaded = 0   # external → internal
    internal = 0     # internal → internal
    external = 0     # external → external

    for key, flow in state.flows.items():
        direction = classify_direction(key.src_ip, key.dst_ip, config)
        if direction == "outbound":
            uploaded += flow.bytes_sent
        elif direction == "inbound":
            downloaded += flow.bytes_sent
        elif direction == "internal":
            internal += flow.bytes_sent
        else:
            external += flow.bytes_sent

    return {
        "uploaded_bytes": uploaded,
        "downloaded_bytes": downloaded,
        "internal_bytes": internal,
        "external_bytes": external,
    }

def _summarize_mitre(findings) -> dict:
    from collections import Counter
    counter = Counter()
    for f in findings:
        for t in f.mitre_techniques:
            counter[t] += 1
    return {
        "total_techniques": len(counter),
        "by_technique": [
            {"technique": t, "count": c}
            for t, c in counter.most_common()
        ],
    }


def run_pipeline(
    pcap_path: Path,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    state = CaptureState()

    _extract(
        pcap_path, state, config,
        should_stop=should_stop,
        on_progress=on_progress,
    )
    findings = _detect(
        state, config,
        should_stop=should_stop,
        on_phase=on_phase,
    )

    # Contradictions — между detectors и build_entities.
    # После detectors: используют findings. До entities: влияют на роли (pivot).
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config)
    if on_phase is not None:
        on_phase("contradictions", 1, 1)
        on_phase("report", 0, 1)

    # v0.8.0: timeline / kill-chain reconstruction.
    # Собираем события из findings + contradictions, сортируем по ts,
    # группируем по фазам kill-chain (группировка — на стороне reporters).
    # Делается ДО reporters: они читают готовый список.
    timeline_events = build_timeline(findings, contradictions)

    flow_report = build_flow_report(state, config, top_n=config.flow_report_top_n)
    dns_report = build_dns_report(state, top_n=config.flow_report_top_n)
    http_report = build_http_report(state, top_n=config.flow_report_top_n)
    http_objects_report = build_http_object_report(
        state, top_n=config.flow_report_top_n,
    )
    carved_report = {
        "total": len(state.carved_files),
        "files": [c.to_dict() for c in state.carved_files],
        "mitre": _summarize_mitre(findings),
    }
    entities = build_entities(
        state, findings, config, contradictions=contradictions,
    )
    direction_summary = _summarize_direction(state, config)

    if on_phase is not None:
        on_phase("report", 1, 1)

    return {
        # 0.3.0: добавлен top-level ключ "contradictions".
        "schema_version": "0.3.0",
        "provenance": {
            "tool_version": __version__,
            "pcap_path": str(pcap_path),
            "pcap_sha256": sha256_file(pcap_path),
        },
        "summary": {
            "packets": state.packet_count,
            "unique_dns_queries": len(state.dns_queries),
            "nxdomain_count": sum(state.dns_nxdomain.values()),
            "flows": len(state.flows),
            "findings": len(findings),
            "contradictions": len(contradictions),
            "extractor_errors": dict(state.extractor_errors),
            "tcp_streams": len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            **direction_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
        # v0.8.0: timeline / kill-chain reconstruction.
        # Плоский список TimelineEvent, отсортированный по ts.
        "timeline": [e.to_dict() for e in timeline_events],
    }