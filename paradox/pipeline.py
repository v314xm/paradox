import hashlib
import logging
from collections.abc import Callable
from pathlib import Path

from scapy.utils import RawPcapReader

from paradox import __version__
from paradox.aggregators.entities import build_entities
from paradox.analyzers.absence import analyze_absence
from paradox.config import Config
from paradox.contradictions import run_all as run_contradictions
from paradox.detectors.beaconing import BeaconingDetector
from paradox.detectors.brute_force import BruteForceDetector
from paradox.detectors.cloud_tunnel import CloudTunnelDetector
from paradox.detectors.command_injection import CommandInjectionDetector
from paradox.detectors.dga import DGADetector
from paradox.detectors.dns_tunneling import DNSTunnelingDetector
from paradox.detectors.ftp_brute_force import FTPBruteForceDetector
from paradox.detectors.ip_check_service import IPCheckServiceDetector
from paradox.detectors.ja3_malware import JA3MalwareDetector
from paradox.detectors.large_transfer import LargeTransferDetector
from paradox.detectors.lateral_movement import LateralMovementDetector
from paradox.detectors.nxdomain_burst import NXDOMAINBurstDetector
from paradox.detectors.port_scan import PortScanDetector
from paradox.detectors.smtp_spam import SMTP_SpamDetector
from paradox.detectors.sni_mismatch import SNIMismatchDetector
from paradox.detectors.ssh_brute_force import SSHBruteForceDetector
from paradox.detectors.suspicious_port import SuspiciousPortDetector
from paradox.detectors.typosquatting import TyposquattingDetector
from paradox.detectors.vulnerable_path import VulnerablePathDetector
from paradox.detectors.yara_detector import YARADetector
from paradox.extractors.arp_history import ARPMacHistoryExtractor
from paradox.extractors.dhcp import DHCPExtractor
from paradox.extractors.dns import DNSExtractor
from paradox.extractors.flow import FlowExtractor
from paradox.extractors.host_identity import HostIdentityExtractor
from paradox.extractors.http import HTTPExtractor
from paradox.extractors.http_object import HTTPObjectExtractor
from paradox.extractors.kerberos import KerberosExtractor
from paradox.extractors.nbns import NBNSExtractor
from paradox.extractors.ndp import NDPExtractor
from paradox.extractors.smtp import SMTPExtractor
from paradox.extractors.ssh_banner import SSHBannerExtractor
from paradox.extractors.tls import TLSExtractor
from paradox.file_carve import carve_files
from paradox.models import CaptureState
from paradox.parsers import parse_packet
from paradox.reassembler import TCPReassembler
from paradox.reporters.flow_report import (
    build_dns_report,
    build_flow_report,
    build_http_object_report,
    build_http_report,
)
from paradox.timeline import build_timeline

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
    DHCPExtractor(),           # v0.9.0
    SSHBannerExtractor(),      # v0.9.0
    SMTPExtractor(),           # v0.9.0
    NBNSExtractor(),
    KerberosExtractor(),
    NDPExtractor(),
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
    SSHBruteForceDetector(),       # v0.9.0
    SMTP_SpamDetector(),           # v0.9.0
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
    CommandInjectionDetector(),
    YARADetector(),
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
            from paradox.extractors.tls_cert import (
                TlsCertificateExtractor,
            )
            TlsCertificateExtractor().run_post_extract(state, config)
        except Exception:
            state.extractor_errors["tls_cert"] += 1

        # FileCarve — метаданные payload'ов (без записи на диск по умолчанию)
        if config.file_carve_enabled:
            try:
                _carved_dir = config.output_dir / "carved"
                state.carved_files = carve_files(
                    state, config, output_dir=_carved_dir,
                )
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
    from paradox.detectors.mitre_map import get_techniques
    for f in findings:
        if not f.mitre_techniques:
            f.mitre_techniques = get_techniques(f.type)
    return findings


def _summarize_direction(state: CaptureState, config: Config) -> dict:
    """Суммы байт по направлениям: uploaded / downloaded / internal."""
    from paradox.net_utils import classify_direction

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


def _build_report(
    state: CaptureState,
    findings: list,
    config: Config,
    provenance: dict,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    """Общая часть сборки отчёта для run_pipeline и run_multi_pipeline."""
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config)
    if on_phase is not None:
        on_phase("contradictions", 1, 1)
        on_phase("report", 0, 1)

    timeline_events = build_timeline(
        findings, contradictions, carved_files=state.carved_files,
    )

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
    absence_report = analyze_absence(state)

    entities = build_entities(
        state, findings, config, contradictions=contradictions,
    )
    # v1.2: attack graph
    try:
        from paradox.analyzers.attack_graph import build_attack_graph
        _attack_graph = build_attack_graph(
            findings=findings, config=config,
            entities=entities, contradictions=contradictions,
        )
        _attack_graph_dict = _attack_graph.to_dict()
    except Exception:
        import logging
        logging.getLogger(__name__).exception(
            "build_attack_graph failed; falling back to empty graph"
        )
        _attack_graph_dict = {
            "nodes": [], "edges": [], "paths": [],
            "entry_points": [], "impact_targets": [],
            "stats": {"nodes_total": 0, "edges_total": 0, "paths_total": 0},
        }
    direction_summary = _summarize_direction(state, config)

    # v0.9.0: экспорт IOC для EDR/SIEM.
    ioc_files: dict = {}
    if getattr(config, "ioc_export_enabled", True):
        try:
            from paradox.reporters.ioc_reporter import (
                build_ioc_report,
                write_ioc_files,
            )
            ioc_report = build_ioc_report({
                "findings": [f.to_dict() for f in findings],
                "carved_files": carved_report,
                "absence": absence_report,
            })
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": getattr(state, "ndp_total", 0),
        "neighbors": [{"ip": k, "mac": v} for k, v in getattr(state, "ndp_neighbors", {}).items()],
        "routers": list(getattr(state, "ndp_routers", set())),
    }

    return {
        "schema_version": "0.3.0",
        "provenance": provenance,
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
        "ndp": ndp_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
        "attack_graph": _attack_graph_dict,
        "timeline": [e.to_dict() for e in timeline_events],
        "absence": absence_report,
        "ioc_files": ioc_files,
    }


def run_pipeline(    pcap_path: Path,
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

    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": sha256_file(pcap_path),
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)


def run_multi_pipeline(
    pcap_paths: list[Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    """Multi-pcap: прогон нескольких файлов со слиянием в один отчёт.

    Не трогает run_pipeline. Внутри:
      1. _extract для каждого файла (накапливаем CaptureState)
      2. merge_capture_states(...) — склейка
      3. _detect на объединённом state (все детекторы видят длинный горизонт)
      4. run_contradictions, build_timeline, build_*_report — как в run_pipeline
    """
    from paradox.multi_pcap import merge_capture_states

    if not pcap_paths:
        raise ValueError("pcap_paths is empty")

    # 1. Извлечение
    states = []
    total = len(pcap_paths)
    for i, p in enumerate(pcap_paths, start=1):
        st = CaptureState()
        _extract(p, st, config, should_stop=should_stop, on_progress=on_progress)
        states.append(st)
        if on_progress:
            on_progress(i, total)

    if should_stop is not None and should_stop():
        raise PipelineCancelled()

    # 2. Слияние
    state = merge_capture_states(states)

    # 3. Детекторы
    findings = _detect(state, config, should_stop=should_stop, on_phase=on_phase)

    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)
