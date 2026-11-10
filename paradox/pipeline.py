import hashlib
import logging
from collections.abc import Callable
from pathlib import Path

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
from paradox.detectors.encoded_payload import EncodedPayloadDetector
from paradox.detectors.ftp_brute_force import FTPBruteForceDetector
from paradox.detectors.http_binary_upload import HttpBinaryUploadDetector
from paradox.detectors.ip_check_service import IPCheckServiceDetector
from paradox.detectors.ja3_malware import JA3MalwareDetector
from paradox.detectors.ja3s_malware import JA3SMalwareDetector
from paradox.detectors.large_transfer import LargeTransferDetector
from paradox.detectors.lateral_movement import LateralMovementDetector
from paradox.detectors.long_connections import LongConnectionDetector
from paradox.detectors.nxdomain_burst import NXDOMAINBurstDetector
from paradox.detectors.php_payload import PhpPayloadDetector
from paradox.detectors.port_scan import PortScanDetector
from paradox.detectors.rare_external_ip import RareExternalIPDetector
from paradox.detectors.smtp_spam import SMTP_SpamDetector
from paradox.detectors.sni_mismatch import SNIMismatchDetector
from paradox.detectors.ssh_brute_force import SSHBruteForceDetector
from paradox.detectors.suspicious_port import SuspiciousPortDetector
from paradox.detectors.typosquatting import TyposquattingDetector
from paradox.detectors.vulnerable_path import VulnerablePathDetector
from paradox.detectors.webshell_markers import WebShellMarkersDetector
from paradox.detectors.yara_detector import YARADetector
from paradox.errors import ParadoxInputError
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
from paradox.pcap_reader import PcapFormatError, PcapRecordReader
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
    RareExternalIPDetector(),
    EncodedPayloadDetector(),
    JA3MalwareDetector(),
    JA3SMalwareDetector(),
    BruteForceDetector(),
    FTPBruteForceDetector(),
    BeaconingDetector(),
    LongConnectionDetector(),
    DNSTunnelingDetector(),
    SSHBruteForceDetector(),       # v0.9.0
    SMTP_SpamDetector(),           # v0.9.0
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
    CommandInjectionDetector(),
    HttpBinaryUploadDetector(),
    PhpPayloadDetector(),
    WebShellMarkersDetector(),
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
) -> str | None:
    """Разобрать pcap в state.

    Возвращает sha256 файла, если его удалось посчитать за проход
    целиком (файл прочитан до конца), иначе None — вызывающий считает
    хэш отдельно.
    """
    import sys
    import time

    if not pcap_path.is_file():
        raise ParadoxInputError(f"файл не найден: {pcap_path}")

    with pcap_path.open("rb") as probe:
        magic = probe.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        raise ParadoxInputError(
            f"{pcap_path.name}: pcapng не поддержан. "
            "Сконвертируйте в pcap: editcap -F pcap in.pcapng out.pcap"
        )

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

    try:
        hasher = PcapRecordReader(pcap_path.open("rb"))
    except Exception as exc:
        raise ParadoxInputError(
            f"{pcap_path.name}: не удалось прочитать pcap "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    reader = hasher
    try:
        for raw_data, ts in reader:
            state.packet_count += 1

            if (
                should_stop is not None
                and state.packet_count % 10_000 == 0
                and should_stop()
            ):
                raise PipelineCancelled()

            bytes_read = reader.bytes_hashed

            try:
                record = parse_packet(raw_data, ts)
            except Exception:
                state.extractor_errors["parse"] += 1
                continue

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
    except PcapFormatError as exc:
        raise ParadoxInputError(
            f"{pcap_path.name}: {exc}"
        ) from exc
    finally:
        reader.close()

    # Финализация потоков
    if reassembler is not None:
        reassembler.finalize_all()
        state.tcp_streams = reassembler.all_streams()
        state.tcp_streams_total = len(state.tcp_streams)
        state.tcp_streams_truncated = reassembler.truncated_flows()

    # Post-extract: HTTP-объекты, X.509, carve. Не зависят от флага
    # reassembly напрямую: если reassembly выключен, streams пусты и
    # экстракторы ничего не найдут. Раньше они были вложены в
    # `if reassembler is not None` и молча выпадали при выключенной
    # reassembly, хотя их собственные флаги ничего не отключали.
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

    # SNI/JA3 из склеенных потоков: ClientHello больше одного сегмента
    # потоковый экстрактор целиком не видит.
    try:
        TLSExtractor().run_post_extract(state, config)
    except Exception:
        state.extractor_errors["tls"] += 1

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

    # Сырые байты потоков больше не нужны: HTTP-объекты, сертификаты
    # и carved-файлы уже извлечены. Без очистки state держал бы
    # до 200 МБ до конца прогона.
    state.tcp_streams.clear()

    if show_progress:
        elapsed = time.monotonic() - start
        print(
            f"\r  done: {state.packet_count:,} packets in {elapsed:.1f}s"
            + " " * 20
        )

    # Хэш валиден, только если прочитан весь файл: при обрезанном
    # хвосте (trailing garbage) отдаём None, и вызывающий пересчитает.
    if hasher.bytes_hashed == file_size:
        return hasher.hexdigest()
    return None


def _detect(
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str, int, int], None] | None = None,
    detectors: list | None = None,
):
    # v1.4: детекторы — параметром, без monkey-patch глобального
    # DETECTORS (thread-safe для параллельных воркеров).
    # Каждый детектор обёрнут в try/except: один упавший не валит
    # остальные. Ошибки считаются в state.extractor_errors с префиксом
    # "detector:<name>" — их видно в summary отчёта.
    active = list(detectors) if detectors is not None else list(DETECTORS)

    # Пользовательские детекторы из ~/.paradox/plugins (если включены).
    # Ошибки загрузки считаются в summary, но пайплайн не валят.
    from paradox.detector_plugins import load_detector_plugins

    plugin_result = load_detector_plugins(
        config, reserved_names={d.name for d in active},
    )
    if plugin_result.detectors:
        active.extend(plugin_result.detectors)
    if plugin_result.errors:
        state.extractor_errors["plugin"] += len(plugin_result.errors)

    findings = []
    total = len(active)
    for i, det in enumerate(active):
        if should_stop is not None and should_stop():
            raise PipelineCancelled()
        if on_phase is not None:
            on_phase("detect", i, total, det.name)
        try:
            findings.extend(det.run(state, config))
        except Exception:
            key = f"detector:{det.name}"
            prev = state.extractor_errors[key]
            state.extractor_errors[key] = prev + 1
            if getattr(config, "debug_log_extractor_errors", False) and prev == 0:
                import logging
                logging.exception(
                    "detector %s failed (first occurrence)", det.name,
                )
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


# Порт → прикладной протокол. Нужен только для summary-разреза;
# для детекции протокол определяется экстракторами, а не портом.
_L7_BY_PORT: dict[int, str] = {
    53: "dns", 5353: "mdns", 5355: "llmnr",
    80: "http", 8000: "http", 8080: "http", 3128: "http", 8888: "http",
    443: "tls", 465: "tls", 636: "tls", 993: "tls", 995: "tls",
    8443: "tls",
    137: "nbns", 138: "netbios", 139: "smb", 445: "smb",
    22: "ssh",
    25: "smtp", 587: "smtp",
    88: "kerberos",
    123: "ntp",
    389: "ldap",
    67: "dhcp", 68: "dhcp",
    1900: "ssdp",
}


def _classify_l7(key, flow) -> str:
    """Прикладной протокол flow по фактам экстракторов, затем по порту."""
    if key.proto in ("icmp", "icmpv6"):
        return "icmp"
    if flow.sni or flow.ja3 or flow.ja3s:
        return "tls"
    if flow.http_host or flow.http_uri or flow.http_method:
        return "http"
    for port in (key.dst_port, key.src_port):
        if port in _L7_BY_PORT:
            return _L7_BY_PORT[port]
    return "other"


def _summarize_protocols(state: CaptureState, config: Config) -> dict:
    """Разрез по L4/L7 в количестве flows; для summary отчёта."""
    from collections import Counter

    l4: Counter = Counter()
    l7: Counter = Counter()
    for key, flow in state.flows.items():
        l4[key.proto] += 1
        l7[_classify_l7(key, flow)] += 1

    return {
        "by_l4": dict(sorted(l4.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_l7": dict(sorted(l7.items(), key=lambda kv: (-kv[1], kv[0]))),
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
    rules: list | None = None,
) -> dict:
    """Общая часть сборки отчёта для run_pipeline и run_multi_pipeline.

    rules — опциональный список правил contradictions (default —
    глобальный RULES). Позволяет GUI отключать правила без monkey-patch.
    """
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config, rules=rules)
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
    absence_report = analyze_absence(state, top_n=config.absence_top_n)

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
    protocol_summary = _summarize_protocols(state, config)

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
            }, config)
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": state.ndp_total,
        "neighbors": [{"ip": k, "mac": v} for k, v in state.ndp_neighbors.items()],
        "routers": list(state.ndp_routers),
    }

    cert_limit = config.flow_report_top_n
    certificates_report = {
        "total": len(state.tls_certs),
        "parse_errors": state.tls_cert_parse_errors,
        "truncated": len(state.tls_certs) > cert_limit,
        "items": [
            {
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "self_signed": cert.is_self_signed,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "san_dns": list(cert.san_dns),
                "san_ips": list(cert.san_ips),
            }
            for key, cert in state.tls_certs[:cert_limit]
        ],
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
            "tcp_streams": state.tcp_streams_total or len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            "certificates": len(state.tls_certs),
            "tls_cert_parse_errors": state.tls_cert_parse_errors,
            **direction_summary,
            "protocols": protocol_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "ndp": ndp_report,
        "certificates": certificates_report,
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


def run_pipeline(
    pcap_path: str | Path,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
) -> dict:
    pcap_path = Path(pcap_path)
    state = CaptureState()

    pcap_sha256 = _extract(
        pcap_path, state, config,
        should_stop=should_stop,
        on_progress=on_progress,
    )
    findings = _detect(
        state, config,
        should_stop=should_stop,
        on_phase=on_phase,
        detectors=detectors,
    )

    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": pcap_sha256 or sha256_file(pcap_path),
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )


def run_multi_pipeline(
    pcap_paths: list[str | Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
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

    pcap_paths = [Path(p) for p in pcap_paths]

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
    findings = _detect(
        state, config,
        should_stop=should_stop, on_phase=on_phase,
        detectors=detectors,
    )

    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )
