import hashlib
from pathlib import Path

from scapy.utils import RawPcapReader

from pcap_triage import __version__
from pcap_triage.config import Config
from pcap_triage.detectors.cloud_tunnel import CloudTunnelDetector
from pcap_triage.detectors.dga import DGADetector
from pcap_triage.detectors.ip_check_service import IPCheckServiceDetector
from pcap_triage.detectors.nxdomain_burst import NXDOMAINBurstDetector
from pcap_triage.detectors.suspicious_port import SuspiciousPortDetector
from pcap_triage.detectors.typosquatting import TyposquattingDetector
from pcap_triage.extractors.dns import DNSExtractor
from pcap_triage.extractors.flow import FlowExtractor
from pcap_triage.models import CaptureState
from pcap_triage.parsers import parse_packet
from pcap_triage.reporters.flow_report import build_flow_report


# Порядок экстракторов важен: FlowExtractor ДОЛЖЕН идти первым,
# остальные L0-экстракторы независимы, но будущие L2 (TLS/HTTP/SMB)
# будут искать существующий FlowStats по FlowKey и падать, если его нет.
EXTRACTORS = [
    FlowExtractor(),
    DNSExtractor(),
]

# Порядок детекторов не важен — они независимы.
DETECTORS = [
    DGADetector(),
    SuspiciousPortDetector(),
    NXDOMAINBurstDetector(),
    CloudTunnelDetector(),
    IPCheckServiceDetector(),
    TyposquattingDetector(),
]


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _extract(pcap_path: Path, state: CaptureState) -> None:
    import sys
    import time

    file_size = pcap_path.stat().st_size
    last_update = time.monotonic()
    update_interval = 2.0
    start = last_update
    show_progress = sys.stdout.isatty()

    reader = RawPcapReader(str(pcap_path))
    try:
        for raw_data, metadata in reader:
            state.packet_count += 1
            bytes_read = reader.f.tell()

            ts = metadata.sec + metadata.usec / 1_000_000
            record = parse_packet(raw_data, ts)

            now = time.monotonic()
            if show_progress and now - last_update >= update_interval:
                pct = min(100.0, bytes_read * 100.0 / file_size) if file_size else 0.0
                elapsed = now - start
                print(
                    f"\r  {pct:5.1f}%  "
                    f"{state.packet_count:>10,} packets  "
                    f"{elapsed:6.1f}s",
                    end="",
                    flush=True,
                )
                last_update = now

            for ex in EXTRACTORS:
                try:
                    ex.process(record, state)
                except Exception:
                    state.extractor_errors[ex.name] += 1
    finally:
        reader.close()

    if show_progress:
        elapsed = time.monotonic() - start
        print(
            f"\r  done: {state.packet_count:,} packets in {elapsed:.1f}s"
            + " " * 20
        )


def _detect(state: CaptureState, config: Config):
    findings = []
    for det in DETECTORS:
        findings.extend(det.run(state, config))
    return findings


def run_pipeline(pcap_path: Path, config: Config) -> dict:
    state = CaptureState()

    _extract(pcap_path, state)
    findings = _detect(state, config)
    flow_report = build_flow_report(state, top_n=config.flow_report_top_n)

    return {
        "schema_version": "0.1.0",
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
            "extractor_errors": dict(state.extractor_errors),
        },
        "flows": flow_report,
        "findings": [f.to_dict() for f in findings],
    }