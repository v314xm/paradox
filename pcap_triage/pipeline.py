import hashlib
from pathlib import Path

from scapy.all import PcapReader

from pcap_triage import __version__
from pcap_triage.config import Config
from pcap_triage.detectors.cloud_tunnel import CloudTunnelDetector
from pcap_triage.detectors.dga import DGADetector
from pcap_triage.detectors.ip_check_service import IPCheckServiceDetector
from pcap_triage.detectors.nxdomain_burst import NXDOMAINBurstDetector
from pcap_triage.detectors.suspicious_port import SuspiciousPortDetector
from pcap_triage.extractors.dns import DNSExtractor
from pcap_triage.extractors.flow import FlowExtractor
from pcap_triage.models import CaptureState
from pcap_triage.reporters.flow_report import build_flow_report
from pcap_triage.detectors.typosquatting import TyposquattingDetector

# Порядок экстракторов важен: FlowExtractor ДОЛЖЕН идти первым,
# остальные L0-экстракторы независимы, но будущие L2 (TLS/HTTP/SMB)
# будут искать существующий FlowStats по FlowKey и падать, если его нет.
EXTRACTORS = [
    FlowExtractor(),
    DNSExtractor(),
]

# Порядок детекторов не важен — они независимы.
# Группировка по семьям для читаемости:
#   сигнатуры по DNS  : dga, cloud_tunnel, ip_check_service, nxdomain_burst
#   сигнатуры по flow : suspicious_port
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
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            state.packet_count += 1
            for ex in EXTRACTORS:
                try:
                    ex.process(pkt, state)
                except Exception:
                    state.extractor_errors[ex.name] += 1


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