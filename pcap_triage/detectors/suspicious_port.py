from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SuspiciousPortDetector:
    name = "suspicious_port"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.dst_port not in config.suspicious_ports:
                continue

            findings.append(Finding(
                type="suspicious_port",
                value=f"{key.dst_ip}:{key.dst_port}",
                confidence=0.5,
                evidence={
                    "proto": key.proto,
                    "src_ip": key.src_ip,
                    "src_port": key.src_port,
                    "dst_ip": key.dst_ip,
                    "dst_port": key.dst_port,
                    "packets": flow.packets,
                    "bytes": flow.bytes_sent,
                    "duration": round(flow.duration, 6),
                },
                first_seen=flow.first_ts,
                last_seen=flow.last_ts,
            ))

        return findings