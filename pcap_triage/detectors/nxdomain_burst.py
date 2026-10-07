from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class NXDOMAINBurstDetector:
    """
    Один хост получил >= N NXDOMAIN за время захвата.

    TODO: пока считаем за весь файл. Когда появится windowing —
    порог должен быть «N за окно», иначе на длинных захватах
    легитимные опечатки пользователя будут ложно срабатывать.
    """
    name = "nxdomain_burst"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for src_ip, count in state.dns_nxdomain_by_src.items():
            if count < config.nxdomain_burst_threshold:
                continue

            confidence = min(0.9, 0.4 + count * 0.05)

            findings.append(Finding(
                type="nxdomain_burst",
                value=src_ip,
                confidence=round(confidence, 3),
                evidence={
                    "src_ip": src_ip,
                    "nxdomain_count": count,
                    "threshold": config.nxdomain_burst_threshold,
                },
            ))

        return findings