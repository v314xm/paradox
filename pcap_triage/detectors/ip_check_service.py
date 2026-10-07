from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class IPCheckServiceDetector:
    """
    Обращения к сервисам вроде ip-api.com / ifconfig.me — типичный
    шаг малвари перед установкой C2 (узнать свой внешний IP).
    """
    name = "ip_check_service"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for name, count in state.dns_queries.items():
            if name not in config.ip_check_services:
                continue

            findings.append(Finding(
                type="ip_check_service",
                value=name,
                confidence=0.5,
                evidence={"queries": count},
            ))

        return findings