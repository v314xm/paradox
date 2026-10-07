from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class CloudTunnelDetector:
    """
    Домены на сервисах, которые часто используются для скрытия C2:
    trycloudflare, ngrok, serveo, localtunnel и т.п.
    """
    name = "cloud_tunnel"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for name, count in state.dns_queries.items():
            match = self._match_tunnel(name, config)
            if match is None:
                continue

            findings.append(Finding(
                type="cloud_tunnel_domain",
                value=name,
                confidence=0.7,
                evidence={
                    "matched_suffix": match,
                    "queries": count,
                },
            ))

        return findings

    def _match_tunnel(self, name: str, config: Config) -> str | None:
        for suffix in config.cloud_tunnel_domains:
            if name == suffix or name.endswith("." + suffix):
                return suffix
        return None