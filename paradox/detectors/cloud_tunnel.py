from paradox.config import Config
from paradox.models import CaptureState, Finding


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

            ts_list = state.dns_query_ts_by_name.get(name)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None

            findings.append(Finding(
                type="cloud_tunnel_domain",
                value=name,
                confidence=0.7,
                evidence={
                    "matched_suffix": match,
                    "queries": count,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))

        return findings

    def _match_tunnel(self, name: str, config: Config) -> str | None:
        for suffix in config.cloud_tunnel_domains:
            if name == suffix or name.endswith("." + suffix):
                return suffix
        return None
