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

        # Атрибуция к клиенту: без src_ip finding не попадает ни в
        # entities, ни в victim_of — роль victim_candidate не
        # выставляется. Одно имя могут запрашивать несколько хостов,
        # поэтому finding на пару (src_ip, domain).
        srcs_by_name: dict[str, list[str]] = {}
        for src_ip, bucket in state.dns_queries_by_src.items():
            for name in bucket:
                srcs_by_name.setdefault(name, []).append(src_ip)

        for name, count in state.dns_queries.items():
            match = self._match_tunnel(name, config)
            if match is None:
                continue

            ts_list = state.dns_query_ts_by_name.get(name)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None

            # Нет dns_queries_by_src (например, state собран вручную) —
            # отдаём finding без src, как раньше.
            for src_ip in sorted(srcs_by_name.get(name, [])) or [None]:
                findings.append(Finding(
                    type="cloud_tunnel_domain",
                    value=name,
                    confidence=0.7,
                    src_ip=src_ip,
                    evidence={
                        "src_ip": src_ip,
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
