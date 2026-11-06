import math
from collections import Counter

from paradox.config import Config
from paradox.models import CaptureState, Finding, dns_sources_by_name


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class DGADetector:
    name = "dga"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        srcs_by_name = dns_sources_by_name(state)

        for name, count in state.dns_queries.items():
            if self._is_allowlisted(name, config):
                continue

            label = name.split(".")[0]

            if len(label) < config.dga_min_label_length:
                continue

            # DGA-домены почти никогда не содержат дефисов.
            # Дефис — признак человекочитаемого домена
            # (safebrowsing-cache.google.com и т.п.).
            if "-" in label:
                continue

            entropy = shannon_entropy(label)
            if entropy < config.dga_entropy_threshold:
                continue

            confidence = min(
                0.95,
                0.5 + (entropy - config.dga_entropy_threshold) / 2.0,
            )

            ts_list = state.dns_query_ts_by_name.get(name)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None

            # Атрибуция к клиенту: без src_ip finding не попадает
            # в entities. Одно имя могут спрашивать несколько хостов,
            # поэтому finding на пару (src_ip, domain).
            for src_ip in sorted(srcs_by_name.get(name, [])) or [None]:
                src_queries = (
                    state.dns_queries_by_src[src_ip][name]
                    if src_ip else count
                )
                findings.append(Finding(
                    type="dga_domain",
                    value=name,
                    confidence=round(confidence, 3),
                    src_ip=src_ip,
                    evidence={
                        "src_ip": src_ip,
                        "label": label,
                        "entropy": round(entropy, 3),
                        "queries": src_queries,
                    },
                    first_seen=first_seen,
                    last_seen=last_seen,
                ))

        return findings

    def _is_allowlisted(self, name: str, config: Config) -> bool:
        from paradox.domain_utils import matches_suffix
        return matches_suffix(name, config.dga_allowlist)
