import math
from collections import Counter

from paradox.config import Config
from paradox.models import CaptureState, Finding


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

            findings.append(Finding(
                type="dga_domain",
                value=name,
                confidence=round(confidence, 3),
                evidence={
                    "label": label,
                    "entropy": round(entropy, 3),
                    "queries": count,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))

        return findings

    def _is_allowlisted(self, name: str, config: Config) -> bool:
        from paradox.domain_utils import matches_suffix
        return matches_suffix(name, config.dga_allowlist)
