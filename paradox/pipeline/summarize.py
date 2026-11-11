"""Срезы отчёта: направления байт, L4/L7, MITRE."""
from __future__ import annotations

from paradox.config import Config
from paradox.models import CaptureState


def _summarize_direction(state: CaptureState, config: Config) -> dict:
    """Суммы байт по направлениям: uploaded / downloaded / internal."""
    from paradox.net_utils import classify_direction

    uploaded = 0     # internal → external
    downloaded = 0   # external → internal
    internal = 0     # internal → internal
    external = 0     # external → external

    for key, flow in state.flows.items():
        direction = classify_direction(key.src_ip, key.dst_ip, config)
        if direction == "outbound":
            uploaded += flow.bytes_sent
        elif direction == "inbound":
            downloaded += flow.bytes_sent
        elif direction == "internal":
            internal += flow.bytes_sent
        else:
            external += flow.bytes_sent

    return {
        "uploaded_bytes": uploaded,
        "downloaded_bytes": downloaded,
        "internal_bytes": internal,
        "external_bytes": external,
    }


# Порт → прикладной протокол. Нужен только для summary-разреза;
# для детекции протокол определяется экстракторами, а не портом.
_L7_BY_PORT: dict[int, str] = {
    53: "dns", 5353: "mdns", 5355: "llmnr",
    80: "http", 8000: "http", 8080: "http", 3128: "http", 8888: "http",
    443: "tls", 465: "tls", 636: "tls", 993: "tls", 995: "tls",
    8443: "tls",
    137: "nbns", 138: "netbios", 139: "smb", 445: "smb",
    22: "ssh",
    25: "smtp", 587: "smtp",
    88: "kerberos",
    123: "ntp",
    389: "ldap",
    67: "dhcp", 68: "dhcp",
    1900: "ssdp",
}


def _classify_l7(key, flow) -> str:
    """Прикладной протокол flow по фактам экстракторов, затем по порту."""
    if key.proto in ("icmp", "icmpv6"):
        return "icmp"
    if flow.sni or flow.ja3 or flow.ja3s:
        return "tls"
    if flow.http_host or flow.http_uri or flow.http_method:
        return "http"
    for port in (key.dst_port, key.src_port):
        if port in _L7_BY_PORT:
            return _L7_BY_PORT[port]
    return "other"


def _summarize_protocols(state: CaptureState, config: Config) -> dict:
    """Разрез по L4/L7 в количестве flows; для summary отчёта."""
    from collections import Counter

    l4: Counter = Counter()
    l7: Counter = Counter()
    for key, flow in state.flows.items():
        l4[key.proto] += 1
        l7[_classify_l7(key, flow)] += 1

    return {
        "by_l4": dict(sorted(l4.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_l7": dict(sorted(l7.items(), key=lambda kv: (-kv[1], kv[0]))),
    }

def _summarize_mitre(findings) -> dict:
    from collections import Counter
    counter = Counter()
    for f in findings:
        for t in f.mitre_techniques:
            counter[t] += 1
    return {
        "total_techniques": len(counter),
        "by_technique": [
            {"technique": t, "count": c}
            for t, c in counter.most_common()
        ],
    }
