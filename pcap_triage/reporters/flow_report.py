from collections import Counter

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, FlowKey, FlowStats, get_session_sni
from pcap_triage.net_utils import classify_direction


def _flow_to_dict(
    key: FlowKey,
    flow: FlowStats,
    state: CaptureState,
    config: Config,
) -> dict:
    d = {
        "proto": key.proto,
        "src_ip": key.src_ip,
        "src_port": key.src_port,
        "dst_ip": key.dst_ip,
        "dst_port": key.dst_port,
        "direction": classify_direction(key.src_ip, key.dst_ip, config),
        "packets": flow.packets,
        "bytes": flow.bytes_sent,
        "duration": round(flow.duration, 6),
        "first_ts": flow.first_ts,
        "last_ts": flow.last_ts,
    }

    sni = get_session_sni(key, flow, state)
    if sni:
        d["sni"] = sni
    if flow.ja3:
        d["ja3"] = flow.ja3
    if flow.http_host:
        d["http_host"] = flow.http_host
    if flow.http_user_agent:
        d["http_user_agent"] = flow.http_user_agent
    return d


def _sort_key_bytes(f: dict) -> tuple:
    return (
        -f["bytes"],
        f["src_ip"],
        f["src_port"] or 0,
        f["dst_ip"],
        f["dst_port"] or 0,
        f["proto"],
    )


def _sort_key_packets(f: dict) -> tuple:
    return (
        -f["packets"],
        f["src_ip"],
        f["src_port"] or 0,
        f["dst_ip"],
        f["dst_port"] or 0,
        f["proto"],
    )


def build_flow_report(
    state: CaptureState,
    config: Config,
    top_n: int = 100,
) -> dict:
    all_flows = [
        _flow_to_dict(k, v, state, config)
        for k, v in state.flows.items()
    ]

    by_bytes = sorted(all_flows, key=_sort_key_bytes)[:top_n]
    by_packets = sorted(all_flows, key=_sort_key_packets)[:top_n]

    return {
        "total_flows": len(all_flows),
        "top_by_bytes": by_bytes,
        "top_by_packets": by_packets,
    }


def build_dns_report(
    state: CaptureState,
    top_n: int = 100,
) -> dict:
    """
    DNS-секция отчёта.

    Возвращает полный список уникальных запросов + топ по частоте.
    Плюс NXDOMAIN отдельно.
    """
    all_queries = [
        {"name": name, "count": count}
        for name, count in state.dns_queries.items()
    ]

    by_count = sorted(
        all_queries,
        key=lambda d: (-d["count"], d["name"]),
    )[:top_n]

    nxdomain = [
        {"name": name, "count": count}
        for name, count in state.dns_nxdomain.items()
    ]
    nxdomain.sort(key=lambda d: (-d["count"], d["name"]))

    return {
        "unique_count": len(state.dns_queries),
        "total_queries": sum(state.dns_queries.values()),
        "top_by_count": by_count,
        "nxdomain": nxdomain,
    }


def build_http_report(
    state: CaptureState,
    top_n: int = 50,
) -> dict:
    """
    HTTP-секция отчёта.

    Собирает top hosts, top user-agents, top URIs и unique counts
    из http_*-полей в FlowStats.
    """
    hosts: Counter = Counter()
    user_agents: Counter = Counter()
    methods: Counter = Counter()
    uris: list[dict] = []

    for key, flow in state.flows.items():
        if flow.http_host:
            hosts[flow.http_host] += 1
        if flow.http_user_agent:
            user_agents[flow.http_user_agent] += 1
        if flow.http_method:
            methods[flow.http_method] += 1
        if flow.http_uri and flow.http_host:
            uris.append({
                "method": flow.http_method,
                "host": flow.http_host,
                "uri": flow.http_uri,
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "bytes": flow.bytes_sent,
                "user_agent": flow.http_user_agent,
            })

    # Уникальные URI: сортируем по bytes убыв., берём top_n
    # Дедуплицируем по (host, uri) — оставляем первый
    seen: set[tuple[str, str]] = set()
    unique_uris: list[dict] = []
    for u in sorted(uris, key=lambda x: -x["bytes"]):
        k = (u["host"], u["uri"])
        if k in seen:
            continue
        seen.add(k)
        unique_uris.append(u)
        if len(unique_uris) >= top_n:
            break

    return {
        "unique_hosts": len(hosts),
        "unique_user_agents": len(user_agents),
        "unique_uris": len(seen),
        "top_hosts": [
            {"host": h, "count": c}
            for h, c in sorted(hosts.items(),
                                 key=lambda kv: (-kv[1], kv[0]))[:top_n]
        ],
        "top_user_agents": [
            {"user_agent": ua, "count": c}
            for ua, c in sorted(user_agents.items(),
                                  key=lambda kv: (-kv[1], kv[0]))[:top_n]
        ],
        "methods": [
            {"method": m, "count": c}
            for m, c in sorted(methods.items(),
                                 key=lambda kv: (-kv[1], kv[0]))
        ],
        "top_uris": unique_uris,
    }


def build_http_object_report(
    state: CaptureState,
    top_n: int = 100,
) -> dict:
    """
    Отчёт по HTTP-объектам, извлечённым из склеенных TCP-потоков
    (HTTPObjectExtractor). Каждый объект — (FlowKey, HttpObject).

    Top_n по размеру body. Body-превью — hex первых 64 байт.
    """
    objs = list(state.http_objects or [])

    # Сортировка по body_size (крупные сверху), затем по uri/method
    objs.sort(
        key=lambda pair: (-pair[1].body_size, str(pair[1].uri or "")),
    )
    objs = objs[:top_n]

    out: list[dict] = []
    for key, obj in objs:
        headers = obj.headers or {}
        d = {
            "src_ip": key.src_ip,
            "dst_ip": key.dst_ip,
            "src_port": key.src_port,
            "dst_port": key.dst_port,
            "kind": obj.kind,
            "method": obj.method,
            "uri": obj.uri,
            "status_code": obj.status_code,
            "host": headers.get("host"),
            "user_agent": headers.get("user-agent"),
            "content_type": headers.get("content-type"),
            "body_size": obj.body_size,
            "truncated": obj.truncated,
        }
        if obj.body:
            # Первые 64 байта body — hex. Для бинарных достаточно,
            # для текстовых можно декодировать отдельно.
            d["body_preview"] = obj.body[:64].hex()
        out.append(d)

    return {
        "total": len(state.http_objects or []),
        "objects": out,
    }
