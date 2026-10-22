"""Слияние нескольких CaptureState в один.

Нужно для анализа длинных инцидентов, разбитых на несколько pcap-файлов.
Детекторы (beaconing, dga, slow scan) работают на длинном горизонте
и в одном файле не набирают статистику.
"""
from __future__ import annotations

from collections import Counter

from paradox.models import CaptureState, FlowStats


def merge_capture_states(
    states: list[CaptureState],
    filenames: list[str] | None = None,
) -> CaptureState:
    """Слить несколько CaptureState в один.

    Временные метки сохраняются как есть (предполагается, что файлы
    уже в хронологическом порядке, или это не важно для детекторов).
    """
    if not states:
        return CaptureState()

    merged = CaptureState()
    merged.first_ts = None
    merged.last_ts = None

    for st in states:
        # --- мета ---
        merged.packet_count += st.packet_count
        for k, v in st.unsupported.items():
            merged.unsupported[k] = merged.unsupported.get(k, 0) + v
        for k, v in st.extractor_errors.items():
            merged.extractor_errors[k] += v

        if st.first_ts is not None:
            if merged.first_ts is None or st.first_ts < merged.first_ts:
                merged.first_ts = st.first_ts
        if st.last_ts is not None:
            if merged.last_ts is None or st.last_ts > merged.last_ts:
                merged.last_ts = st.last_ts

        # --- DNS ---
        merged.dns_queries.update(st.dns_queries)
        merged.dns_nxdomain.update(st.dns_nxdomain)
        merged.dns_nxdomain_by_src.update(st.dns_nxdomain_by_src)

        for src, counter in st.dns_queries_by_src.items():
            if src not in merged.dns_queries_by_src:
                merged.dns_queries_by_src[src] = Counter()
            merged.dns_queries_by_src[src].update(counter)

        for name, ips in st.dns_answers_by_name.items():
            merged.dns_answers_by_name.setdefault(name, set()).update(ips)
        for ip, names in st.dns_answers_by_ip.items():
            merged.dns_answers_by_ip.setdefault(ip, set()).update(names)

        for src, ts_list in st.dns_nxdomain_ts_by_src.items():
            merged.dns_nxdomain_ts_by_src.setdefault(src, []).extend(ts_list)

        for name, ts_list in st.dns_query_ts_by_name.items():
            merged.dns_query_ts_by_name.setdefault(name, []).extend(ts_list)

        # --- Flows ---
        for key, flow in st.flows.items():
            existing = merged.flows.get(key)
            if existing is None:
                merged.flows[key] = FlowStats(
                    packets=flow.packets,
                    bytes_sent=flow.bytes_sent,
                    first_ts=flow.first_ts,
                    last_ts=flow.last_ts,
                    initiated_by_src=flow.initiated_by_src,
                    sni=flow.sni,
                    ja3=flow.ja3,
                    ja3s=flow.ja3s,
                    http_host=flow.http_host,
                    http_user_agent=flow.http_user_agent,
                    http_method=flow.http_method,
                    http_uri=flow.http_uri,
                )
            else:
                existing.packets += flow.packets
                existing.bytes_sent += flow.bytes_sent
                if flow.first_ts is not None:
                    if existing.first_ts is None or flow.first_ts < existing.first_ts:
                        existing.first_ts = flow.first_ts
                if flow.last_ts is not None:
                    if existing.last_ts is None or flow.last_ts > existing.last_ts:
                        existing.last_ts = flow.last_ts
                if existing.initiated_by_src is None:
                    existing.initiated_by_src = flow.initiated_by_src
                if existing.sni is None:
                    existing.sni = flow.sni
                if existing.ja3 is None:
                    existing.ja3 = flow.ja3
                if existing.ja3s is None:
                    existing.ja3s = flow.ja3s
                if existing.http_host is None:
                    existing.http_host = flow.http_host
                if existing.http_user_agent is None:
                    existing.http_user_agent = flow.http_user_agent
                if existing.http_method is None:
                    existing.http_method = flow.http_method
                if existing.http_uri is None:
                    existing.http_uri = flow.http_uri

        # --- Sessions ---
        for sk, sni in st.session_sni.items():
            if sk not in merged.session_sni:
                merged.session_sni[sk] = sni

        # --- Host identities ---
        for ip, ident in st.host_identities.items():
            existing = merged.host_identities.get(ip)
            if existing is None:
                merged.host_identities[ip] = ident
            else:
                if ident.mac and not existing.mac:
                    existing.mac = ident.mac
                existing.hostnames.update(ident.hostnames)
                if ident.username and not existing.username:
                    existing.username = ident.username
                if ident.realm and not existing.realm:
                    existing.realm = ident.realm

        # --- ARP ---
        for ip, macs in st.arp_macs.items():
            if ip not in merged.arp_macs:
                merged.arp_macs[ip] = {}
            for mac, entry in macs.items():
                if mac not in merged.arp_macs[ip]:
                    merged.arp_macs[ip][mac] = list(entry)
                else:
                    dst = merged.arp_macs[ip][mac]
                    dst[0] = min(dst[0], entry[0])
                    dst[1] = max(dst[1], entry[1])
                    dst[2] += entry[2]

        # --- TCP streams ---
        for key, stream in st.tcp_streams.items():
            if key not in merged.tcp_streams:
                merged.tcp_streams[key] = stream
            else:
                merged.tcp_streams[key] += stream
        merged.tcp_streams_truncated.update(st.tcp_streams_truncated)

        # --- HTTP objects / TLS certs / carved files ---
        merged.http_objects.extend(st.http_objects)
        merged.tls_certs.extend(st.tls_certs)
        merged.carved_files.extend(st.carved_files)

        # --- SSH / SMTP ---
        for k, v in st.ssh_server_versions.items():
            if k not in merged.ssh_server_versions:
                merged.ssh_server_versions[k] = v
        for ip, versions in st.ssh_client_versions.items():
            merged.ssh_client_versions.setdefault(ip, set()).update(versions)
        for k, v in st.ssh_client_attempts.items():
            merged.ssh_client_attempts[k] = merged.ssh_client_attempts.get(k, 0) + v

        merged.smtp_helo_by_src.update(st.smtp_helo_by_src)
        for ip, addrs in st.smtp_from_by_src.items():
            merged.smtp_from_by_src.setdefault(ip, set()).update(addrs)
        for ip, addrs in st.smtp_rcpt_by_src.items():
            merged.smtp_rcpt_by_src.setdefault(ip, set()).update(addrs)
        for ip, mailers in st.smtp_mailer_by_src.items():
            merged.smtp_mailer_by_src.setdefault(ip, set()).update(mailers)

    return merged
