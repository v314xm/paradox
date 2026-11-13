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

        for src, ts_list in st.dns_query_ts_by_src.items():
            merged.dns_query_ts_by_src.setdefault(src, []).extend(ts_list)

        # --- Flows ---
        for key, flow in st.flows.items():
            existing = merged.flows.get(key)
            if existing is None:
                merged.flows[key] = FlowStats(
                    packets=flow.packets,
                    bytes_sent=flow.bytes_sent,
                    first_ts=flow.first_ts,
                    last_ts=flow.last_ts,
                    bytes_sumsq=flow.bytes_sumsq,
                    gap_sum=flow.gap_sum,
                    gap_sumsq=flow.gap_sumsq,
                    gap_count=flow.gap_count,
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
                existing.bytes_sumsq += flow.bytes_sumsq
                existing.gap_sum += flow.gap_sum
                existing.gap_sumsq += flow.gap_sumsq
                existing.gap_count += flow.gap_count
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
        # Потоки уже разобраны post-extract внутри каждого файла:
        # http_objects/tls_certs/carved_files лежат отдельно. Склеивать
        # байты одного 5-tuple из разных pcap нельзя — на стыке
        # получится поток, которого не было, и ложные совпадения.
        for key, stream in st.tcp_streams.items():
            if key not in merged.tcp_streams:
                merged.tcp_streams[key] = stream
            else:
                merged.extractor_errors["multi_pcap_stream_conflict"] += 1
        merged.tcp_streams_truncated.update(st.tcp_streams_truncated)
        merged.tcp_streams_total += st.tcp_streams_total or len(st.tcp_streams)

        # --- HTTP objects / TLS certs / carved files ---
        merged.http_objects.extend(st.http_objects)
        merged.tls_certs.extend(st.tls_certs)
        merged.tls_cert_parse_errors += st.tls_cert_parse_errors
        merged.carved_files.extend(st.carved_files)

        # --- AD и DCE/RPC ---
        merged.smb2_messages += st.smb2_messages
        merged.smb2_parse_errors += st.smb2_parse_errors
        merged.smb2_commands.update(st.smb2_commands)
        merged.smb2_dialects.update(st.smb2_dialects)
        merged.smb2_shares.update(st.smb2_shares)
        merged.smb2_paths.update(st.smb2_paths)
        merged.smb2_status_errors.update(st.smb2_status_errors)
        merged.smb2_read_bytes += st.smb2_read_bytes
        merged.smb2_write_bytes += st.smb2_write_bytes

        merged.ldap_messages += st.ldap_messages
        merged.ldap_parse_errors += st.ldap_parse_errors
        merged.ldap_bind_dns.update(st.ldap_bind_dns)
        merged.ldap_search_bases.update(st.ldap_search_bases)
        merged.ldap_filters.update(st.ldap_filters)
        merged.ldap_attributes.update(st.ldap_attributes)
        merged.ldap_result_codes.update(st.ldap_result_codes)
        merged.ldap_searches_by_src.update(st.ldap_searches_by_src)
        merged.ldap_root_dse_by_src.update(st.ldap_root_dse_by_src)
        for client, attrs in st.ldap_sensitive_attrs_by_src.items():
            merged.ldap_sensitive_attrs_by_src.setdefault(
                client, set(),
            ).update(attrs)

        merged.kerberos_tgs_requests.update(st.kerberos_tgs_requests)
        merged.kerberos_etypes.update(st.kerberos_etypes)
        merged.dcerpc_binds.update(st.dcerpc_binds)
        merged.dcerpc_drsuapi_calls.update(st.dcerpc_drsuapi_calls)
        merged.dcerpc_naming_contexts.update(st.dcerpc_naming_contexts)

        # --- HTTP/2 и расшифровка TLS ---
        merged.h2_connections += st.h2_connections
        merged.h2_streams += st.h2_streams
        merged.h2_frames += st.h2_frames
        merged.h2_parse_errors += st.h2_parse_errors
        merged.tls_decrypted_streams += st.tls_decrypted_streams
        merged.tls_decrypted_records += st.tls_decrypted_records
        merged.tls_decrypt_errors += st.tls_decrypt_errors
        merged.tls_streams_without_keylog += st.tls_streams_without_keylog
        merged.tls_http1_objects += st.tls_http1_objects

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

        # --- NDP ---
        merged.ndp_total += st.ndp_total
        merged.ndp_neighbors.update(st.ndp_neighbors)
        merged.ndp_routers.update(st.ndp_routers)

    return merged
