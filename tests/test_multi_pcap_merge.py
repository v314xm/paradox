"""Тесты merge_capture_states (fix_32).

merge склеивает CaptureState'ы из разных pcap. Вызывается ТОЛЬКО
в multi-pcap режиме — обычные тесты его не касаются. 71 statement
не покрыт, а fix_30 только что добавил туда merge dns_query_ts_by_name.

Риск: если merge теряет поля или перезаписывает вместо агрегации,
пользователь с 5 pcap не увидит findings — и никто не заметит,
пока не попробует multi-pcap.
"""
from collections import Counter

from paradox.models import (
    CaptureState,
    FlowKey,
    FlowStats,
    HostIdentity,
)
from paradox.multi_pcap import merge_capture_states


def _flow(src="10.0.0.1", dst="1.1.1.1", sport=12345, dport=80,
          packets=10, bytes_sent=1000, first=100.0, last=200.0):
    return FlowKey("tcp", src, dst, sport, dport), FlowStats(
        packets=packets, bytes_sent=bytes_sent,
        first_ts=first, last_ts=last,
    )


# ================== базовые ==================

def test_empty_list_returns_empty_state():
    merged = merge_capture_states([])
    assert merged.packet_count == 0
    assert len(merged.flows) == 0
    assert len(merged.dns_queries) == 0


def test_single_state_returns_its_data():
    s = CaptureState()
    s.packet_count = 100
    k, f = _flow()
    s.flows[k] = f
    merged = merge_capture_states([s])
    assert merged.packet_count == 100
    assert len(merged.flows) == 1


def test_meta_aggregates():
    s1 = CaptureState()
    s1.packet_count = 100
    s1.first_ts = 100.0
    s1.last_ts = 200.0
    s1.unsupported = {"ipv6": 5}
    s1.extractor_errors = Counter({"dns": 1})

    s2 = CaptureState()
    s2.packet_count = 200
    s2.first_ts = 150.0
    s2.last_ts = 300.0
    s2.unsupported = {"ipv6": 3, "arp": 2}
    s2.extractor_errors = Counter({"dns": 2, "tls": 1})

    merged = merge_capture_states([s1, s2])
    assert merged.packet_count == 300
    assert merged.first_ts == 100.0
    assert merged.last_ts == 300.0
    assert merged.unsupported["ipv6"] == 8
    assert merged.unsupported["arp"] == 2
    assert merged.extractor_errors["dns"] == 3
    assert merged.extractor_errors["tls"] == 1


# ================== flows ==================

def test_flows_aggregate_packets_and_bytes():
    k, _ = _flow()
    s1 = CaptureState()
    s1.flows[k] = FlowStats(
        packets=10, bytes_sent=1000, first_ts=100.0, last_ts=150.0,
    )
    s2 = CaptureState()
    s2.flows[k] = FlowStats(
        packets=5, bytes_sent=500, first_ts=120.0, last_ts=200.0,
    )
    merged = merge_capture_states([s1, s2])
    mf = merged.flows[k]
    assert mf.packets == 15
    assert mf.bytes_sent == 1500
    assert mf.first_ts == 100.0
    assert mf.last_ts == 200.0


def test_flows_different_keys_kept():
    k1, _ = _flow(sport=11111)
    k2, _ = _flow(sport=22222)
    s1 = CaptureState()
    s1.flows[k1] = FlowStats(packets=1, bytes_sent=100)
    s2 = CaptureState()
    s2.flows[k2] = FlowStats(packets=1, bytes_sent=100)
    merged = merge_capture_states([s1, s2])
    assert len(merged.flows) == 2
    assert k1 in merged.flows
    assert k2 in merged.flows


def test_flows_preserve_http_and_sni_from_either_state():
    k, _ = _flow()
    s1 = CaptureState()
    s1.flows[k] = FlowStats(sni="example.com")
    s2 = CaptureState()
    s2.flows[k] = FlowStats(http_host="example.com", http_method="GET")
    merged = merge_capture_states([s1, s2])
    mf = merged.flows[k]
    assert mf.sni == "example.com"
    assert mf.http_host == "example.com"
    assert mf.http_method == "GET"


# ================== DNS ==================

def test_dns_queries_merge_counters():
    s1 = CaptureState()
    s1.dns_queries["evil.com"] = 3
    s1.dns_queries["good.com"] = 1
    s2 = CaptureState()
    s2.dns_queries["evil.com"] = 2
    s2.dns_queries["other.com"] = 5
    merged = merge_capture_states([s1, s2])
    assert merged.dns_queries["evil.com"] == 5
    assert merged.dns_queries["good.com"] == 1
    assert merged.dns_queries["other.com"] == 5


def test_dns_queries_by_src_merge():
    s1 = CaptureState()
    s1.dns_queries_by_src["10.0.0.5"] = Counter({"evil.com": 2})
    s2 = CaptureState()
    s2.dns_queries_by_src["10.0.0.5"] = Counter({"evil.com": 1, "b.com": 3})
    s2.dns_queries_by_src["10.0.0.6"] = Counter({"c.com": 1})
    merged = merge_capture_states([s1, s2])
    assert merged.dns_queries_by_src["10.0.0.5"]["evil.com"] == 3
    assert merged.dns_queries_by_src["10.0.0.5"]["b.com"] == 3
    assert merged.dns_queries_by_src["10.0.0.6"]["c.com"] == 1


def test_dns_answers_by_name_and_ip():
    s1 = CaptureState()
    s1.dns_answers_by_name["evil.com"] = {"1.1.1.1"}
    s1.dns_answers_by_ip["1.1.1.1"] = {"evil.com"}
    s2 = CaptureState()
    s2.dns_answers_by_name["evil.com"] = {"2.2.2.2"}
    s2.dns_answers_by_ip["2.2.2.2"] = {"evil.com"}
    merged = merge_capture_states([s1, s2])
    assert merged.dns_answers_by_name["evil.com"] == {"1.1.1.1", "2.2.2.2"}
    assert merged.dns_answers_by_ip["2.2.2.2"] == {"evil.com"}


def test_dns_nxdomain_ts_by_src_extends():
    s1 = CaptureState()
    s1.dns_nxdomain_ts_by_src["10.0.0.5"] = [100.0, 200.0]
    s2 = CaptureState()
    s2.dns_nxdomain_ts_by_src["10.0.0.5"] = [300.0]
    merged = merge_capture_states([s1, s2])
    assert merged.dns_nxdomain_ts_by_src["10.0.0.5"] == [100.0, 200.0, 300.0]


def test_dns_query_ts_by_name_extends():
    """Регрессия fix_30: ts для dga/cloud_tunnel/typosquatting."""
    s1 = CaptureState()
    s1.dns_query_ts_by_name["evil.com"] = [100.0, 200.0]
    s2 = CaptureState()
    s2.dns_query_ts_by_name["evil.com"] = [300.0]
    s2.dns_query_ts_by_name["other.com"] = [400.0]
    merged = merge_capture_states([s1, s2])
    assert merged.dns_query_ts_by_name["evil.com"] == [100.0, 200.0, 300.0]
    assert merged.dns_query_ts_by_name["other.com"] == [400.0]


# ================== host_identities ==================

def test_host_identity_merges_mac_and_hostnames():
    s1 = CaptureState()
    s1.host_identities["10.0.0.5"] = HostIdentity(
        ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff",
        hostnames={"host1"},
    )
    s2 = CaptureState()
    s2.host_identities["10.0.0.5"] = HostIdentity(
        ip="10.0.0.5", hostnames={"host2"},
        username="alice", realm="EXAMPLE.COM",
    )
    merged = merge_capture_states([s1, s2])
    ident = merged.host_identities["10.0.0.5"]
    assert ident.mac == "aa:bb:cc:dd:ee:ff"
    assert ident.hostnames == {"host1", "host2"}
    assert ident.username == "alice"
    assert ident.realm == "EXAMPLE.COM"


# ================== arp_macs ==================

def test_arp_macs_merge_by_ip_and_mac():
    s1 = CaptureState()
    s1.arp_macs["10.0.0.5"] = {"aa:bb:cc:dd:ee:ff": [100.0, 200.0, 3]}
    s2 = CaptureState()
    s2.arp_macs["10.0.0.5"] = {"aa:bb:cc:dd:ee:ff": [50.0, 250.0, 2]}
    s2.arp_macs["10.0.0.5"]["11:22:33:44:55:66"] = [150.0, 160.0, 1]
    merged = merge_capture_states([s1, s2])
    entry = merged.arp_macs["10.0.0.5"]["aa:bb:cc:dd:ee:ff"]
    assert entry[0] == 50.0
    assert entry[1] == 250.0
    assert entry[2] == 5
    assert "11:22:33:44:55:66" in merged.arp_macs["10.0.0.5"]


# ================== tcp_streams ==================

def test_tcp_streams_concatenated():
    k1 = FlowKey("tcp", "10.0.0.1", "1.1.1.1", 12345, 80)
    k2 = FlowKey("tcp", "10.0.0.1", "1.1.1.1", 12346, 80)
    s1 = CaptureState()
    s1.tcp_streams[k1] = b"GET / "
    s2 = CaptureState()
    s2.tcp_streams[k1] = b"HTTP/1.1"
    s2.tcp_streams[k2] = b"POST"
    merged = merge_capture_states([s1, s2])
    assert merged.tcp_streams[k1] == b"GET / HTTP/1.1"
    assert merged.tcp_streams[k2] == b"POST"


# ================== http_objects / tls_certs / carved_files ==================

def test_http_objects_extended():
    s1 = CaptureState()
    s1.http_objects = [("obj1",)]
    s2 = CaptureState()
    s2.http_objects = [("obj2",), ("obj3",)]
    merged = merge_capture_states([s1, s2])
    assert len(merged.http_objects) == 3


def test_tls_certs_extended():
    s1 = CaptureState()
    s1.tls_certs = [("cert1",)]
    s2 = CaptureState()
    s2.tls_certs = [("cert2",)]
    merged = merge_capture_states([s1, s2])
    assert len(merged.tls_certs) == 2


def test_carved_files_extended():
    s1 = CaptureState()
    s1.carved_files = ["file1"]
    s2 = CaptureState()
    s2.carved_files = ["file2", "file3"]
    merged = merge_capture_states([s1, s2])
    assert len(merged.carved_files) == 3


# ================== SSH / SMTP ==================

def test_ssh_versions_and_attempts_merge():
    s1 = CaptureState()
    s1.ssh_server_versions[("1.1.1.1", 22)] = "OpenSSH_8.2"
    s1.ssh_client_versions["10.0.0.5"] = {"OpenSSH_9.0"}
    s1.ssh_client_attempts[("10.0.0.5", "1.1.1.1", 22)] = 5
    s2 = CaptureState()
    s2.ssh_client_versions["10.0.0.5"] = {"PuTTY_0.76"}
    s2.ssh_client_attempts[("10.0.0.5", "1.1.1.1", 22)] = 3
    merged = merge_capture_states([s1, s2])
    assert merged.ssh_server_versions[("1.1.1.1", 22)] == "OpenSSH_8.2"
    assert merged.ssh_client_versions["10.0.0.5"] == {"OpenSSH_9.0", "PuTTY_0.76"}
    assert merged.ssh_client_attempts[("10.0.0.5", "1.1.1.1", 22)] == 8


def test_smtp_merge():
    s1 = CaptureState()
    s1.smtp_helo_by_src["10.0.0.5"] = "spammer.com"
    s1.smtp_from_by_src["10.0.0.5"] = {"evil@bad.com"}
    s1.smtp_rcpt_by_src["10.0.0.5"] = {"victim1@x.com"}
    s1.smtp_mailer_by_src["10.0.0.5"] = {"PHPMailer"}
    s2 = CaptureState()
    s2.smtp_from_by_src["10.0.0.5"] = {"other@bad.com"}
    s2.smtp_rcpt_by_src["10.0.0.5"] = {"victim2@x.com"}
    s2.smtp_mailer_by_src["10.0.0.5"] = {"Swaks"}
    merged = merge_capture_states([s1, s2])
    assert merged.smtp_helo_by_src["10.0.0.5"] == "spammer.com"
    assert merged.smtp_from_by_src["10.0.0.5"] == {
        "evil@bad.com", "other@bad.com",
    }
    assert merged.smtp_rcpt_by_src["10.0.0.5"] == {
        "victim1@x.com", "victim2@x.com",
    }
    assert merged.smtp_mailer_by_src["10.0.0.5"] == {"PHPMailer", "Swaks"}
