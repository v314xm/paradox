"""
Генератор тестового pcap для проверки pipeline.

Создаёт синтетический захват со всем, что должен ловить текущий пайплайн:
- нормальные DNS-запросы;
- DGA-подобные домены (высокая энтропия, длинный label);
- NXDOMAIN-ответы и NXDOMAIN burst;
- TCP-соединения на подозрительные порты (4444, 12132, 8080);
- cloud tunnel домены (trycloudflare, ngrok, serveo);
- ip check services (ip-api.com, ifconfig.me);
- typosquatting (подделки под Microsoft);
- нормальный TLS-трафик на 443 для контраста;
- UDP-трафик на невыделенный порт.

Запуск:
    python make_test_pcap.py

Результат:
    test_capture.pcap в текущей папке.
"""

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    wrpcap,
)


CLIENT_IP = "192.168.1.100"
CLIENT_MAC = "aa:bb:cc:dd:ee:01"
GW_MAC = "aa:bb:cc:dd:ee:02"

# Фиксированный base_ts, чтобы отчёт был детерминирован между запусками.
BASE_TS = 1_700_000_000.0


def _eth_ip_udp(src_ip, dst_ip, sport, dport, payload=b""):
    return (
        Ether(src=CLIENT_MAC, dst=GW_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / payload
    )


def _eth_ip_tcp(src_ip, dst_ip, sport, dport, flags="S", payload=b""):
    return (
        Ether(src=CLIENT_MAC, dst=GW_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags)
        / payload
    )


def build_packets():
    packets = []
    t = BASE_TS

    # 1. Нормальный DNS-запрос
    p = _eth_ip_udp(
        CLIENT_IP, "8.8.8.8", 51000, 53,
        DNS(rd=1, qd=DNSQR(qname="google.com")),
    )
    p.time = t
    packets.append(p)
    t += 0.01

    # 2. DGA-подобные домены
    dga_domains = [
        "kq3jf9zxqp1mwv7n.ru",
        "a8sd7f6g9h2k4l5m3n.biz",
        "x9c2v7b4n1m8q3w5e.top",
    ]
    for d in dga_domains:
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 51001, 53,
            DNS(rd=1, qd=DNSQR(qname=d)),
        )
        p.time = t
        packets.append(p)
        t += 0.01

    # 3. NXDOMAIN-ответы (не burst, просто несколько штук)
    for d in ["notexist1.example", "notexist2.example", "notexist3.example"]:
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 51002, 53,
            DNS(rd=1, qd=DNSQR(qname=d), rcode=3),
        )
        p.time = t
        packets.append(p)
        t += 0.01

    # 4. Ответ DNS для нормального домена
    p = _eth_ip_udp(
        "8.8.8.8", CLIENT_IP, 53, 51000,
        DNS(
            qr=1, rd=1, ra=1,
            qd=DNSQR(qname="google.com"),
            an=DNSRR(rrname="google.com", rdata="142.250.185.78"),
        ),
    )
    p.time = t
    packets.append(p)
    t += 0.01

    # 5. Нормальный TLS-трафик на 443
    p = _eth_ip_tcp(CLIENT_IP, "142.250.185.78", 52000, 443, flags="S")
    p.time = t
    packets.append(p)
    t += 0.001

    p = _eth_ip_tcp("142.250.185.78", CLIENT_IP, 443, 52000, flags="SA")
    p.time = t
    packets.append(p)
    t += 0.001

    p = _eth_ip_tcp(
        CLIENT_IP, "142.250.185.78", 52000, 443, flags="A",
        payload=b"\x16\x03\x01\x00\x50",
    )
    p.time = t
    packets.append(p)
    t += 0.5

    # 6. Соединение на 4444 (Metasploit) — один flow
    p = _eth_ip_tcp(CLIENT_IP, "203.0.113.66", 53000, 4444, flags="S")
    p.time = t
    packets.append(p)
    t += 0.001

    p = _eth_ip_tcp("203.0.113.66", CLIENT_IP, 4444, 53000, flags="SA")
    p.time = t
    packets.append(p)
    t += 0.5

    # 7. Beaconing на 12132 (STRRAT) — ОДИН sport, много ударов
    p = _eth_ip_tcp(CLIENT_IP, "203.0.113.77", 54000, 12132, flags="S")
    p.time = t
    packets.append(p)
    t += 0.001

    p = _eth_ip_tcp("203.0.113.77", CLIENT_IP, 12132, 54000, flags="SA")
    p.time = t
    packets.append(p)
    t += 0.001

    for i in range(5):
        p = _eth_ip_tcp(
            CLIENT_IP, "203.0.113.77", 54000, 12132, flags="A",
            payload=b"ping",
        )
        p.time = t
        packets.append(p)
        t += 30.0

    # 8. Соединение на 8080 — один flow
    p = _eth_ip_tcp(CLIENT_IP, "203.0.113.88", 55000, 8080, flags="S")
    p.time = t
    packets.append(p)
    t += 0.001

    p = _eth_ip_tcp(
        CLIENT_IP, "203.0.113.88", 55000, 8080, flags="A",
        payload=b"GET / HTTP/1.1\r\nHost: 203.0.113.88\r\n\r\n",
    )
    p.time = t
    packets.append(p)
    t += 0.01

    # 9. UDP на NTP (123)
    p = _eth_ip_udp(CLIENT_IP, "1.1.1.1", 56000, 123, b"\x00" * 48)
    p.time = t
    packets.append(p)
    t += 0.01

    # 10. NXDOMAIN burst — 6 подряд, чтобы превысить порог 5
    for i in range(6):
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 57000 + i, 53,
            DNS(rd=1, qd=DNSQR(qname=f"burst{i}.nxdomain.example"), rcode=3),
        )
        p.time = t
        packets.append(p)
        t += 0.1

    # 11. Cloud tunnel домены
    for d in [
        "varying-rentals-calgary-predict.trycloudflare.com",
        "abc123.ngrok.io",
        "test.serveo.net",
    ]:
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 58000, 53,
            DNS(rd=1, qd=DNSQR(qname=d)),
        )
        p.time = t
        packets.append(p)
        t += 0.01

    # 12. IP check service
    for d in ["ip-api.com", "ifconfig.me"]:
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 59000, 53,
            DNS(rd=1, qd=DNSQR(qname=d)),
        )
        p.time = t
        packets.append(p)
        t += 0.01

    # 13. Typosquatting — подделки под Microsoft
    for d in [
        "event-datamicrosoft.live",   # contains
        "micr0soft.com",              # levenshtein
    ]:
        p = _eth_ip_udp(
            CLIENT_IP, "8.8.8.8", 60000, 53,
            DNS(rd=1, qd=DNSQR(qname=d)),
        )
        p.time = t
        packets.append(p)
        t += 0.01

    return packets


def main():
    output = "test_capture.pcap"
    packets = build_packets()
    wrpcap(output, packets)

    print(f"written: {output}")
    print(f"packets: {len(packets)}")
    print()
    print("Ожидаемые findings после прогона pipeline:")
    print("  dga_domain           x3")
    print("  suspicious_port      x3  (4444, 12132, 8080)")
    print("  nxdomain_burst       x1  (192.168.1.100)")
    print("  cloud_tunnel_domain  x3  (trycloudflare, ngrok, serveo)")
    print("  ip_check_service     x2  (ip-api.com, ifconfig.me)")
    print("  typosquatting        x2  (event-datamicrosoft.live, micr0soft.com)")
    print()
    print("Ожидаемые summary:")
    print(f"  packets:            {len(packets)}")
    print("  unique_dns_queries: ~20")
    print("  nxdomain_count:     ~9")
    print("  findings:           14")


if __name__ == "__main__":
    main()