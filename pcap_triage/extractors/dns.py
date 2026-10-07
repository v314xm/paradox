from collections import Counter

from scapy.layers.dns import DNS

from pcap_triage.models import CaptureState
from pcap_triage.parsers import PacketRecord


class DNSExtractor:
    """
    DNS-экстрактор.

    Работает поверх PacketRecord. DNS payload парсит через scapy,
    но только для пакетов на порт 53 — таких в реальных pcap'ах
    сотни из сотен тысяч, накладные расходы незаметны.
    """
    name = "dns"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.src_port != 53 and record.dst_port != 53:
            return
        if not record.payload:
            return

        try:
            dns = DNS(record.payload)
        except Exception:
            return

        if dns.qdcount < 1 or dns.qd is None:
            return

        qname = dns.qd.qname
        if not qname:
            return

        name = qname.decode(errors="ignore").rstrip(".").lower()
        if not name:
            return

        state.dns_queries[name] += 1

        # DNS по источнику: клиент — тот, кто спрашивал.
        # Если src_port == 53 — это ответ, клиент = dst_ip.
        # Иначе клиент = src_ip.
        if record.src_port == 53:
            client_ip = record.dst_ip
        else:
            client_ip = record.src_ip

        if client_ip:
            bucket = state.dns_queries_by_src.get(client_ip)
            if bucket is None:
                bucket = Counter()
                state.dns_queries_by_src[client_ip] = bucket
            bucket[name] += 1

        if dns.rcode == 3:  # NXDOMAIN
            state.dns_nxdomain[name] += 1
            if client_ip:
                state.dns_nxdomain_by_src[client_ip] += 1