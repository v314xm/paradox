from scapy.layers.dns import DNS
from scapy.layers.inet import IP

from pcap_triage.models import CaptureState


class DNSExtractor:
    name = "dns"
    layer = 0

    def process(self, pkt, state: CaptureState) -> None:
        if not pkt.haslayer(DNS):
            return

        dns = pkt[DNS]
        if dns.qdcount < 1 or dns.qd is None:
            return

        qname = dns.qd.qname
        if not qname:
            return

        name = qname.decode(errors="ignore").rstrip(".").lower()
        if not name:
            return

        state.dns_queries[name] += 1
        if dns.rcode == 3:  # NXDOMAIN
            state.dns_nxdomain[name] += 1
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                state.dns_nxdomain_by_src[src_ip] += 1