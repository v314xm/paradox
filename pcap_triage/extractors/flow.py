from scapy.layers.inet import IP, TCP, UDP

from pcap_triage.models import CaptureState, FlowKey, FlowStats


class FlowExtractor:
    name = "flow"
    layer = 0

    def process(self, pkt, state: CaptureState) -> None:
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]

        if pkt.haslayer(TCP):
            proto = "tcp"
            l4 = pkt[TCP]
            sport, dport = int(l4.sport), int(l4.dport)
        elif pkt.haslayer(UDP):
            proto = "udp"
            l4 = pkt[UDP]
            sport, dport = int(l4.sport), int(l4.dport)
        else:
            proto = "other"
            sport = dport = None

        key = FlowKey(
            proto=proto,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=sport,
            dst_port=dport,
        )

        flow = state.flows.get(key)
        if flow is None:
            flow = FlowStats()
            state.flows[key] = flow

        ts = float(pkt.time)
        flow.packets += 1
        flow.bytes_sent += len(pkt)
        flow.timestamps.append(ts)

        if flow.first_ts is None:
            flow.first_ts = ts
        flow.last_ts = ts

        if state.first_ts is None:
            state.first_ts = ts
        state.last_ts = ts