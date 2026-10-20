from paradox.models import CaptureState, FlowKey, FlowStats
from paradox.parsers import PacketRecord

# флаги TCP
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10


class FlowExtractor:
    name = "flow"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        # ARP — не IP-flow, для него отдельный экстрактор (позже)
        if record.proto == "arp":
            return
        if record.src_ip is None or record.dst_ip is None:
            return

        key = FlowKey(
            proto=record.proto,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
        )

        flow = state.flows.get(key)
        is_new = flow is None
        if is_new:
            flow = FlowStats()
            state.flows[key] = flow

        ts = record.ts
        flow.packets += 1
        flow.bytes_sent += record.length

        if flow.first_ts is None:
            flow.first_ts = ts
        flow.last_ts = ts

        # определяем инициатора по первому SYN без ACK
        if is_new and flow.initiated_by_src is None:
            if record.proto == "tcp" and record.tcp_flags is not None:
                flags = record.tcp_flags
                if (flags & TCP_FLAG_SYN) and not (flags & TCP_FLAG_ACK):
                    flow.initiated_by_src = True

        if state.first_ts is None:
            state.first_ts = ts
        state.last_ts = ts
