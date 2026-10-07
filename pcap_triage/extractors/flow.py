from pcap_triage.models import CaptureState, FlowKey, FlowStats
from pcap_triage.parsers import PacketRecord


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
        if flow is None:
            flow = FlowStats()
            state.flows[key] = flow

        ts = record.ts
        flow.packets += 1
        flow.bytes_sent += record.length
        flow.timestamps.append(ts)

        if flow.first_ts is None:
            flow.first_ts = ts
        flow.last_ts = ts

        if state.first_ts is None:
            state.first_ts = ts
        state.last_ts = ts