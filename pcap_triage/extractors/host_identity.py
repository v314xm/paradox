"""
HostIdentityExtractor — связывает IP ↔ MAC.

Источники:
  1. ARP — авторитетный. arp_sender_mac ↔ arp_sender_ip.
  2. Ethernet IPv4 — fallback. eth_src ↔ src_ip.
     (В routed-сетях eth_src — MAC шлюза, поэтому fallback слабее.)

Приоритет: ARP перезаписывает fallback. Fallback не перезаписывает
уже установленный MAC.
"""
from pcap_triage.models import CaptureState, HostIdentity
from pcap_triage.parsers import PacketRecord


class HostIdentityExtractor:
    name = "host_identity"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        # ARP — авторитетный источник
        if record.proto == "arp":
            if record.arp_sender_ip and record.arp_sender_mac:
                self._set_mac(
                    state, record.arp_sender_ip, record.arp_sender_mac,
                    overwrite=True,
                )
            return

        # Fallback: Ethernet src MAC для IPv4-пакета
        if record.src_ip and record.eth_src:
            self._set_mac(
                state, record.src_ip, record.eth_src, overwrite=False,
            )

    def _set_mac(
        self, state: CaptureState, ip: str, mac: str, overwrite: bool,
    ) -> None:
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        if mac.startswith("01:00:5e") or mac.startswith("33:33"):
            return  # multicast

        ident = state.host_identities.get(ip)
        if ident is None:
            ident = HostIdentity(ip=ip)
            state.host_identities[ip] = ident

        if ident.mac is None or overwrite:
            ident.mac = mac