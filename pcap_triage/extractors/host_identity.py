"""
HostIdentityExtractor — IP ↔ MAC.

Источник: только ARP. Это авторитетный источник —
arp_sender_ip ↔ arp_sender_mac.

Fallback из Ethernet (eth_src ↔ src_ip) НЕ используется:
в routed-сетях eth_src — MAC шлюза, а не хоста. Это приводило
к тому, что один MAC (шлюза) записывался на десятки IP.

Если MAC не найден в ARP — оставляем None. Это честнее, чем
неверный MAC.
"""
from pcap_triage.models import CaptureState, HostIdentity
from pcap_triage.parsers import PacketRecord


class HostIdentityExtractor:
    name = "host_identity"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "arp":
            return
        if not record.arp_sender_ip or not record.arp_sender_mac:
            return

        self._set_mac(
            state, record.arp_sender_ip, record.arp_sender_mac,
        )

    def _set_mac(
        self, state: CaptureState, ip: str, mac: str,
    ) -> None:
        # пропускаем невалидные IP (DHCP-запросы идут с 0.0.0.0)
        if not ip or ip == "0.0.0.0":
            return
        # пропускаем broadcast/multicast MAC
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        if mac.startswith("01:00:5e") or mac.startswith("33:33"):
            return

        ident = state.host_identities.get(ip)
        if ident is None:
            ident = HostIdentity(ip=ip)
            state.host_identities[ip] = ident

        # ARP — авторитетный, всегда перезаписываем
        ident.mac = mac