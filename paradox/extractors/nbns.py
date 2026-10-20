"""
NBNSExtractor — имена хостов из NBNS-запросов.

Работает на UDP/137. Пишет hostname в state.host_identities[ip].

Суффиксы имени:
  0x00 — Workstation (имя компьютера)
  0x20 — Server (файловый сервис)
"""
from paradox.models import CaptureState, HostIdentity
from paradox.nbns_parse import parse_nbns
from paradox.parsers import PacketRecord

HOSTNAME_SUFFIXES = {0x00, 0x20}


class NBNSExtractor:
    name = "nbns"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "udp":
            return
        if record.src_port != 137 and record.dst_port != 137:
            return
        if not record.payload:
            return

        result = parse_nbns(record.payload)
        if result is None:
            return

        if result.suffix not in HOSTNAME_SUFFIXES:
            return

        # Имя принадлежит инициатору NBNS-пакета.
        client_ip = record.src_ip

        if not client_ip or not result.name:
            return

        ident = state.host_identities.get(client_ip)
        if ident is None:
            ident = HostIdentity(ip=client_ip)
            state.host_identities[client_ip] = ident

        ident.hostnames.add(result.name)