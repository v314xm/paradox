"""
KerberosExtractor — извлекает cname, realm, sname из Kerberos-пакетов.

Работает на UDP/88 и TCP/88. Парсит AS-REQ/AS-REP/TGS-REQ/TGS-REP/AP-REQ
через paradox.kerberos_parse (ручной ASN.1 DER).

Пишет в state.host_identities[src_ip]:
  - cname без `$` и без `/` → username
  - cname с `$` в конце    → hostname (без `$`)
  - cname с `/` или krbtgt → service principal, игнорируется
  - crealm / realm          → realm (приоритет у FQDN с точкой)

Только запросы клиента (dst_port == 88). Ответы KDC не дают
новых данных — там тот же principal.
"""
from paradox.kerberos_parse import parse_kerberos
from paradox.models import CaptureState, HostIdentity
from paradox.parsers import PacketRecord


class KerberosExtractor:
    name = "kerberos"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto not in ("tcp", "udp"):
            return
        if record.src_port != 88 and record.dst_port != 88:
            return
        if not record.payload:
            return

        # обрабатываем оба направления:
        #   dst_port == 88 → запрос клиента, client_ip = src_ip
        #   src_port == 88 → ответ KDC, client_ip = dst_ip
        if record.dst_port == 88:
            client_ip = record.src_ip
        elif record.src_port == 88:
            client_ip = record.dst_ip
        else:
            return

        if not client_ip:
            return

        info = parse_kerberos(record.payload)
        if info is None:
            return

        ident = state.host_identities.get(client_ip)
        if ident is None:
            ident = HostIdentity(ip=client_ip)
            state.host_identities[client_ip] = ident

        # --- cname: username / hostname / service ---
        if info.cname:
            name = info.cname
            if name.endswith("$"):
                # hostname (компьютерная учётка)
                hostname = name[:-1].strip()
                if hostname:
                    ident.hostnames.add(hostname)
            elif "/" in name or name.lower() == "krbtgt":
                # service principal (SPN) — не наш case
                pass
            else:
                # username
                if ident.username is None:
                    ident.username = name

        # --- realm: FQDN предпочтительнее короткого NetBIOS ---
        realm = info.crealm or info.realm
        if realm:
            if ident.realm is None or (
                "." in realm and "." not in ident.realm
            ):
                ident.realm = realm
