from collections import Counter

from scapy.layers.dns import DNS

from paradox.models import CaptureState
from paradox.parsers import PacketRecord


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

        # Декодируем строго: не-ASCII → отбрасываем весь запрос.
        # Реальные домены — только [a-z0-9.-]. Битые DNS-пакеты
        # (с непечатаемыми байтами в qname) дают мусорные "домены",
        # на которых DGA-детектор ложно срабатывает.
        try:
            name = qname.decode("ascii")
        except UnicodeDecodeError:
            return
        name = name.rstrip(".").lower()
        if not name:
            return
        # Дополнительная защита от бинарного мусора:
        # разрешены только буквы, цифры, дефис, точка
        if not all(c.isalnum() or c in ".-" for c in name):
            return

        # DNS по источнику: клиент — тот, кто спрашивал.
        # Если src_port == 53 — это ответ, клиент = dst_ip.
        # Иначе клиент = src_ip.
        if record.src_port == 53:
            client_ip = record.dst_ip
        else:
            client_ip = record.src_ip

        # NXDOMAIN — свойство ответа, но считаем до разделения по qr:
        # исторически rcode=3 учитывался независимо от qr, и менять
        # это поведение в рамках фикса двойного счёта не нужно.
        if dns.rcode == 3:  # NXDOMAIN
            state.dns_nxdomain[name] += 1
            if client_ip:
                state.dns_nxdomain_by_src[client_ip] += 1
                # v0.9.0: помним ts для скользящего окна в
                # nxdomain_burst. list, не set — повторы ts нужны.
                state.dns_nxdomain_ts_by_src.setdefault(
                    client_ip, [],
                ).append(record.ts)

        # qr=0 — запрос, qr=1 — ответ. Ответ нельзя учитывать как
        # запрос: раньше учитывался, из-за чего dns_queries был
        # удвоен, а ratio в nxdomain_burst получал завышенный
        # знаменатель и глушил детект.
        if dns.qr != 1:
            state.dns_queries[name] += 1

            # v1.3.1: timestamps запросов по имени — для dga/cloud_tunnel/
            # typosquatting, чтобы timeline их видел.
            state.dns_query_ts_by_name.setdefault(name, []).append(record.ts)

            # v1.3.x: ts запросов по src — для windowed ratio в
            # nxdomain_burst.
            if client_ip:
                state.dns_query_ts_by_src.setdefault(
                    client_ip, [],
                ).append(record.ts)

            if client_ip:
                bucket = state.dns_queries_by_src.get(client_ip)
                if bucket is None:
                    bucket = Counter()
                    state.dns_queries_by_src[client_ip] = bucket
                bucket[name] += 1
            return

        # DNS-ответы: A / AAAA / CNAME. Только для ответов (qr=1),
        # только для поддерживаемых типов. Ключ — qname из вопроса,
        # не rrname каждого ответа: так CNAME-цепочка
        # www.foo.com → foo.cdn.com → 1.2.3.4 собирается в один
        # набор {foo.cdn.com, 1.2.3.4} под именем www.foo.com,
        # как его видит клиент.
        if dns.an:
            for rr in dns.an:
                # SOA/MX/TXT и др. могут не иметь rdata — читаем
                # только для известных типов. Без этой проверки
                # rr.rdata падает с AttributeError.
                #
                # v1.3.1: rr.type тоже может падать — крафтовый
                # DNS-ответ с битым RR бросает AttributeError или
                # ValueError. try/except сохраняет остальные RR.
                try:
                    rr_type = rr.type
                except (AttributeError, ValueError):
                    continue
                if rr_type not in (1, 28, 5):
                    continue
                raw = getattr(rr, 'rdata', None)
                if raw is None:
                    continue
                # scapy отдаёт rdata как bytes для CNAME/AAAA;
                # str(bytes) даёт "b'...'" — мусор в отчёте.
                if isinstance(raw, bytes):
                    raw = raw.decode('ascii', errors='ignore')
                value = str(raw)
                if not value:
                    continue
                if rr.type in (1, 28):  # A / AAAA
                    state.dns_answers_by_name.setdefault(name, set()).add(value)
                    state.dns_answers_by_ip.setdefault(value, set()).add(name)
                else:  # 5 = CNAME
                    cname = value.rstrip('.').lower()
                    if cname:
                        state.dns_answers_by_name.setdefault(name, set()).add(cname)
