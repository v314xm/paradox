from pcap_triage.models import CaptureState, FlowKey
from pcap_triage.parsers import PacketRecord
from pcap_triage.tls_parse import extract_sni


class TLSExtractor:
    """
    Извлекает SNI из TLS ClientHello.

    Работает поверх PacketRecord. Порты не проверяются специально:
    смотрим только на сигнатуру payload (первый байт 0x16 = handshake).
    Это ловит TLS и на нестандартных портах (8443, 4443, 9443 и т.п.),
    которые часто используют C2.

    Пишет SNI в уже существующий FlowStats, найденный по FlowKey.
    FlowExtractor ДОЛЖЕН идти первым в pipeline — если flow не найден,
    экстрактор падает явно, чтобы не терять SNI молча.

    Ограничения:
    - ClientHello должен уместиться в один TCP-сегмент. Большинство
      умещается, но фрагментированные (ECH, большие сертификаты) —
      пропустятся. Полное решение — StreamReassembler (L1).
    - Перезаписывает sni, если для этого flow его ещё не было.
      Если уже был — оставляет первое значение (обычно оно же и одно).
    """
    name = "tls"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "tcp":
            return
        if not record.payload:
            return
        # первая сигнатура TLS handshake — 0x16
        if record.payload[0] != 0x16:
            return

        sni = extract_sni(record.payload)
        if not sni:
            return

        if record.src_ip is None or record.dst_ip is None:
            return

        key = FlowKey(
            proto="tcp",
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
        )

        flow = state.flows.get(key)
        if flow is None:
            # FlowExtractor должен был создать flow раньше.
            # Если его нет — что-то не так с порядком экстракторов.
            raise RuntimeError(
                f"TLSExtractor requires FlowExtractor to run first; "
                f"no flow for key {key}"
            )

        # не перезаписываем, если уже установлен
        if flow.sni is None:
            flow.sni = sni