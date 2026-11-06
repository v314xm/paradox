from paradox.ja3 import parse_client_hello, parse_server_hello
from paradox.models import CaptureState, FlowKey, make_session_key
from paradox.parsers import PacketRecord


class TLSExtractor:
    """
    Извлекает SNI + JA3 из TLS ClientHello и JA3S из ServerHello.

    Работает поверх PacketRecord. Порты не проверяются специально:
    смотрим только на сигнатуру payload (первый байт 0x16 = handshake).
    Это ловит TLS и на нестандартных портах (8443, 4443, 9443 и т.п.),
    которые часто используют C2.

    Пишет в существующий FlowStats, найденный по FlowKey.
    FlowExtractor ДОЛЖЕН идти первым в pipeline — если flow не найден,
    экстрактор падает явно, чтобы не терять данные молча.

    Ограничения:
    - ClientHello/ServerHello должны уместиться в один TCP-сегмент.
      Полное решение — StreamReassembler (L1, TODO).
    - Перезаписывает поля только если они ещё пустые. Первое значение
      считается правильным (обычно оно и одно).
    """
    name = "tls"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "tcp":
            return
        if not record.payload:
            return
        # сигнатура TLS handshake — 0x16
        if record.payload[0] != 0x16:
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
            raise RuntimeError(
                f"TLSExtractor requires FlowExtractor to run first; "
                f"no flow for key {key}"
            )

        # 1. Пробуем ClientHello — SNI + JA3
        client = parse_client_hello(record.payload)
        if client is not None:
            if client.get("sni") and flow.sni is None:
                flow.sni = client["sni"]
                # дублируем в session_sni для обратного направления
                sk = make_session_key(key)
                if sk not in state.session_sni:
                    state.session_sni[sk] = client["sni"]

            if client.get("ja3") and flow.ja3 is None:
                flow.ja3 = client["ja3"]
            return

        # 2. Пробуем ServerHello — JA3S
        server = parse_server_hello(record.payload)
        if server is not None:
            if server.get("ja3s") and flow.ja3s is None:
                flow.ja3s = server["ja3s"]
            return

        # Ни ClientHello, ни ServerHello — просто TLS handshake
        # (Certificate, Finished, Alert, ...). Игнорируем.

    def run_post_extract(
        self, state: CaptureState, config,
    ) -> None:
        """Добрать SNI/JA3 из склеенных TCP-потоков.

        ClientHello современного Chrome (post-quantum key share,
        длинный список расширений) не влезает в один сегмент.
        Потоковый process() видит только первый сегмент и теряет
        SNI, а с ним sni_mismatch, sni_without_dns, ja3_malware и
        sni_domains у сущностей. В tcp_streams лежит весь поток —
        парсим его, если поля ещё пустые.
        """
        _ = config
        for key, stream in state.tcp_streams.items():
            flow = state.flows.get(key)
            if flow is None:
                continue
            if flow.sni is not None and flow.ja3 is not None:
                continue

            client = parse_client_hello(stream)
            if client is None:
                continue

            if client.get("sni") and flow.sni is None:
                flow.sni = client["sni"]
                sk = make_session_key(key)
                if sk not in state.session_sni:
                    state.session_sni[sk] = client["sni"]

            if client.get("ja3") and flow.ja3 is None:
                flow.ja3 = client["ja3"]
