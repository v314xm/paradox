"""
TlsCertificateExtractor — извлекает X.509 сертификаты из TLS-хендшейков.

Работает как пост-процессор ПОСЛЕ TCP-reassembly: ему нужны склеенные
потоки, потому что сертификат обычно больше одного TCP-сегмента.

Использование в pipeline:
    TlsCertificateExtractor().run_post_extract(state, config)

Не идёт в общий список EXTRACTORS, потому что не имеет метода process().
"""
from __future__ import annotations

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, FlowKey
from pcap_triage.tls_cert import parse_certificate_from_stream


class TlsCertificateExtractor:
    name = "tls_cert"

    def run_post_extract(
        self, state: CaptureState, config: Config,
    ) -> None:
        """Найти TLS-сертификаты в серверных потоках.

        Логика: для каждого flow с SNI (значит TLS-клиент) смотрим
        в ОБРАТНЫЙ поток (сервер→клиент) в tcp_streams. Там ищется
        ServerHello, потом Certificate. Парсим, сохраняем.
        """
        _ = config  # пока не используется, но сигнатура на будущее

        for key, flow in state.flows.items():
            if not flow.sni:
                continue

            reverse_key = FlowKey(
                proto=key.proto,
                src_ip=key.dst_ip,
                dst_ip=key.src_ip,
                src_port=key.dst_port,
                dst_port=key.src_port,
            )
            stream = state.tcp_streams.get(reverse_key)
            if not stream:
                continue

            cert = parse_certificate_from_stream(stream)
            if cert is None:
                continue

            state.tls_certs.append((key, cert))
