"""
HTTP-экстрактор.

Работает поверх PacketRecord. Ловит HTTP-запросы в TCP-payload,
парсит через http_parse, пишет в FlowStats.

Порты не проверяются: смотрим только на сигнатуру payload
(начинается с известного HTTP-метода). Так ловим HTTP и на
нестандартных портах (8000, 8080, 8888 и т.п.).

Пишет только HTTP-запросы, не ответы. Ответы имеют первую
строку "HTTP/1.1 200 OK" — версия идёт первой, метод не наш.

Ограничения:
- HTTP-запрос должен уместиться в один TCP-сегмент.
- HTTP/2 (бинарный) не поддерживается.
"""
from paradox.http_parse import HTTP_METHODS, parse_request
from paradox.models import CaptureState, FlowKey
from paradox.parsers import PacketRecord


class HTTPExtractor:
    name = "http"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.proto != "tcp":
            return
        if not record.payload:
            return

        if not self._looks_like_http(record.payload):
            return

        req = parse_request(record.payload)
        if req is None:
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
            raise RuntimeError(
                f"HTTPExtractor requires FlowExtractor to run first; "
                f"no flow for key {key}"
            )

        if flow.http_method is None:
            flow.http_method = req.method
        if flow.http_uri is None:
            flow.http_uri = req.uri
        if flow.http_host is None:
            flow.http_host = req.host
        if flow.http_user_agent is None:
            flow.http_user_agent = req.user_agent

    def _looks_like_http(self, payload: bytes) -> bool:
        """Проверка: первая строка начинается с HTTP-метода."""
        space_idx = payload.find(b" ")
        if space_idx <= 0 or space_idx > 10:
            return False
        method_bytes = payload[:space_idx]
        try:
            method = method_bytes.decode("ascii")
        except UnicodeDecodeError:
            return False
        return method in HTTP_METHODS
