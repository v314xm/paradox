"""
HTTPObjectExtractor — построение HTTP-объектов из склеенных потоков.

Особенность: это НЕ обычный экстрактор в pipeline. Он не вызывается
per-packet. Вместо этого его метод run_post_extract() вызывается
один раз — после того как TCPReassembler закончил и state.tcp_streams
заполнен.

Что делает:
- Идёт по state.tcp_streams
- Для каждого потока пробует parse_http_request и parse_http_response
- Кладёт результат в state.http_objects как (FlowKey, HttpObject)

Почему после reassembly, а не параллельно:
- HTTP заголовки и body часто разбиты на 2-3 TCP-сегмента.
- Раньше (extractors/http.py) мы видели только первый сегмент.
- Теперь видим полностью.
"""
from pcap_triage.config import Config
from pcap_triage.http_object import (
    DEFAULT_BODY_LIMIT,
    parse_http_request,
    parse_http_response,
)
from pcap_triage.models import CaptureState


class HTTPObjectExtractor:
    name = "http_object"
    layer = 1  # не L0 — работает после reassembly

    def process(self, record, state: CaptureState) -> None:
        """Per-packet обработка не нужна — no-op."""
        return

    def run_post_extract(
        self,
        state: CaptureState,
        config: Config,
    ) -> None:
        """Пройтись по state.tcp_streams, распарсить HTTP-объекты."""
        if not state.tcp_streams:
            return

        body_limit = getattr(
            config, "http_object_body_limit", DEFAULT_BODY_LIMIT,
        )

        objects: list = []
        for key, stream in state.tcp_streams.items():
            if not stream:
                continue

            # Быстрая проверка: HTTP-запросы начинаются с метода,
            # HTTP-ответы — с "HTTP/". Если не совпало — пропускаем
            # без вызова парсеров.
            head = stream[:16]
            if b" " not in head and not head.startswith(b"HTTP/"):
                continue

            obj = parse_http_request(stream, body_limit=body_limit)
            if obj is not None:
                objects.append((key, obj))
                continue

            obj = parse_http_response(stream, body_limit=body_limit)
            if obj is not None:
                objects.append((key, obj))

        state.http_objects = objects