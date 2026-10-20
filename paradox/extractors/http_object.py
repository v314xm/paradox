"""
HTTPObjectExtractor — построение HTTP-объектов из склеенных потоков.

Особенность: это НЕ обычный экстрактор в pipeline. Он не вызывается
per-packet. Вместо этого его метод run_post_extract() вызывается
один раз — после того как TCPReassembler закончил и state.tcp_streams
заполнен.

Что делает:
- Идёт по state.tcp_streams (два прохода).
- Pass 1: собирает все HTTP-запросы, сохраняет URI по нормализованному
  ключу пары (src↔dst).
- Pass 2: собирает все HTTP-ответы. Если у response нет URI (что норма),
  берёт URI из парного request.

Зачем pairing: URI есть только в request. Response видит только
"HTTP/1.1 200 OK ...". Чтобы FileCarve мог использовать URI для
определения расширения (например /ftp_update.sh → .sh), нужно
пробросить URI из request в response.

Нормализация пары: request имеет ключ (client_ip:client_port →
server_ip:server_port), response имеет обратный. Приводим оба к
отсортированному кортежу — тогда они встречаются.

Почему после reassembly, а не параллельно:
- HTTP заголовки и body часто разбиты на 2-3 TCP-сегмента.
- Раньше (extractors/http.py) мы видели только первый сегмент.
- Теперь видим полностью.
"""
from paradox.config import Config
from paradox.http_object import (
    DEFAULT_BODY_LIMIT,
    parse_http_request,
    parse_http_response,
)
from paradox.models import CaptureState


def _norm_pair(key) -> tuple:
    """
    Нормализованный ключ TCP-пары: request и response одной сессии
    получают одинаковый ключ.

    request:  (src=(client_ip, client_port), dst=(server_ip, server_port))
    response: (src=(server_ip, server_port), dst=(client_ip, client_port))
    → оба становятся ((client_ip, client_port), (server_ip, server_port))
    """
    a = (key.src_ip, key.src_port or 0)
    b = (key.dst_ip, key.dst_port or 0)
    if a <= b:
        return (a, b, key.proto)
    return (b, a, key.proto)


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

        # Pass 1: requests. Собираем URI по нормализованному pair-key.
        requests_by_pair: dict = {}
        request_objects: list = []
        for key, stream in state.tcp_streams.items():
            if not stream:
                continue
            head = stream[:16]
            # request начинается с "GET ", "POST ", "HEAD " и т.п.
            # — там точно есть пробел в первых 16 байтах.
            if b" " not in head:
                continue
            obj = parse_http_request(stream, body_limit=body_limit)
            if obj is not None:
                request_objects.append((key, obj))
                if obj.uri:
                    requests_by_pair[_norm_pair(key)] = obj.uri

        # Pass 2: responses. Пробрасываем URI из парного request.
        response_objects: list = []
        for key, stream in state.tcp_streams.items():
            if not stream:
                continue
            head = stream[:16]
            if not head.startswith(b"HTTP/"):
                continue
            obj = parse_http_response(stream, body_limit=body_limit)
            if obj is not None:
                if not obj.uri:
                    obj.uri = requests_by_pair.get(_norm_pair(key))
                response_objects.append((key, obj))

        state.http_objects = request_objects + response_objects