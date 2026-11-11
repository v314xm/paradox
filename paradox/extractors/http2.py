"""HTTP2Extractor — HTTP/2 из склеенных потоков и из-под TLS.

Два источника:

  - открытый h2c: поток клиента начинается с префейса
    `PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`, сервер отвечает кадром
    SETTINGS;
  - h2 поверх TLS: если задан `Config.tls_keylog_path`, потоки
    расшифровываются по SSLKEYLOGFILE (`tls_decrypt.py`), дальше
    разбор тот же.

Мультиплексирование учитывается: запросы и ответы сопоставляются по
stream id внутри одной TCP-пары, поэтому ответ получает URI запроса
(нужно FileCarve и отчёту).

Только HTTP/2-объекты: HTTP/1 остаётся за HTTPObjectExtractor.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.http2_parse import HTTP2_PREFACE, parse_http2_stream
from paradox.http_object import (
    DEFAULT_BODY_LIMIT,
    DEFAULT_MAX_MESSAGES_PER_STREAM,
    HttpObject,
    iter_http_requests,
    iter_http_responses,
)
from paradox.models import CaptureState
from paradox.tls_decrypt import (
    decrypt_tls_pair,
    is_tls_client_hello,
    is_tls_server_hello,
    looks_like_tls,
)
from paradox.tls_keys import load_keylog


def _pair_key(key) -> tuple:
    a = (key.src_ip, key.src_port or 0)
    b = (key.dst_ip, key.dst_port or 0)
    if a <= b:
        return (a, b, key.proto)
    return (b, a, key.proto)


def _to_http_object(message) -> HttpObject:
    return HttpObject(
        kind=message.kind,
        method=message.method,
        uri=message.uri,
        version="2",
        status_code=message.status_code,
        headers=message.headers,
        body=message.body,
        body_size=message.body_size,
        truncated=message.truncated,
    )


class HTTP2Extractor:
    name = "http2"
    layer = 1

    def process(self, record, state: CaptureState) -> None:
        """Per-packet обработка не нужна — no-op."""
        return

    def run_post_extract(
        self,
        state: CaptureState,
        config: Config,
    ) -> None:
        if not state.tcp_streams:
            return
        if not getattr(config, "http2_enabled", True):
            return

        body_limit = getattr(
            config, "http_object_body_limit", DEFAULT_BODY_LIMIT,
        )
        max_messages = getattr(
            config,
            "http_object_max_messages_per_stream",
            DEFAULT_MAX_MESSAGES_PER_STREAM,
        )

        keylog = None
        keylog_path = getattr(config, "tls_keylog_path", None)
        if keylog_path:
            try:
                keylog = load_keylog(keylog_path)
            except Exception:
                state.tls_decrypt_errors += 1

        groups: dict[tuple, list] = {}
        for key, stream in state.tcp_streams.items():
            if not stream or key.proto != "tcp":
                continue
            groups.setdefault(_pair_key(key), []).append((key, stream))

        for entries in groups.values():
            if len(entries) > 2:
                entries = entries[:2]
            client_entry = self._client_entry(entries)
            if client_entry is None:
                continue
            client_key, client_stream = client_entry
            server_entry = next(
                (entry for entry in entries if entry[0] is not client_key),
                None,
            )
            server_key = server_entry[0] if server_entry else None
            server_stream = server_entry[1] if server_entry else b""

            tls = looks_like_tls(client_stream) or looks_like_tls(
                server_stream,
            )
            if tls:
                if keylog is None:
                    state.tls_streams_without_keylog += 1
                    continue
                result = decrypt_tls_pair(
                    client_stream, server_stream, keylog,
                )
                if result.error is not None:
                    state.tls_decrypt_errors += 1
                    continue
                state.tls_decrypted_streams += 1
                state.tls_decrypted_records += result.decrypted_records
                client_plaintext = result.client_plaintext
                server_plaintext = result.server_plaintext
            else:
                client_plaintext = client_stream
                server_plaintext = server_stream

            requests = parse_http2_stream(
                client_plaintext,
                body_limit=body_limit,
                max_messages=max_messages,
            )
            responses = parse_http2_stream(
                server_plaintext,
                body_limit=body_limit,
                max_messages=max_messages,
            )
            if not (requests.is_http2 or responses.is_http2):
                # Расшифрованный HTTPS/1.1: HTTPObjectExtractor такой
                # поток не видел (он зашифрован), разбираем здесь.
                if tls:
                    state.tls_http1_objects += self._add_http1_objects(
                        state, client_key, server_key,
                        client_plaintext, server_plaintext,
                        body_limit, max_messages,
                    )
                continue

            state.h2_connections += 1
            state.h2_frames += requests.frames + responses.frames
            state.h2_parse_errors += requests.errors + responses.errors
            state.h2_streams += len(requests.messages)

            uris = {
                message.stream_id: message.uri
                for message in requests.messages
                if message.uri
            }
            state.http_objects.extend(
                (client_key, _to_http_object(message))
                for message in requests.messages
            )
            if server_key is not None:
                for message in responses.messages:
                    if message.uri is None:
                        message.uri = uris.get(message.stream_id)
                    state.http_objects.append(
                        (server_key, _to_http_object(message)),
                    )

    @staticmethod
    def _add_http1_objects(
        state: CaptureState,
        client_key,
        server_key,
        client_plaintext: bytes,
        server_plaintext: bytes,
        body_limit: int,
        max_messages: int,
    ) -> int:
        """HTTP/1.1 из расшифрованного TLS — как HTTPObjectExtractor."""
        requests = list(iter_http_requests(
            client_plaintext,
            body_limit=body_limit,
            max_messages=max_messages,
        ))
        responses = list(iter_http_responses(
            server_plaintext,
            body_limit=body_limit,
            max_messages=max_messages,
        ))
        uris = [obj.uri for obj in requests if obj.uri]
        for index, obj in enumerate(responses):
            if obj.uri is None and index < len(uris):
                obj.uri = uris[index]

        state.http_objects.extend((client_key, obj) for obj in requests)
        if server_key is not None:
            state.http_objects.extend(
                (server_key, obj) for obj in responses
            )
        return len(requests) + len(responses)

    @staticmethod
    def _client_entry(entries: list):
        """Определить направление клиент→сервер."""
        for entry in entries:
            if entry[1].startswith(HTTP2_PREFACE):
                return entry
        for entry in entries:
            if is_tls_client_hello(entry[1]):
                return entry
        for entry in entries:
            if is_tls_server_hello(entry[1]):
                continue
            if looks_like_tls(entry[1]):
                # TLS без видимого ClientHello — берём меньший dst_port
                # (серверный), это направление клиента.
                return min(entries, key=lambda item: item[0].dst_port or 0)
        if not entries:
            return None
        return min(entries, key=lambda item: item[0].dst_port or 0)
