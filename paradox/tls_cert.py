"""
Парсер TLS Certificate handshake message из TCP-потока сервера.

Структура:

  Record layer:
    [content_type(1)=0x16] [version(2)] [length(2)] [handshake_msg...]

  Handshake layer:
    [hs_type(1)] [length(3)] [body]

  Certificate body (TLS 1.2):
    [chain_length(3)]
    repeat: [cert_length(3)] [cert_der...]

  Certificate body (TLS 1.3):
    [request_context_length(1)] [request_context]
    [chain_length(3)]
    repeat: [cert_length(3)] [cert_der...]
    [extensions_length(2)] [extensions...]

Проблема: различить TLS 1.2 и 1.3 по префиксу нельзя. Для TLS 1.2
body[0] тоже 0 (старший байт 3-байтовой длины цепочки). Решение —
пробовать оба layout'а и брать первый, где DER-парсинг успешен.
"""
from __future__ import annotations

from paradox.x509_cert import Certificate, parse_certificate
from paradox.x509_der import DerError


TLS_RECORD_HANDSHAKE = 0x16
HS_TYPE_CERTIFICATE = 11


def parse_certificate_from_stream(stream: bytes) -> Certificate | None:
    """Извлечь leaf-сертификат из TCP-потока сервер→клиент.

    Возвращает None, если TLS-хендшейк не найден или битый.
    Не бросает исключений на входных данных.
    """
    pos = 0
    while pos + 5 <= len(stream):
        content_type = stream[pos]
        if content_type != TLS_RECORD_HANDSHAKE:
            return None

        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        rec_start = pos + 5
        rec_end = rec_start + length
        if rec_end > len(stream):
            return None

        record = stream[rec_start:rec_end]
        for cert_der in _find_certificate_candidates(record):
            try:
                return parse_certificate(cert_der)
            except DerError:
                continue

        pos = rec_end

    return None


def _find_certificate_candidates(record: bytes) -> list[bytes]:
    """Все возможные DER-байты leaf-сертификата из одного record.

    Возвращает список кандидатов (сначала TLS 1.3, потом TLS 1.2).
    Вызывающий код пробует каждый через parse_certificate и берёт
    первый валидный.
    """
    pos = 0
    while pos + 4 <= len(record):
        hs_type = record[pos]
        hs_len = int.from_bytes(record[pos + 1:pos + 4], "big")
        body_start = pos + 4
        body_end = body_start + hs_len
        if body_end > len(record):
            return []

        if hs_type == HS_TYPE_CERTIFICATE:
            body = record[body_start:body_end]
            candidates: list[bytes] = []
            c13 = _try_extract_tls13(body)
            if c13 is not None:
                candidates.append(c13)
            c12 = _try_extract_tls12(body)
            if c12 is not None:
                candidates.append(c12)
            return candidates

        pos = body_end

    return []


def _try_extract_tls12(body: bytes) -> bytes | None:
    """TLS 1.2 layout: [chain_len(3)] [cert_len(3)] [der]..."""
    if len(body) < 6:
        return None
    chain_len = int.from_bytes(body[0:3], "big")
    if 3 + chain_len > len(body):
        return None
    cert_len = int.from_bytes(body[3:6], "big")
    if cert_len == 0 or 6 + cert_len > len(body):
        return None
    return body[6:6 + cert_len]


def _try_extract_tls13(body: bytes) -> bytes | None:
    """TLS 1.3 layout: [ctx_len(1)=0] [chain_len(3)] [cert_len(3)] [der]..."""
    if len(body) < 7:
        return None
    if body[0] != 0:
        return None
    chain_len = int.from_bytes(body[1:4], "big")
    if 4 + chain_len > len(body):
        return None
    cert_len = int.from_bytes(body[4:7], "big")
    if cert_len == 0 or 7 + cert_len > len(body):
        return None
    return body[7:7 + cert_len]
