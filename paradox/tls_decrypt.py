"""Расшифровка TLS-потока по SSLKEYLOGFILE.

Задача — получить открытый текст прикладного уровня из пары
направлений TCP (client→server и server→client), не строя полный
TLS-стек:

  - из ClientHello берём client_random, из ServerHello — server_random
    и cipher suite (и признак TLS 1.3);
  - по client_random находим секрет в keylog;
  - для TLS 1.2 выводим key block и расшифровываем записи после
    ChangeCipherSpec; для TLS 1.3 — записи с traffic secret, а
    зашифрованный handshake пропускаем (он под другими ключами).

Ограничения: только AEAD-сьюты (AES-GCM, ChaCha20-Poly1305), без
CBC; без renegotiation; без 0-RTT. Если ключа в keylog нет, поток
остаётся закрытым — это видно в счётчике `tls_streams_without_keylog`.
"""
from __future__ import annotations

from dataclasses import dataclass

from paradox.tls_keys import (
    CIPHER_SUITES,
    TLS13_SUITES,
    KeyLog,
    TrafficKeys,
    decrypt_tls12_record,
    decrypt_tls13_record,
    derive_tls12_keys,
    derive_tls13_keys,
)

TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPLICATION_DATA = 23

TLS_HANDSHAKE_CLIENT_HELLO = 1
TLS_HANDSHAKE_SERVER_HELLO = 2

_EXT_SUPPORTED_VERSIONS = 0x002B
_TLS13_VERSION = 0x0304
_MAX_RECORD_LEN = 16384 + 2048
_MAX_RECORDS = 200_000


@dataclass(frozen=True)
class TlsRecord:
    content_type: int
    version: bytes
    payload: bytes
    truncated: bool = False


@dataclass
class TlsHandshakeInfo:
    client_random: bytes | None = None
    server_random: bytes | None = None
    cipher_suite: int | None = None
    tls13: bool = False


@dataclass
class TlsDecryptResult:
    client_plaintext: bytes = b""
    server_plaintext: bytes = b""
    client_random: bytes | None = None
    server_random: bytes | None = None
    cipher_suite: int | None = None
    suite_name: str | None = None
    tls13: bool = False
    decrypted_records: int = 0
    failed_records: int = 0
    error: str | None = None


def iter_tls_records(stream: bytes):
    """Идти по TLS-записям; на не-TLS или мусоре — остановиться."""
    pos = 0
    count = 0
    while pos + 5 <= len(stream) and count < _MAX_RECORDS:
        content_type = stream[pos]
        if content_type not in (
            TLS_CONTENT_CHANGE_CIPHER_SPEC,
            TLS_CONTENT_ALERT,
            TLS_CONTENT_HANDSHAKE,
            TLS_CONTENT_APPLICATION_DATA,
        ):
            return
        version = stream[pos + 1:pos + 3]
        if not version or version[0] != 0x03:
            return
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        if length > _MAX_RECORD_LEN:
            return
        start = pos + 5
        end = start + length
        if end > len(stream):
            yield TlsRecord(content_type, version, stream[start:], True)
            return
        yield TlsRecord(content_type, version, stream[start:end])
        pos = end
        count += 1


def _find_handshake(
    stream: bytes, message_type: int,
) -> bytes | None:
    """Тело первого handshake-сообщения нужного типа (до CCS)."""
    buffer = b""
    for record in iter_tls_records(stream):
        if record.content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC:
            return None
        if record.content_type != TLS_CONTENT_HANDSHAKE:
            if record.truncated:
                return None
            continue
        buffer += record.payload
        while len(buffer) >= 4:
            hs_type = buffer[0]
            hs_len = int.from_bytes(buffer[1:4], "big")
            if len(buffer) < 4 + hs_len:
                break
            body = buffer[4:4 + hs_len]
            buffer = buffer[4 + hs_len:]
            if hs_type == message_type:
                return body
    return None


def _parse_server_hello(body: bytes) -> tuple[bytes, int, bool] | None:
    """(server_random, cipher_suite, tls13) из тела ServerHello."""
    if len(body) < 35:
        return None
    random = body[2:34]
    pos = 34
    session_id_len = body[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(body):
        return None
    cipher_suite = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    if pos < len(body):
        compression_len = body[pos]
        pos += 1 + compression_len
    tls13 = cipher_suite in TLS13_SUITES
    if pos + 2 <= len(body):
        ext_total = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type == _EXT_SUPPORTED_VERSIONS and ext:
                if int.from_bytes(ext[1:3], "big") == _TLS13_VERSION:
                    tls13 = True
    return random, cipher_suite, tls13


def parse_handshake_info(
    client_stream: bytes, server_stream: bytes,
) -> TlsHandshakeInfo:
    info = TlsHandshakeInfo()
    client_hello = _find_handshake(
        client_stream, TLS_HANDSHAKE_CLIENT_HELLO,
    )
    if client_hello is not None and len(client_hello) >= 34:
        info.client_random = client_hello[2:34]
    server_hello = _find_handshake(
        server_stream, TLS_HANDSHAKE_SERVER_HELLO,
    )
    if server_hello is not None:
        parsed = _parse_server_hello(server_hello)
        if parsed is not None:
            info.server_random, info.cipher_suite, info.tls13 = parsed
    return info


def _decrypt_tls12_direction(
    stream: bytes, keys: TrafficKeys,
) -> tuple[bytes, int, int]:
    out = bytearray()
    decrypted = 0
    failed = 0
    active = False
    seq = 0
    for record in iter_tls_records(stream):
        if not active:
            if record.content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC:
                active = True
                seq = 0
            continue
        try:
            plain = decrypt_tls12_record(
                keys, seq, record.content_type, record.version,
                record.payload,
            )
        except Exception:
            failed += 1
        else:
            decrypted += 1
            if record.content_type == TLS_CONTENT_APPLICATION_DATA:
                out.extend(plain)
        seq += 1
    return bytes(out), decrypted, failed


def _decrypt_tls13_direction(
    stream: bytes,
    app_keys: TrafficKeys,
    handshake_keys: TrafficKeys | None,
) -> tuple[bytes, int, int]:
    out = bytearray()
    decrypted = 0
    failed = 0
    app_seq = 0
    hs_seq = 0
    for record in iter_tls_records(stream):
        if record.content_type != TLS_CONTENT_APPLICATION_DATA:
            continue
        header = (
            bytes([record.content_type])
            + record.version
            + len(record.payload).to_bytes(2, "big")
        )
        try:
            inner_type, plain = decrypt_tls13_record(
                app_keys, app_seq, header, record.payload,
            )
        except Exception:
            # Зашифрованный handshake/new session ticket под своими
            # ключами: пробуем их, чтобы не сдвинуть app-счётчик.
            if handshake_keys is not None:
                try:
                    decrypt_tls13_record(
                        handshake_keys, hs_seq, header, record.payload,
                    )
                except Exception:
                    failed += 1
                else:
                    hs_seq += 1
            else:
                failed += 1
            continue
        app_seq += 1
        decrypted += 1
        if inner_type == TLS_CONTENT_APPLICATION_DATA:
            out.extend(plain)
    return bytes(out), decrypted, failed


def decrypt_tls_pair(
    client_stream: bytes,
    server_stream: bytes,
    keylog: KeyLog,
) -> TlsDecryptResult:
    """Расшифровать прикладной трафик пары TLS-потоков."""
    result = TlsDecryptResult()
    info = parse_handshake_info(client_stream, server_stream)
    result.client_random = info.client_random
    result.server_random = info.server_random
    result.cipher_suite = info.cipher_suite
    result.tls13 = info.tls13

    if info.client_random is None or info.cipher_suite is None:
        result.error = "no_handshake"
        return result
    suite = CIPHER_SUITES.get(info.cipher_suite)
    result.suite_name = suite.name if suite else None
    if suite is None:
        result.error = "unsupported_cipher"
        return result

    if info.tls13:
        client_secret = keylog.traffic_secret(
            "CLIENT_TRAFFIC_SECRET_0", info.client_random,
        )
        server_secret = keylog.traffic_secret(
            "SERVER_TRAFFIC_SECRET_0", info.client_random,
        )
        if client_secret is None or server_secret is None:
            result.error = "no_keylog_entry"
            return result
        client_keys = derive_tls13_keys(client_secret, info.cipher_suite)
        server_keys = derive_tls13_keys(server_secret, info.cipher_suite)
        client_hs_secret = keylog.traffic_secret(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET", info.client_random,
        )
        server_hs_secret = keylog.traffic_secret(
            "SERVER_HANDSHAKE_TRAFFIC_SECRET", info.client_random,
        )
        client_hs_keys = (
            derive_tls13_keys(client_hs_secret, info.cipher_suite)
            if client_hs_secret else None
        )
        server_hs_keys = (
            derive_tls13_keys(server_hs_secret, info.cipher_suite)
            if server_hs_secret else None
        )
        if client_keys is None or server_keys is None:
            result.error = "unsupported_cipher"
            return result

        client_plain, c_ok, c_fail = _decrypt_tls13_direction(
            client_stream, client_keys, client_hs_keys,
        )
        server_plain, s_ok, s_fail = _decrypt_tls13_direction(
            server_stream, server_keys, server_hs_keys,
        )
    else:
        master_secret = keylog.master_secret(info.client_random)
        if master_secret is None or info.server_random is None:
            result.error = "no_keylog_entry"
            return result
        derived = derive_tls12_keys(
            master_secret,
            info.client_random,
            info.server_random,
            info.cipher_suite,
        )
        if derived is None:
            result.error = "unsupported_cipher"
            return result
        client_keys, server_keys = derived
        client_plain, c_ok, c_fail = _decrypt_tls12_direction(
            client_stream, client_keys,
        )
        server_plain, s_ok, s_fail = _decrypt_tls12_direction(
            server_stream, server_keys,
        )

    result.client_plaintext = client_plain
    result.server_plaintext = server_plain
    result.decrypted_records = c_ok + s_ok
    result.failed_records = c_fail + s_fail
    if result.decrypted_records == 0:
        result.error = "decrypt_failed"
    return result


def looks_like_tls(stream: bytes) -> bool:
    return (
        len(stream) >= 5
        and stream[0] in (
            TLS_CONTENT_HANDSHAKE,
            TLS_CONTENT_APPLICATION_DATA,
        )
        and stream[1] == 0x03
    )


def is_tls_client_hello(stream: bytes) -> bool:
    return (
        len(stream) >= 6
        and stream[0] == TLS_CONTENT_HANDSHAKE
        and stream[5] == TLS_HANDSHAKE_CLIENT_HELLO
    )


def is_tls_server_hello(stream: bytes) -> bool:
    return (
        len(stream) >= 6
        and stream[0] == TLS_CONTENT_HANDSHAKE
        and stream[5] == TLS_HANDSHAKE_SERVER_HELLO
    )
