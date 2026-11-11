"""Синтетическая TLS-сессия через MemoryBIO для тестов расшифровки.

Никакой сети: клиент и сервер — SSLObject поверх пар MemoryBIO.
Собранные «сырые» байты каждого направления — ровно то, что видно
в TCP-потоке pcap, включая handshake. keylog пишет сам Python ssl
через `SSLContext.keylog_filename`.
"""
from __future__ import annotations

import datetime
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class TlsSession:
    client_raw: bytes
    server_raw: bytes
    keylog_path: Path
    keylog_text: str


def _write_certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path


def make_tls_session(
    tmp_path: Path,
    *,
    tls13: bool = True,
    cipher: str | None = None,
    client_payload: bytes = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    server_payload: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
) -> TlsSession:
    cert_path, key_path = _write_certificate(tmp_path)
    keylog_path = tmp_path / "keys.log"

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.keylog_filename = str(keylog_path)

    version = ssl.TLSVersion.TLSv1_3 if tls13 else ssl.TLSVersion.TLSv1_2
    for ctx in (client_ctx, server_ctx):
        ctx.minimum_version = version
        ctx.maximum_version = version
        if cipher is not None:
            ctx.set_ciphers(cipher)

    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(
        client_in, client_out, server_hostname="localhost",
    )
    server = server_ctx.wrap_bio(server_in, server_out, server_side=True)

    client_raw = bytearray()
    server_raw = bytearray()

    def transfer(source, target) -> bool:
        data = source.read()
        if not data:
            return False
        if target is server_in:
            client_raw.extend(data)
        else:
            server_raw.extend(data)
        target.write(data)
        return True

    def pump(loop) -> None:
        for _ in range(1000):
            moved = False
            for obj in (client, server):
                try:
                    loop(obj)
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLWantWriteError:
                    pass
            if transfer(client_out, server_in):
                moved = True
            if transfer(server_out, client_in):
                moved = True
            if not moved:
                return

    pump(lambda obj: obj.do_handshake())

    def flush() -> None:
        for _ in range(200):
            moved = False
            if transfer(client_out, server_in):
                moved = True
            if transfer(server_out, client_in):
                moved = True
            for obj in (client, server):
                try:
                    obj.read(65536)
                except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                    pass
            if not moved:
                return

    client.write(client_payload)
    flush()
    server.write(server_payload)
    flush()

    return TlsSession(
        client_raw=bytes(client_raw),
        server_raw=bytes(server_raw),
        keylog_path=keylog_path,
        keylog_text=keylog_path.read_text(encoding="utf-8"),
    )
