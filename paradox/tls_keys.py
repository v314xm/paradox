"""Ключи TLS из SSLKEYLOGFILE и AEAD-расшифровка записей.

Формат keylog (NSS, его пишут Chrome, Firefox, OpenSSL, Python ssl):

    CLIENT_RANDOM <client_random> <master_secret>        # TLS <= 1.2
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>     # TLS 1.3
    SERVER_TRAFFIC_SECRET_0 <client_random> <secret>

TLS 1.2: key block выводится PRF (RFC 5246) из master_secret,
client_random и server_random. Поддержаны AEAD-сьюты AES-GCM и
ChaCha20-Poly1305; CBC-сьюты не расшифровываются.

TLS 1.3: из traffic secret выводятся key/iv через HKDF-Expand-Label
(RFC 8446). Нужен только тип сьюта (AES-128/256-GCM, ChaCha20).

Почему keylog, а не ECDHE: shared secret по трафику не восстановить,
а keylog отдаёт готовые секреты — это единственный практичный способ
разобрать TLS в офлайн-триаже.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

AEAD_TAG_LEN = 16
_MAX_KEYLOG_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True)
class CipherSuite:
    name: str
    tls13: bool
    aead: str          # "aes128gcm" | "aes256gcm" | "chacha20"
    hash_name: str     # "sha256" | "sha384"
    key_len: int
    iv_len: int        # TLS 1.2 GCM — 4 (salt), иначе 12


CIPHER_SUITES: dict[int, CipherSuite] = {
    # TLS 1.2, AES-GCM (RFC 5288/5289)
    0x009C: CipherSuite(
        "TLS_RSA_WITH_AES_128_GCM_SHA256", False, "aes128gcm", "sha256", 16, 4,
    ),
    0x009D: CipherSuite(
        "TLS_RSA_WITH_AES_256_GCM_SHA384", False, "aes256gcm", "sha384", 32, 4,
    ),
    0x009E: CipherSuite(
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0x009F: CipherSuite(
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0x00A0: CipherSuite(
        "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0x00A1: CipherSuite(
        "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0x00A2: CipherSuite(
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0x00A3: CipherSuite(
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0x00A4: CipherSuite(
        "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0x00A5: CipherSuite(
        "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0x00A6: CipherSuite(
        "TLS_DH_anon_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0x00A7: CipherSuite(
        "TLS_DH_anon_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    # TLS 1.2, ECDHE/ECDH AES-GCM
    0xC02B: CipherSuite(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0xC02C: CipherSuite(
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0xC02D: CipherSuite(
        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0xC02E: CipherSuite(
        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0xC02F: CipherSuite(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0xC030: CipherSuite(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    0xC031: CipherSuite(
        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", False,
        "aes128gcm", "sha256", 16, 4,
    ),
    0xC032: CipherSuite(
        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", False,
        "aes256gcm", "sha384", 32, 4,
    ),
    # TLS 1.2, ChaCha20-Poly1305 (RFC 7905)
    0xCCA8: CipherSuite(
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", False,
        "chacha20", "sha256", 32, 12,
    ),
    0xCCA9: CipherSuite(
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", False,
        "chacha20", "sha256", 32, 12,
    ),
    0xCCAA: CipherSuite(
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", False,
        "chacha20", "sha256", 32, 12,
    ),
    # TLS 1.3 (RFC 8446)
    0x1301: CipherSuite(
        "TLS_AES_128_GCM_SHA256", True, "aes128gcm", "sha256", 16, 12,
    ),
    0x1302: CipherSuite(
        "TLS_AES_256_GCM_SHA384", True, "aes256gcm", "sha384", 32, 12,
    ),
    0x1303: CipherSuite(
        "TLS_CHACHA20_POLY1305_SHA256", True, "chacha20", "sha256", 32, 12,
    ),
}

TLS13_SUITES = frozenset({
    suite_id for suite_id, suite in CIPHER_SUITES.items() if suite.tls13
})


@dataclass(frozen=True)
class TrafficKeys:
    suite: CipherSuite
    key: bytes
    iv: bytes

    @property
    def tls13(self) -> bool:
        return self.suite.tls13


@dataclass
class KeyLog:
    """Секреты из SSLKEYLOGFILE, проиндексированные по client_random."""

    master_secrets: dict[bytes, bytes]
    secrets: dict[tuple[str, bytes], bytes]

    def __bool__(self) -> bool:
        return bool(self.master_secrets or self.secrets)

    def master_secret(self, client_random: bytes) -> bytes | None:
        return self.master_secrets.get(client_random)

    def traffic_secret(
        self, label: str, client_random: bytes,
    ) -> bytes | None:
        return self.secrets.get((label, client_random))


def _decode_hex(value: str) -> bytes | None:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def parse_keylog(text: str) -> KeyLog:
    """Разобрать SSLKEYLOGFILE. Битые строки пропускаются."""
    master_secrets: dict[bytes, bytes] = {}
    secrets: dict[tuple[str, bytes], bytes] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, client_random_hex, secret_hex = parts
        client_random = _decode_hex(client_random_hex)
        secret = _decode_hex(secret_hex)
        if client_random is None or secret is None:
            continue
        if label == "CLIENT_RANDOM":
            master_secrets[client_random] = secret
        else:
            secrets[(label, client_random)] = secret
    return KeyLog(master_secrets=master_secrets, secrets=secrets)


def load_keylog(path: str | Path) -> KeyLog:
    """Прочитать keylog-файл. Ошибки чтения — исключением."""
    file_path = Path(path)
    if file_path.stat().st_size > _MAX_KEYLOG_SIZE:
        raise ValueError(f"keylog слишком большой: {file_path}")
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return parse_keylog(text)


# ---------------------------------------------------------------------
# TLS 1.2 PRF и TLS 1.3 HKDF-Expand-Label
# ---------------------------------------------------------------------

def _p_hash(
    hash_name: str, secret: bytes, seed: bytes, length: int,
) -> bytes:
    out = b""
    a = hmac.new(secret, seed, hash_name).digest()
    while len(out) < length:
        out += hmac.new(secret, a + seed, hash_name).digest()
        a = hmac.new(secret, a, hash_name).digest()
    return out[:length]


def tls12_prf(
    secret: bytes,
    label: bytes,
    seed: bytes,
    length: int,
    hash_name: str,
) -> bytes:
    return _p_hash(hash_name, secret, label + seed, length)


def _hkdf_expand(
    hash_name: str, prk: bytes, info: bytes, length: int,
) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(
            prk, block + info + bytes([counter]), hash_name,
        ).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(
    hash_name: str,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return _hkdf_expand(hash_name, secret, info, length)


def derive_tls12_keys(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    suite_id: int,
) -> tuple[TrafficKeys, TrafficKeys] | None:
    """(client_keys, server_keys) для TLS 1.2 или None."""
    suite = CIPHER_SUITES.get(suite_id)
    if suite is None or suite.tls13:
        return None

    block_len = 2 * suite.key_len + 2 * suite.iv_len
    key_block = tls12_prf(
        master_secret,
        b"key expansion",
        server_random + client_random,
        block_len,
        suite.hash_name,
    )
    pos = 0
    client_key = key_block[pos:pos + suite.key_len]
    pos += suite.key_len
    server_key = key_block[pos:pos + suite.key_len]
    pos += suite.key_len
    client_iv = key_block[pos:pos + suite.iv_len]
    pos += suite.iv_len
    server_iv = key_block[pos:pos + suite.iv_len]
    return (
        TrafficKeys(suite=suite, key=client_key, iv=client_iv),
        TrafficKeys(suite=suite, key=server_key, iv=server_iv),
    )


def derive_tls13_keys(
    traffic_secret: bytes,
    suite_id: int,
) -> TrafficKeys | None:
    suite = CIPHER_SUITES.get(suite_id)
    if suite is None or not suite.tls13:
        return None
    key = hkdf_expand_label(
        suite.hash_name, traffic_secret, b"key", b"", suite.key_len,
    )
    iv = hkdf_expand_label(
        suite.hash_name, traffic_secret, b"iv", b"", suite.iv_len,
    )
    return TrafficKeys(suite=suite, key=key, iv=iv)


# ---------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------

def _xor_nonce(iv: bytes, seq: int) -> bytes:
    padded = b"\x00" * (len(iv) - 8) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, padded, strict=True))


def _aead_decrypt(keys: TrafficKeys, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    if keys.suite.aead == "chacha20":
        cipher = ChaCha20Poly1305(keys.key)
    else:
        cipher = AESGCM(keys.key)
    return cipher.decrypt(nonce, data, aad)


def decrypt_tls12_record(
    keys: TrafficKeys,
    seq: int,
    content_type: int,
    version: bytes,
    fragment: bytes,
) -> bytes:
    """Расшифровать запись TLS 1.2 (fragment — как на проводе)."""
    if keys.suite.aead == "chacha20":
        nonce = _xor_nonce(keys.iv, seq)
        ciphertext = fragment
        plain_len = len(ciphertext) - AEAD_TAG_LEN
    else:
        if len(fragment) < 8 + AEAD_TAG_LEN:
            raise ValueError("слишком короткая GCM-запись")
        nonce = keys.iv + fragment[:8]
        ciphertext = fragment[8:]
        plain_len = len(ciphertext) - AEAD_TAG_LEN
    if plain_len < 0:
        raise ValueError("слишком короткая запись")
    aad = (
        seq.to_bytes(8, "big")
        + bytes([content_type])
        + version
        + plain_len.to_bytes(2, "big")
    )
    return _aead_decrypt(keys, nonce, ciphertext, aad)


def decrypt_tls13_record(
    keys: TrafficKeys,
    seq: int,
    header: bytes,
    fragment: bytes,
) -> tuple[int, bytes]:
    """Расшифровать запись TLS 1.3 → (inner_content_type, payload)."""
    nonce = _xor_nonce(keys.iv, seq)
    plain = _aead_decrypt(keys, nonce, fragment, header)
    end = len(plain)
    while end and plain[end - 1] == 0:
        end -= 1
    if end == 0:
        raise ValueError("пустая запись TLS 1.3")
    return plain[end - 1], plain[:end - 1]
