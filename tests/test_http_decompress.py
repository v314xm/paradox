"""
Тесты распаковки HTTP-тел (gzip/deflate) в _http_body.

Проверяем: gzip, zlib-deflate, raw-deflate, мультикодировку,
битый/обрезанный поток, лимит распакованного размера
(защита от zip-бомбы) и выключение через config.
"""
import gzip
import zlib

from paradox.config import Config
from paradox.detectors._http_body import (
    body_for_scan,
    decoded_body,
    is_text_body,
)
from paradox.http_object import HttpObject

TEXT = b'{"cmd": "$(id); `whoami`", "pad": "' + b"a" * 500 + b'"}'


def _obj(body, content_encoding=None, content_type="application/json"):
    headers = {"content-type": content_type}
    if content_encoding:
        headers["content-encoding"] = content_encoding
    return HttpObject(
        kind="request", method="POST", uri="/api",
        headers=headers, body=body, body_size=len(body),
    )


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def test_plain_body_passthrough():
    obj = _obj(TEXT)
    assert decoded_body(obj, Config()) == TEXT


def test_gzip_body_decoded():
    obj = _obj(gzip.compress(TEXT), "gzip")
    assert decoded_body(obj, Config()) == TEXT


def test_x_gzip_alias():
    obj = _obj(gzip.compress(TEXT), "x-gzip")
    assert decoded_body(obj, Config()) == TEXT


def test_deflate_zlib_wrapped():
    obj = _obj(zlib.compress(TEXT), "deflate")
    assert decoded_body(obj, Config()) == TEXT


def test_deflate_raw():
    obj = _obj(_raw_deflate(TEXT), "deflate")
    assert decoded_body(obj, Config()) == TEXT


def test_multiple_encodings_applied_in_reverse():
    """content-encoding: gzip, deflate — сначала gzip, затем deflate."""
    obj = _obj(zlib.compress(gzip.compress(TEXT)), "gzip, deflate")
    assert decoded_body(obj, Config()) == TEXT


def test_broken_gzip_returns_empty():
    obj = _obj(b"not a gzip stream", "gzip")
    assert decoded_body(obj, Config()) == b""
    assert body_for_scan(obj, Config()) is None


def test_truncated_gzip_decodes_prefix():
    full = gzip.compress(TEXT)
    obj = _obj(full[: len(full) // 2], "gzip")
    decoded = decoded_body(obj, Config())
    assert decoded
    assert TEXT.startswith(decoded)


def test_decompression_limit_stops_zip_bomb():
    bomb = gzip.compress(b"A" * (1024 * 1024))
    config = Config(http_body_max_decoded_bytes=4096)
    decoded = decoded_body(_obj(bomb, "gzip"), config)
    assert len(decoded) == 4096


def test_decompression_can_be_disabled():
    obj = _obj(gzip.compress(TEXT), "gzip")
    config = Config(http_body_decompress=False)
    assert decoded_body(obj, config) == b""


def test_body_for_scan_returns_text_after_gunzip():
    obj = _obj(gzip.compress(TEXT), "gzip")
    payload = body_for_scan(obj, Config())
    assert payload == TEXT


def test_body_for_scan_skips_binary_after_gunzip():
    """gzip разворачивается в случайные байты — не текст, не сканируем."""
    binary = bytes(range(256)) * 8
    obj = _obj(gzip.compress(binary), "gzip",
               content_type="application/octet-stream")
    assert body_for_scan(obj, Config()) is None


def test_body_for_scan_decodes_text_under_octet_stream():
    """content-type врёт: gzip-обёртка JSON'а помечена octet-stream."""
    obj = _obj(gzip.compress(TEXT), None,
               content_type="application/octet-stream")
    assert body_for_scan(obj, Config()) == TEXT


def test_unknown_encoding_not_scanned():
    obj = _obj(b"data", "br")
    assert decoded_body(obj, Config()) == b""


def test_gzip_magic_without_header_decoded():
    """gzip без content-encoding распознаётся по magic 1f 8b."""
    obj = _obj(gzip.compress(TEXT))
    assert decoded_body(obj, Config()) == TEXT


def test_gzip_magic_garbage_falls_back_to_raw():
    obj = _obj(b"\x1f\x8bnot-really-gzip")
    assert decoded_body(obj, Config()) == b"\x1f\x8bnot-really-gzip"


def test_is_text_body_still_treats_compressed_as_binary():
    """http_binary_upload: сжатое тело на проводе — бинарное."""
    obj = _obj(gzip.compress(TEXT), "gzip")
    assert is_text_body(obj, Config()) is False
