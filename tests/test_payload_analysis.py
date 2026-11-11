"""Разбор payload'а: multipart, IOC, вложенные файлы, PE/ZIP."""
import base64
import io
import zipfile

from paradox.config import Config
from paradox.http_object import HttpObject
from paradox.payload_analysis import (
    analyze_payload,
    entropy,
    extract_iocs,
    find_embedded,
    split_multipart,
    strings,
)
from paradox.payload_excerpt import decode_sample, make_sample


def _multipart(field_value: bytes, file_data: bytes) -> bytes:
    return (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="appeal_id"\r\n\r\n'
        + field_value
        + b"\r\n"
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="me"; '
        b'filename="me.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + file_data
        + b"\r\n--boundary--\r\n"
    )


def test_split_multipart_fields_and_files():
    body = _multipart(b"9e35ed-00e9", b"\x89PNG\r\n\x1a\nfile")

    parts = split_multipart(body)

    assert [p.kind for p in parts] == ["field", "file"]
    assert parts[0].name == "appeal_id"
    assert parts[0].data == b"9e35ed-00e9"
    assert parts[1].filename == "me.bin"
    assert parts[1].data == b"\x89PNG\r\n\x1a\nfile"
    assert body[parts[1].offset:parts[1].offset + 8] == b"\x89PNG\r\n\x1a\n"


def test_multipart_file_beyond_main_excerpt_is_captured():
    field_value = b"a" * (70 * 1024)
    file_data = b"\x89PNG\r\n\x1a\n" + b"pixels" * 100
    body = _multipart(field_value, file_data)
    obj = HttpObject(
        kind="request",
        method="POST",
        uri="/upload",
        headers={
            "host": "victim.local",
            "content-type": "multipart/form-data; boundary=boundary",
        },
        body=body,
    )

    sample = make_sample(
        body, obj=obj, direction="request",
        config=Config(payload_excerpt_bytes=64 * 1024),
    )

    parts = sample["parts"]
    file_part = next(part for part in parts if part["kind"] == "file")
    assert file_part["offset"] > 64 * 1024
    assert base64.b64decode(file_part["excerpt_b64"]).startswith(
        b"\x89PNG\r\n\x1a\n",
    )
    # Общая выдержка по-прежнему первые 64 КБ — файла в ней нет.
    assert b"\x89PNG" not in decode_sample(sample)


def test_analyze_detects_type_hashes_and_iocs():
    payload = (
        b"POST http://evil.example/drop?x=1\n"
        b"host=10.0.0.5 mail=bad@evil.example\n"
        b"sha256=" + b"a" * 64
    )

    analysis = analyze_payload(payload)

    assert analysis.file_kind == "text"
    assert len(analysis.sha256) == 64
    assert "http://evil.example/drop?x=1" in analysis.urls
    assert "evil.example" in analysis.domains
    assert "10.0.0.5" in analysis.ips
    assert "bad@evil.example" in analysis.emails
    assert len(analysis.hashes) == 1


def test_extract_iocs_ignores_invalid_ips():
    iocs = extract_iocs("1.2.3.4 999.1.1.1 example.org")

    assert iocs["ips"] == ["1.2.3.4"]
    assert "example.org" in iocs["domains"]


def test_entropy_and_strings():
    assert entropy(b"\x00" * 64) == 0.0
    assert entropy(bytes(range(256))) > 7.9
    assert "hello" in strings(b"\x00hello\x00\x00world")
    assert "wide" in strings("wide".encode("utf-16-le"))


def _minimal_pe() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff:coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2:coff + 4] = (1).to_bytes(2, "little")
    data[coff + 16:coff + 18] = (0xE0).to_bytes(2, "little")
    optional = coff + 20
    data[optional:optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 68:optional + 70] = (3).to_bytes(2, "little")
    section = optional + 0xE0
    data[section:section + 8] = b".text\0\0\0"
    data[section + 8:section + 12] = (0x100).to_bytes(4, "little")
    data[section + 16:section + 20] = (0x100).to_bytes(4, "little")
    data[section + 20:section + 24] = (0x200).to_bytes(4, "little")
    data[0x200:0x300] = b"\x90" * 0x100
    return bytes(data)


def test_find_embedded_pe_and_zip():
    pe = _minimal_pe()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", "hi")
    zipped = buffer.getvalue()
    data = b"prefix" + pe + zipped

    found = find_embedded(data)

    kinds = {item.kind for item in found}
    assert "PE" in kinds and "ZIP" in kinds
    pe_item = next(item for item in found if item.kind == "PE")
    assert pe_item.detail["magic"] == "PE32"
    assert pe_item.detail["sections"][0]["name"] == ".text"
    zip_item = next(item for item in found if item.kind == "ZIP")
    assert zip_item.detail["entries"] == ["a.txt"]
    assert zip_item.size == len(zipped)


def test_analyze_payload_includes_parts():
    body = _multipart(b"x", b"file")

    analysis = analyze_payload(body)

    assert [part.kind for part in analysis.parts] == ["field", "file"]
    assert analysis.file_kind == "text"
