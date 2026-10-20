"""
Unit-тесты парсера NBNS.

Эталон — реальный пакет из MTA 2025-06-13 (frame 24):
NBNS-запрос от 10.6.13.133 к broadcast с именем DESKTOP-5AVE44C<20>.
"""
from paradox.nbns_parse import decode_nbns_name, parse_nbns

# --- эталонный NBNS-payload из frame 24 ---
NBNS_FRAME_24 = bytes.fromhex(
    "840d29100001000000000001"
    "20454545464644454c46"
    "4545504641434e44464542464745464445444545444341"
    "0000200001"
    "c00c00200001000493e0000640000a060d85"
)

# --- ожидаемое закодированное имя ---
ENCODED_DESKTOP = bytes.fromhex(
    "454545464644454c46"
    "4545504641434e44464542464745464445444545444341"
)


def test_decode_nbns_name_desktop():
    result = decode_nbns_name(ENCODED_DESKTOP)
    assert result is not None
    name, suffix = result
    assert name == "DESKTOP-5AVE44C"
    assert suffix == 0x20  # Server service


def test_decode_nbns_name_wrong_length():
    assert decode_nbns_name(b"") is None
    assert decode_nbns_name(b"\x00" * 16) is None


def test_decode_nbns_name_invalid_bytes():
    # байты меньше 0x41 — невалидный nibble
    assert decode_nbns_name(b"\x00" * 32) is None


def test_parse_nbns_frame_24():
    result = parse_nbns(NBNS_FRAME_24)
    assert result is not None
    assert result.name == "DESKTOP-5AVE44C"
    assert result.suffix == 0x20
    assert result.name_type == 0x0020  # NB


def test_parse_nbns_too_short():
    assert parse_nbns(b"") is None
    assert parse_nbns(b"\x00" * 4) is None
