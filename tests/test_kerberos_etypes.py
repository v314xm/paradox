"""TGS-REQ: etypes и полный SPN для Kerberoasting."""
from paradox.kerberos_parse import parse_kerberos


def _len(value: int) -> bytes:
    return bytes([value]) if value < 0x80 else bytes([0x81, value])


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _ctx(number: int, value: bytes) -> bytes:
    return _tlv(0xA0 | number, value)


def _principal(*parts: str) -> bytes:
    name_string = _tlv(
        0x30, b"".join(_tlv(0x1B, p.encode()) for p in parts),
    )
    return _tlv(
        0x30,
        _ctx(0, _tlv(0x02, b"\x02"))
        + _ctx(1, name_string),
    )


def _tgs_req(etypes: tuple[int, ...]) -> bytes:
    body = _ctx(3, _principal("HTTP", "web.corp.local")) + _ctx(
        8,
        _tlv(
            0x30,
            b"".join(_tlv(0x02, bytes([etype])) for etype in etypes),
        ),
    )
    return _tlv(
        0x6C,
        _tlv(
            0x30,
            _ctx(1, _tlv(0x02, b"\x05"))
            + _ctx(2, _tlv(0x02, b"\x0c"))
            + _ctx(4, _tlv(0x30, body)),
        ),
    )


def test_tgs_req_exposes_spn_and_etypes():
    info = parse_kerberos(_tgs_req((23, 18)))

    assert info is not None
    assert info.msg_type == 12
    assert info.sname == "HTTP"
    assert info.spn == "HTTP/web.corp.local"
    assert info.etypes == (23, 18)


def test_principal_without_realm_keeps_spn():
    info = parse_kerberos(_tgs_req((17,)))

    assert info is not None
    assert info.spn == "HTTP/web.corp.local"
    assert info.etypes == (17,)
