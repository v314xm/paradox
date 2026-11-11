"""DCE/RPC-парсер: BIND DRSUAPI, REQUEST opnum, naming context."""
import struct

from paradox.dcerpc_parse import (
    DRSUAPI_UUID,
    extract_naming_contexts,
    opnum_name,
    parse_dcerpc_pdu,
    scan_drsuapi,
    uuid_from_bytes,
    uuid_to_bytes,
)

SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ab"
NDR_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"


def _header(
    ptype: int,
    body: bytes,
    *,
    call_id: int = 1,
    flags: int = 3,
    auth: bytes = b"",
) -> bytes:
    frag_length = 16 + len(body) + len(auth)
    return (
        struct.pack(
            "<BBBB4sHHI",
            5, 0, ptype, flags, b"\x10\x00\x00\x00",
            frag_length, len(auth), call_id,
        )
        + body
        + auth
    )


def _context(
    context_id: int,
    uuid: str,
    version: tuple[int, int] = (4, 0),
) -> bytes:
    return (
        struct.pack("<HBB", context_id, 1, 0)
        + uuid_to_bytes(uuid)
        + struct.pack("<HH", *version)
        + uuid_to_bytes(NDR_UUID)
        + struct.pack("<HH", 2, 0)
    )


def _bind(
    *contexts: tuple[int, str, tuple[int, int]],
    call_id: int = 1,
) -> bytes:
    body = struct.pack("<HHIB3x", 5840, 5840, 0, len(contexts))
    for context_id, uuid, version in contexts:
        body += _context(context_id, uuid, version)
    return _header(11, body, call_id=call_id)


def _request(
    context_id: int,
    opnum: int,
    data: bytes = b"",
    *,
    call_id: int = 2,
) -> bytes:
    body = struct.pack("<IHH", len(data), context_id, opnum) + data
    return _header(0, body, call_id=call_id)


def _auth3(blob: bytes, *, call_id: int = 3) -> bytes:
    return _header(16, b"", call_id=call_id, auth=blob)


def _ntlmssp_type3(domain: str, user: str, workstation: str) -> bytes:
    def secbuf(data: bytes, offset: int) -> bytes:
        return struct.pack("<HHI", len(data), len(data), offset)

    domain_b = domain.encode("utf-16-le")
    user_b = user.encode("utf-16-le")
    ws_b = workstation.encode("utf-16-le")
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + secbuf(b"", 64)
        + secbuf(b"", 64)
        + secbuf(domain_b, 64)
        + secbuf(user_b, 64 + len(domain_b))
        + secbuf(ws_b, 64 + len(domain_b) + len(user_b))
        + b"\x00" * 12
        + domain_b + user_b + ws_b
    )


def test_uuid_wire_roundtrip():
    raw = uuid_to_bytes(DRSUAPI_UUID)

    assert len(raw) == 16
    assert uuid_from_bytes(raw) == DRSUAPI_UUID


def test_parse_bind_contexts():
    pdu = parse_dcerpc_pdu(_bind((0, DRSUAPI_UUID, (4, 0))))

    assert pdu is not None
    assert pdu.ptype == 11
    assert len(pdu.bind_contexts) == 1
    context = pdu.bind_contexts[0]
    assert context.context_id == 0
    assert context.uuid == DRSUAPI_UUID
    assert context.version == "4.0"


def test_scan_collects_call_in_drsuapi_context():
    stream = (
        b"\x00\x01noise"
        + _bind((0, DRSUAPI_UUID, (4, 0)))
        + _request(0, 3)
    )

    session = scan_drsuapi(stream)

    assert [c.opnum for c in session.calls] == [3]
    assert [c.context_id for c in session.calls] == [0]
    assert session.binds[0].uuid == DRSUAPI_UUID


def test_scan_ignores_other_interfaces():
    stream = _bind((0, SAMR_UUID, (1, 0))) + _request(0, 3)

    session = scan_drsuapi(stream)

    assert session.binds[0].uuid == SAMR_UUID
    assert session.calls == ()


def test_scan_ignores_unbound_context():
    stream = (
        _bind((0, DRSUAPI_UUID, (4, 0)))
        + _request(1, 3)
    )

    assert scan_drsuapi(stream).calls == ()


def test_scan_keeps_non_dcsync_opnums():
    stream = (
        _bind((0, DRSUAPI_UUID, (4, 0)))
        + _request(0, 0, call_id=2)
        + _request(0, 4, call_id=3)
    )

    assert [c.opnum for c in scan_drsuapi(stream).calls] == [0, 4]


def test_scan_survives_garbage():
    stream = b"\x05\x00" * 100 + b"\x00\xff" * 50

    assert scan_drsuapi(stream).calls == ()


def test_naming_context_from_utf16_body():
    body = b"\x00" * 8 + "DC=corp,DC=local".encode("utf-16-le")

    assert extract_naming_contexts(body) == ("DC=corp,DC=local",)


def test_naming_context_ignores_plain_text():
    assert extract_naming_contexts(b"hello world") == ()


def test_scan_extracts_naming_context_from_request():
    data = b"\x00" * 8 + "DC=corp,DC=local".encode("utf-16-le")
    stream = _bind((0, DRSUAPI_UUID, (4, 0))) + _request(0, 3, data)

    session = scan_drsuapi(stream)

    assert session.naming_contexts == ("DC=corp,DC=local",)


def test_scan_reads_identity_from_auth3():
    blob = _ntlmssp_type3("CORP", "alice", "WS01")
    stream = _bind((0, DRSUAPI_UUID, (4, 0))) + _auth3(blob)

    assert scan_drsuapi(stream).identity == ("CORP", "alice", "WS01")


def test_opnum_name():
    assert opnum_name(3) == "DRSGetNCChanges"
    assert opnum_name(99) == "opnum 99"
