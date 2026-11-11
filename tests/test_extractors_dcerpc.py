"""DCERPCExtractor: DRSUAPI-вызовы из потоков, учётка из AUTH3."""
import struct

from paradox.config import Config
from paradox.dcerpc_parse import DRSUAPI_UUID
from paradox.extractors.dcerpc import DCERPCExtractor
from paradox.models import CaptureState, FlowKey

SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ab"
NDR_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"


def _uuid_bytes(uuid: str) -> bytes:
    first, second, third, fourth, fifth = uuid.split("-")
    return (
        struct.pack(
            "<IHH", int(first, 16), int(second, 16), int(third, 16),
        )
        + bytes.fromhex(fourth + fifth)
    )


def _header(
    ptype: int,
    body: bytes,
    *,
    call_id: int = 1,
    auth: bytes = b"",
) -> bytes:
    return (
        struct.pack(
            "<BBBB4sHHI",
            5, 0, ptype, 3, b"\x10\x00\x00\x00",
            16 + len(body) + len(auth), len(auth), call_id,
        )
        + body
        + auth
    )


def _bind(uuid: str, *, call_id: int = 1) -> bytes:
    context = (
        struct.pack("<HBB", 0, 1, 0)
        + _uuid_bytes(uuid)
        + struct.pack("<HH", 4, 0)
        + _uuid_bytes(NDR_UUID)
        + struct.pack("<HH", 2, 0)
    )
    body = struct.pack("<HHIB3x", 5840, 5840, 0, 1) + context
    return _header(11, body, call_id=call_id)


def _request(opnum: int, data: bytes = b"", *, call_id: int = 2) -> bytes:
    body = struct.pack("<IHH", len(data), 0, opnum) + data
    return _header(0, body, call_id=call_id)


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


def test_dcerpc_extractor_collects_dcsync():
    naming_context = "DC=corp,DC=local".encode("utf-16-le")
    stream = (
        b"\x00\x00\x00\x40"  # мусор перед первым кадром
        + _bind(DRSUAPI_UUID)
        + _request(0, call_id=2)
        + _request(3, b"\x00" * 8 + naming_context, call_id=3)
        + _request(3, call_id=4)
    )

    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49152, 445)
    state.tcp_streams[key] = stream

    DCERPCExtractor().run_post_extract(state, Config())

    assert state.dcerpc_binds[
        ("10.0.0.5", "10.0.0.10", DRSUAPI_UUID, "4.0")
    ] == 1
    assert state.dcerpc_drsuapi_calls[
        ("10.0.0.5", "10.0.0.10", 445, 3)
    ] == 2
    assert state.dcerpc_naming_contexts[
        ("10.0.0.5", "10.0.0.10", "DC=corp,DC=local")
    ] == 1


def test_dcerpc_extractor_records_other_binds_without_calls():
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49153, 445)
    state.tcp_streams[key] = _bind(SAMR_UUID) + _request(3)

    DCERPCExtractor().run_post_extract(state, Config())

    assert state.dcerpc_binds[
        ("10.0.0.5", "10.0.0.10", SAMR_UUID, "4.0")
    ] == 1
    assert not state.dcerpc_drsuapi_calls


def test_dcerpc_extractor_reads_identity_from_auth3():
    auth_blob = _ntlmssp_type3("CORP", "alice", "WS01")
    stream = _bind(DRSUAPI_UUID) + _header(16, b"", auth=auth_blob)

    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49152, 445)
    state.tcp_streams[key] = stream

    DCERPCExtractor().run_post_extract(state, Config())

    ident = state.host_identities["10.0.0.5"]
    assert (ident.username, ident.realm) == ("alice", "CORP")
    assert "WS01" in ident.hostnames


def test_dcerpc_extractor_skips_non_tcp_and_empty():
    state = CaptureState()
    state.tcp_streams[FlowKey("udp", "10.0.0.5", "10.0.0.10", 53, 53)] = (
        _bind(DRSUAPI_UUID)
    )
    state.tcp_streams[FlowKey("tcp", "10.0.0.5", "10.0.0.10", 1, 2)] = b""

    DCERPCExtractor().run_post_extract(state, Config())

    assert not state.dcerpc_binds
    assert not state.dcerpc_drsuapi_calls
