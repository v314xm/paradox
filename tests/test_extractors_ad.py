"""SMB2/LDAP-экстракторы: агрегаты, port-фильтр, учётки из AD."""
import struct

from paradox.config import Config
from paradox.extractors.ldap import LDAPExtractor
from paradox.extractors.smb2 import SMB2Extractor
from paradox.models import CaptureState, FlowKey


def _smb2(
    command: int,
    *,
    is_response: bool = False,
    body: bytes = b"",
) -> bytes:
    flags = 1 if is_response else 0
    return struct.pack(
        "<4sHHIHHIIQIIQ",
        b"\xfeSMB", 64, 1, 0, command, 1, flags, 0, 1, 0, 0, 0,
    ) + b"\x00" * 16 + body


def _nbss(*messages: bytes) -> bytes:
    return b"".join(
        b"\x00" + len(m).to_bytes(3, "big") + m for m in messages
    )


def _secbuf(data: bytes, offset: int) -> bytes:
    return struct.pack("<HHI", len(data), len(data), offset)


def _ntlmssp_type3(domain: str, user: str, workstation: str) -> bytes:
    domain_b = domain.encode("utf-16-le")
    user_b = user.encode("utf-16-le")
    ws_b = workstation.encode("utf-16-le")
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + _secbuf(b"", 64)
        + _secbuf(b"", 64)
        + _secbuf(domain_b, 64)
        + _secbuf(user_b, 64 + len(domain_b))
        + _secbuf(
            ws_b, 64 + len(domain_b) + len(user_b),
        )
        + b"\x00" * 12
        + domain_b + user_b + ws_b
    )


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _int(value: int) -> bytes:
    return _tlv(0x02, bytes([value]))


def _octet(value: str) -> bytes:
    return _tlv(0x04, value.encode())


def test_smb2_extractor_collects_share_path_and_identity():
    path = "\\\\srv\\SYSVOL".encode("utf-16-le")
    tree = _smb2(
        3, body=struct.pack("<HHHH", 9, 0, 72, len(path)) + path,
    )
    name = "\\Windows\\NTDS\\ntds.dit".encode("utf-16-le")
    create_body = bytearray(56)
    struct.pack_into("<H", create_body, 0, 57)
    struct.pack_into("<H", create_body, 44, 120)
    struct.pack_into("<H", create_body, 46, len(name))
    create = _smb2(5, body=bytes(create_body) + name)
    identity_blob = _ntlmssp_type3("CORP", "alice", "WS01")
    session = _smb2(
        1,
        body=struct.pack(
            "<HBBIIHHQ", 25, 0, 0, 0, 0, 88, len(identity_blob), 0,
        ) + identity_blob,
    )

    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49152, 445)
    state.tcp_streams[key] = _nbss(tree, create, session)

    SMB2Extractor().run_post_extract(state, Config())

    assert state.smb2_messages == 3
    assert state.smb2_shares[("10.0.0.5", "10.0.0.10", "\\\\srv\\SYSVOL")] == 1
    assert ("10.0.0.5", "10.0.0.10", "\\Windows\\NTDS\\ntds.dit") in state.smb2_paths
    ident = state.host_identities["10.0.0.5"]
    assert (ident.username, ident.realm) == ("alice", "CORP")
    assert "WS01" in ident.hostnames


def test_smb2_extractor_ignores_other_ports():
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49152, 80)
    state.tcp_streams[key] = _nbss(_smb2(13))

    SMB2Extractor().run_post_extract(state, Config())

    assert state.smb2_messages == 0


def test_ldap_extractor_collects_bind_search_and_identity():
    bind = _seq(
        _int(1),
        _tlv(
            0x60,
            _int(3)
            + _octet("cn=alice,ou=users,dc=corp,dc=local")
            + _tlv(0x80, b"pw"),
        ),
    )
    search = _seq(
        _int(2),
        _tlv(
            0x63,
            _octet("dc=corp,dc=local")
            + _tlv(0x0A, b"\x02")
            + _tlv(0x0A, b"\x00")
            + _int(0)
            + _int(0)
            + _tlv(0x01, b"\x00")
            + _tlv(0x87, b"servicePrincipalName")
            + _seq(_octet("servicePrincipalName")),
        ),
    )

    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49153, 389)
    state.tcp_streams[key] = bind + search

    LDAPExtractor().run_post_extract(state, Config())

    assert state.ldap_messages == 2
    assert state.ldap_bind_dns["cn=alice,ou=users,dc=corp,dc=local"] == 1
    assert state.ldap_search_bases["dc=corp,dc=local"] == 1
    assert state.ldap_filters["(servicePrincipalName=*)"] == 1
    assert state.ldap_attributes["servicePrincipalName"] == 1
    ident = state.host_identities["10.0.0.5"]
    assert ident.username == "alice"
    assert ident.realm == "corp.local"


def test_ldap_extractor_ignores_ldaps():
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49154, 636)
    state.tcp_streams[key] = _seq(_int(1), _tlv(0x60, b""))

    LDAPExtractor().run_post_extract(state, Config())

    assert state.ldap_messages == 0
