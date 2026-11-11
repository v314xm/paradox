"""Разбор SMB2: заголовки, share/путь, NTLMSSP, кадрирование."""
import struct

from paradox.smb2_parse import (
    parse_ntlmssp_identity,
    parse_smb2_message,
    parse_smb2_messages,
)


def _header(
    command: int,
    *,
    is_response: bool = False,
    status: int = 0,
    message_id: int = 1,
    tree_id: int = 0,
    session_id: int = 0,
    next_command: int = 0,
    body: bytes = b"",
) -> bytes:
    flags = 1 if is_response else 0
    header = struct.pack(
        "<4sHHIHHIIQIIQ",
        b"\xfeSMB", 64, 1, status, command, 1, flags,
        next_command, message_id, 0, tree_id, session_id,
    ) + b"\x00" * 16
    return header + body


def _nbss(*messages: bytes) -> bytes:
    return b"".join(
        b"\x00" + len(message).to_bytes(3, "big") + message
        for message in messages
    )


def _secbuf(data: bytes, offset: int) -> bytes:
    return struct.pack("<HHI", len(data), len(data), offset)


def _ntlmssp_type3(domain: str, user: str, workstation: str) -> bytes:
    enc_domain = domain.encode("utf-16-le")
    enc_user = user.encode("utf-16-le")
    enc_ws = workstation.encode("utf-16-le")
    base = 64
    payload = enc_domain + enc_user + enc_ws
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + _secbuf(b"", base)
        + _secbuf(b"", base)
        + _secbuf(enc_domain, base)
        + _secbuf(enc_user, base + len(enc_domain))
        + _secbuf(
            enc_ws, base + len(enc_domain) + len(enc_user),
        )
        + b"\x00" * 12
        + payload
    )


def test_negotiate_response_dialect():
    body = struct.pack("<HHH", 65, 1, 0x0311)
    message = parse_smb2_message(
        _header(0, is_response=True, body=body),
    )

    assert message is not None
    assert message.command == "NEGOTIATE"
    assert message.is_response is True
    assert message.dialect == "3.1.1"


def test_negotiate_request_dialects():
    dialects = struct.pack("<HH", 0x0210, 0x0311)
    body = struct.pack("<HH", 36, 2) + bytes(32) + dialects
    message = parse_smb2_message(_header(0, body=body))

    assert message is not None
    assert message.dialect == "2.1, 3.1.1"


def test_tree_connect_share():
    path = "\\\\srv\\SYSVOL".encode("utf-16-le")
    body = struct.pack("<HHHH", 9, 0, 72, len(path)) + path
    message = parse_smb2_message(_header(3, body=body))

    assert message is not None
    assert message.share == "\\\\srv\\SYSVOL"


def test_create_path():
    name = "\\Windows\\System32\\config\\SAM".encode("utf-16-le")
    body = bytearray(56)
    struct.pack_into("<H", body, 0, 57)
    struct.pack_into("<H", body, 44, 64 + len(body))
    struct.pack_into("<H", body, 46, len(name))
    message = parse_smb2_message(
        _header(5, body=bytes(body) + name),
    )

    assert message is not None
    assert message.path == "\\Windows\\System32\\config\\SAM"


def test_read_and_write_lengths():
    read = parse_smb2_message(
        _header(8, body=struct.pack("<HBBI", 49, 0, 0, 4096)),
    )
    write = parse_smb2_message(
        _header(9, body=struct.pack("<HBBI", 49, 0, 0, 8192)),
    )

    assert read is not None and read.read_bytes == 4096
    assert write is not None and write.write_bytes == 8192


def test_status_and_direction():
    message = parse_smb2_message(
        _header(1, is_response=True, status=0xC000006D),
    )

    assert message is not None
    assert message.is_response is True
    assert message.status == 0xC000006D


def test_ntlmssp_identity_from_session_setup():
    blob = _ntlmssp_type3("CORP", "alice", "WS01")
    body = struct.pack(
        "<HBBIIHHQ", 25, 0, 0, 0, 0, 88, len(blob), 0,
    ) + blob
    message = parse_smb2_message(_header(1, body=body))

    assert message is not None
    assert (message.domain, message.username) == ("CORP", "alice")
    assert message.workstation == "WS01"


def test_ntlmssp_rejects_challenge():
    challenge = b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 40

    assert parse_ntlmssp_identity(challenge) is None
    assert parse_ntlmssp_identity(b"nothing here") is None


def test_netbios_framing_with_two_messages():
    first = _header(0, is_response=True, body=struct.pack("<HHH", 65, 1, 0x0300))
    second = _header(13)
    messages, errors = parse_smb2_messages(_nbss(first, second))

    assert errors == 0
    assert [m.command for m in messages] == ["NEGOTIATE", "ECHO"]


def test_compound_messages_by_next_command():
    second = _header(13)
    first = _header(0, next_command=len(_header(0)))
    stream = _nbss(first + second)

    messages, errors = parse_smb2_messages(stream)

    assert errors == 0
    assert [m.command for m in messages] == ["NEGOTIATE", "ECHO"]


def test_truncated_frame_counts_error():
    message = _header(13)
    stream = b"\x00" + (len(message) + 10).to_bytes(3, "big") + message

    messages, errors = parse_smb2_messages(stream)

    assert messages == []
    assert errors == 1


def test_not_smb2_stream_is_ignored():
    messages, errors = parse_smb2_messages(b"GET / HTTP/1.1\r\n\r\n")

    assert messages == []
    assert errors == 0
