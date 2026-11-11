"""Минимальный разбор SMB2 из склеенного TCP-потока.

Порт 445, NetBIOS Session Service: 4-байтный префикс (0x00 + 3 байта
длины big-endian), затем одно или несколько SMB2-сообщений. Сообщения
могут быть сцеплены через `NextCommand` (compound), поэтому цикл идёт
по заголовкам, а не по одному на пакет.

Что извлекаем для триажа:
  - команду и статус (ошибки вида STATUS_LOGON_FAILURE);
  - диалект из NEGOTIATE;
  - share из TREE_CONNECT и путь из CREATE/QUERY_DIRECTORY;
  - учётку из NTLMSSP Type 3 в SESSION_SETUP (домен, пользователь,
    рабочая станция) — это то, что видно в SMB-аутентификации;
  - объёмы READ/WRITE.

Что не разбираем: SMB1, шифрование (SMB3 encrypted), подпись,
внутренние структуры FILE_INFO ответов. Для triage хватает шапки.
"""
from __future__ import annotations

from dataclasses import dataclass

SMB2_MAGIC = b"\xfeSMB"
SMB2_HEADER_SIZE = 64
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

SMB2_COMMANDS: dict[int, str] = {
    0: "NEGOTIATE",
    1: "SESSION_SETUP",
    2: "LOGOFF",
    3: "TREE_CONNECT",
    4: "TREE_DISCONNECT",
    5: "CREATE",
    6: "CLOSE",
    7: "FLUSH",
    8: "READ",
    9: "WRITE",
    10: "LOCK",
    11: "IOCTL",
    12: "CANCEL",
    13: "ECHO",
    14: "QUERY_DIRECTORY",
    15: "CHANGE_NOTIFY",
    16: "QUERY_INFO",
    17: "SET_INFO",
    18: "OPLOCK_BREAK",
}

SMB2_DIALECTS: dict[int, str] = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}


@dataclass(frozen=True)
class Smb2Message:
    """Одно SMB2-сообщение; поля заполняются по типу команды."""
    command: str
    is_response: bool
    status: int
    message_id: int
    tree_id: int
    session_id: int
    dialect: str | None = None
    share: str | None = None
    path: str | None = None
    domain: str | None = None
    username: str | None = None
    workstation: str | None = None
    read_bytes: int = 0
    write_bytes: int = 0


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _utf16(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def _slice_at(data: bytes, offset: int, length: int) -> bytes:
    if length <= 0 or offset < 0 or offset >= len(data):
        return b""
    return data[offset:offset + length]


def _decode_dialect(value: int) -> str:
    return SMB2_DIALECTS.get(value, f"0x{value:04X}")


def parse_ntlmssp_identity(
    blob: bytes,
) -> tuple[str, str, str] | None:
    """Достать (domain, user, workstation) из NTLMSSP Type 3.

    Blob — security buffer SESSION_SETUP: SPNEGO-обёртка вокруг
    NTLMSSP. Ищем сигнатуру, проверяем тип 3 и читаем три поля
    SecurityBuffer (domain 28, user 36, workstation 44). Смещения
    полей отсчитываются от начала NTLMSSP.
    """
    index = blob.find(b"NTLMSSP\x00")
    if index < 0:
        return None
    data = blob[index:]
    if len(data) < 52:
        return None
    if _u32(data, 8) != 3:
        return None

    def _field(offset: int) -> bytes:
        length = _u16(data, offset)
        value_offset = _u32(data, offset + 4)
        return _slice_at(data, value_offset, length)

    return (
        _utf16(_field(28)),
        _utf16(_field(36)),
        _utf16(_field(44)),
    )


def parse_smb2_message(data: bytes) -> Smb2Message | None:
    """Разобрать одно сообщение (начинается с ``\\xfeSMB``)."""
    if len(data) < SMB2_HEADER_SIZE or data[:4] != SMB2_MAGIC:
        return None

    command_id = _u16(data, 12)
    flags = _u32(data, 16)
    status = _u32(data, 8)
    message_id = _u64(data, 24)
    tree_id = _u32(data, 36)
    session_id = _u64(data, 40)
    is_response = bool(flags & SMB2_FLAGS_SERVER_TO_REDIR)
    command = SMB2_COMMANDS.get(command_id, f"UNKNOWN({command_id})")

    dialect: str | None = None
    share: str | None = None
    path: str | None = None
    domain: str | None = None
    username: str | None = None
    workstation: str | None = None
    read_bytes = 0
    write_bytes = 0
    body = data[SMB2_HEADER_SIZE:]

    if command == "NEGOTIATE":
        if is_response and len(body) >= 6:
            dialect = _decode_dialect(_u16(body, 4))
        elif not is_response and len(body) >= 4:
            count = _u16(body, 2)
            dialects = [
                _decode_dialect(_u16(body, 36 + i * 2))
                for i in range(count)
                if 36 + i * 2 + 2 <= len(body)
            ]
            dialect = ", ".join(dialects) or None

    elif command == "SESSION_SETUP":
        # SecurityBufferOffset/Length — от начала SMB2-заголовка.
        if len(body) >= 16:
            offset = _u16(body, 12)
            length = _u16(body, 14)
            identity = parse_ntlmssp_identity(
                _slice_at(data, offset, length),
            )
            if identity is not None:
                domain, username, workstation = identity

    elif command == "TREE_CONNECT" and not is_response:
        if len(body) >= 8:
            path_offset = _u16(body, 4)
            path_length = _u16(body, 6)
            share = _utf16(_slice_at(data, path_offset, path_length))

    elif command in ("CREATE", "QUERY_DIRECTORY") and not is_response:
        if command == "CREATE" and len(body) >= 48:
            name_offset = _u16(body, 44)
            name_length = _u16(body, 46)
            path = _utf16(_slice_at(data, name_offset, name_length))
        elif command == "QUERY_DIRECTORY" and len(body) >= 28:
            name_offset = _u16(body, 24)
            name_length = _u16(body, 26)
            path = _utf16(_slice_at(data, name_offset, name_length))

    elif command == "READ" and not is_response and len(body) >= 8:
        read_bytes = _u32(body, 4)

    elif command == "WRITE" and not is_response and len(body) >= 8:
        write_bytes = _u32(body, 4)

    return Smb2Message(
        command=command,
        is_response=is_response,
        status=status,
        message_id=message_id,
        tree_id=tree_id,
        session_id=session_id,
        dialect=dialect,
        share=share,
        path=path,
        domain=domain,
        username=username,
        workstation=workstation,
        read_bytes=read_bytes,
        write_bytes=write_bytes,
    )


def _parse_compound(chunk: bytes) -> list[Smb2Message]:
    """Разобрать сцепленные сообщения по NextCommand."""
    out: list[Smb2Message] = []
    pos = 0
    while pos + SMB2_HEADER_SIZE <= len(chunk):
        if chunk[pos:pos + 4] != SMB2_MAGIC:
            break
        next_command = _u32(chunk, pos + 20)
        message = parse_smb2_message(chunk[pos:])
        if message is None:
            break
        out.append(message)
        if next_command == 0:
            break
        pos += next_command
    return out


def parse_smb2_messages(stream: bytes) -> tuple[list[Smb2Message], int]:
    """Разобрать поток SMB2: (сообщения, число ошибок кадрирования)."""
    messages: list[Smb2Message] = []
    errors = 0
    pos = 0
    while pos + 4 <= len(stream):
        if stream[pos] != 0x00:
            break
        length = int.from_bytes(stream[pos + 1:pos + 4], "big")
        if length == 0:
            break
        start = pos + 4
        chunk = stream[start:start + length]
        if len(chunk) < length:
            errors += 1
            break
        parsed = _parse_compound(chunk)
        if not parsed:
            errors += 1
            break
        messages.extend(parsed)
        pos = start + length
    return messages, errors
