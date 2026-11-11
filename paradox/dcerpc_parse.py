"""Минимальный разбор DCE/RPC (MS-RPCE) для triage.

Зачем: DCSync — это DRSUAPI `DsGetNCChanges` (opnum 3) поверх
DCE/RPC. Полный NDR-парсер здесь не нужен: для вердикта хватает
BIND с UUID интерфейса и opnum запроса в привязанном контексте.

Что разбираем:
  - общий PDU-заголовок (version 5.0, ptype, flags, frag_length,
    auth_length, call_id);
  - BIND (ptype 11) — p_cont_list: context id, abstract syntax UUID
    и версия;
  - REQUEST (ptype 0) — p_ctx_id и opnum;
  - AUTH3 (ptype 16) — NTLMSSP Type 3 (домен/пользователь/станция).

Чего не разбираем: NDR-тела (кроме эвристики по naming context),
фрагментацию, подпись и шифрование. Кадры ищутся сканированием
потока по сигнатуре заголовка: в SMB2 named pipe DCERPC-сообщение
лежит внутри WRITE, отдельной рамки у него нет.

Ссылки: DCE 1.1: Remote Procedure Call, MS-RPCE, MS-DRSR.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from paradox.smb2_parse import parse_ntlmssp_identity

DCERPC_VERSION = 5
DCERPC_VERSION_MINOR = 0

PTYPE_REQUEST = 0
PTYPE_RESPONSE = 2
PTYPE_BIND = 11
PTYPE_BIND_ACK = 12
PTYPE_AUTH3 = 16

_KNOWN_PTYPES = frozenset({
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
})
_HEADER_SIZE = 16
_MAX_FRAG_LENGTH = 64 * 1024 * 1024
_SIGNATURE = b"\x05\x00"

# DRSUAPI (MS-DRSR): Directory Replication Service.
DRSUAPI_UUID = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"

# Имена только тех opnum, которые важны для triage; остальные
# остаются числами. DsGetNCChanges — 3.
DRSUAPI_OPNUMS: dict[int, str] = {
    0: "DRSBind",
    1: "DRSUnbind",
    3: "DRSGetNCChanges",
    4: "DRSUpdateRefs",
}

_HEADER = struct.Struct("<BBBB4sHHI")
_PRINTABLE_RUN = re.compile(r"[ -~]{4,}")
_DN_TAIL_TRIM = " ,;"


@dataclass
class DcerpcBindContext:
    """Один p_cont_elem из BIND."""
    context_id: int
    uuid: str
    major_version: int = 0
    minor_version: int = 0

    @property
    def version(self) -> str:
        return f"{self.major_version}.{self.minor_version}"


@dataclass
class DcerpcPdu:
    """Разобранный PDU. Поля заполняются по типу."""
    ptype: int
    call_id: int
    frag_length: int
    bind_contexts: list[DcerpcBindContext] = field(default_factory=list)
    context_id: int | None = None
    opnum: int | None = None
    body: bytes = b""
    auth_blob: bytes = b""


@dataclass
class DrsuapiSession:
    """Что видно в одном направлении TCP-потока."""
    binds: tuple[DcerpcBindContext, ...] = ()
    calls: tuple[DcerpcPdu, ...] = ()
    naming_contexts: tuple[str, ...] = ()
    identity: tuple[str, str, str] | None = None


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def uuid_to_bytes(uuid: str) -> bytes:
    """UUID в проводной форме DCE/RPC (первые три группы little-endian)."""
    first, second, third, fourth, fifth = uuid.split("-")
    return (
        struct.pack(
            "<IHH",
            int(first, 16),
            int(second, 16),
            int(third, 16),
        )
        + bytes.fromhex(fourth + fifth)
    )


def uuid_from_bytes(raw: bytes) -> str:
    if len(raw) < 16:
        return ""
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    return f"{a:08x}-{b:04x}-{c:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"


def _parse_bind_contexts(body: bytes) -> list[DcerpcBindContext]:
    """p_cont_list: num_elems (u8 + 3 reserved), затем p_cont_elem."""
    if len(body) < 12:
        return []
    pos = 8
    count = body[pos]
    pos += 4
    contexts: list[DcerpcBindContext] = []
    for _ in range(min(count, 32)):
        if pos + 24 > len(body):
            break
        context_id = _u16(body, pos)
        transfer_syntaxes = body[pos + 2]
        pos += 4
        contexts.append(DcerpcBindContext(
            context_id=context_id,
            uuid=uuid_from_bytes(body[pos:pos + 16]),
            major_version=_u16(body, pos + 16),
            minor_version=_u16(body, pos + 18),
        ))
        pos += 20 + 20 * transfer_syntaxes
    return contexts


def parse_dcerpc_pdu(data: bytes, offset: int = 0) -> DcerpcPdu | None:
    """Разобрать PDU, начинающийся по смещению ``offset``."""
    if offset < 0 or len(data) - offset < _HEADER_SIZE:
        return None
    (
        major, minor, ptype, _flags, data_rep, frag_length, auth_length,
        call_id,
    ) = _HEADER.unpack_from(data, offset)
    if major != DCERPC_VERSION or minor != DCERPC_VERSION_MINOR:
        return None
    if ptype not in _KNOWN_PTYPES:
        return None
    if data_rep[0] != 0x10:  # little-endian + ASCII
        return None
    if frag_length < _HEADER_SIZE or frag_length > _MAX_FRAG_LENGTH:
        return None

    end = min(len(data), offset + frag_length)
    body = data[offset + _HEADER_SIZE:end]
    pdu = DcerpcPdu(ptype=ptype, call_id=call_id, frag_length=frag_length)

    if ptype == PTYPE_BIND:
        pdu.bind_contexts = _parse_bind_contexts(body)
    elif ptype == PTYPE_REQUEST:
        if len(body) < 8:
            return None
        pdu.context_id = _u16(body, 4)
        pdu.opnum = _u16(body, 6)
        pdu.body = body[8:]
    elif ptype == PTYPE_AUTH3 and auth_length:
        start = end - auth_length
        if start >= offset + _HEADER_SIZE:
            pdu.auth_blob = data[start:end]

    return pdu


def extract_naming_contexts(data: bytes) -> tuple[str, ...]:
    """Эвристика: DN каталога (`DC=corp,DC=local`) из тела запроса.

    В NDR-теле `DsGetNCChanges` naming context лежит как UTF-16
    строка DSNAME. Точное смещение зависит от версии структуры и
    выравнивания, поэтому ищем печатные отрезки в обоих выравниваниях
    UTF-16 и оставляем те, где есть `DC=`.
    """
    found: list[str] = []
    for shift in (0, 1):
        chunk = data[shift:]
        if len(chunk) % 2:
            chunk = chunk[:-1]
        text = chunk.decode("utf-16-le", errors="ignore")
        for run in _PRINTABLE_RUN.findall(text):
            upper = run.upper()
            index = upper.find("DC=")
            if index < 0:
                continue
            candidate = run[index:].strip(_DN_TAIL_TRIM)
            if 3 < len(candidate) <= 512 and candidate not in found:
                found.append(candidate)
    return tuple(found)


def scan_drsuapi(stream: bytes) -> DrsuapiSession:
    """Найти DCERPC-кадры DRSUAPI в одном направлении потока.

    Сканирование, а не последовательный разбор: в SMB2 named pipe
    кадры разделены заголовками WRITE, а в ncacn_ip_tcp перед ними
    может быть пустой хвост. Собираются только REQUEST'ы, чей
    p_ctx_id привязан к DRSUAPI в этом же потоке.
    """
    bound: dict[int, DcerpcBindContext] = {}
    binds: list[DcerpcBindContext] = []
    calls: list[DcerpcPdu] = []
    naming_contexts: list[str] = []
    identity: tuple[str, str, str] | None = None

    pos = 0
    while pos < len(stream):
        index = stream.find(_SIGNATURE, pos)
        if index < 0:
            break
        pdu = parse_dcerpc_pdu(stream, index)
        if pdu is None:
            pos = index + 1
            continue
        pos = index + max(pdu.frag_length, _HEADER_SIZE)

        if pdu.ptype == PTYPE_BIND:
            for context in pdu.bind_contexts:
                binds.append(context)
                if context.uuid == DRSUAPI_UUID:
                    bound[context.context_id] = context
        elif (
            pdu.ptype == PTYPE_REQUEST
            and pdu.context_id in bound
            and pdu.opnum is not None
        ):
            calls.append(pdu)
            for naming_context in extract_naming_contexts(pdu.body):
                if naming_context not in naming_contexts:
                    naming_contexts.append(naming_context)
        elif pdu.ptype == PTYPE_AUTH3 and identity is None:
            parsed = parse_ntlmssp_identity(pdu.auth_blob)
            if parsed is not None:
                identity = parsed

    return DrsuapiSession(
        binds=tuple(binds),
        calls=tuple(calls),
        naming_contexts=tuple(naming_contexts),
        identity=identity,
    )


def opnum_name(opnum: int) -> str:
    return DRSUAPI_OPNUMS.get(opnum, f"opnum {opnum}")
