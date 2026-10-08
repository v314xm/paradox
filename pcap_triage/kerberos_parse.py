"""
Минимальный ASN.1 DER парсер для Kerberos.

Извлекает cname, sname, realm, msg_type из AS-REQ, AS-REP,
TGS-REQ, TGS-REP, AP-REQ.

Не претендует на полноту ASN.1 — только то, что нужно для triage:
SEQUENCE (0x30), [APPLICATION n] (0x60+n), [context n] (0xA0+n),
GeneralString (0x1B), INTEGER (0x02), OCTET STRING (0x04).

Если структура нестандартная — возвращаем частично заполненный
KerberosInfo или None. Никогда не падаем.

Ссылки:
  RFC 4120 — The Kerberos Network Authentication Service (V5)
  ASN.1 DER — X.690
"""
from __future__ import annotations

from dataclasses import dataclass


# --- теги ASN.1, которые нас интересуют ---
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_GENERAL_STRING = 0x1B
TAG_SEQUENCE = 0x30              # конструктивный SEQUENCE
TAG_APPLICATION = 0x60           # конструктивный [APPLICATION n] = 0x60+n
TAG_CONTEXT = 0xA0               # конструктивный [context n] = 0xA0+n


@dataclass
class KerberosInfo:
    """Извлечённые поля Kerberos-сообщения."""
    msg_type: int | None = None
    cname: str | None = None
    crealm: str | None = None
    sname: str | None = None
    realm: str | None = None


def parse_kerberos(payload: bytes) -> KerberosInfo | None:
    """
    Разобрать Kerberos-сообщение.

    Payload может быть:
      - UDP: начинается прямо с ASN.1 (APPLICATION n или SEQUENCE)
      - TCP: первые 4 байта — длина, потом ASN.1

    Возвращает KerberosInfo или None, если payload не похож на Kerberos.
    """
    if not payload or len(payload) < 4:
        return None

    # Kerberos over TCP: 4-байтовый префикс длины
    # ASN.1 начинается с APPLICATION (0x6n) или SEQUENCE (0x30)
    if (payload[0] & 0xE0) == TAG_APPLICATION:
        asn1 = payload
    elif payload[4:5] and (payload[4] & 0xE0) == TAG_APPLICATION:
        # TCP: пропускаем 4 байта длины
        asn1 = payload[4:]
    elif payload[0] == TAG_SEQUENCE:
        asn1 = payload
    elif payload[4:5] and payload[4] == TAG_SEQUENCE:
        asn1 = payload[4:]
    else:
        return None

    try:
        tag, _, content, _ = _read_tlv(asn1, 0)
    except ValueError:
        return None

    if content is None:
        return None

    return _parse_kerberos_sequence(content)


def _parse_kerberos_sequence(content: bytes) -> KerberosInfo | None:
    """
    Разобрать тело Kerberos SEQUENCE.

    Структура (RFC 4120):
      KDC-REQ      ::= SEQUENCE { pvno [1], msg-type [2], ... }
      KDC-REP      ::= SEQUENCE { pvno [0], msg-type [1], ... }
      AP-REQ       ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1], ... }
    """
    info = KerberosInfo()

    try:
        pos = 0
        # проходим по элементам SEQUENCE
        while pos < len(content):
            tag, _, value, next_pos = _read_tlv(content, pos)

            # [context 0..15] — самые частые
            if tag & 0xE0 == TAG_CONTEXT:
                context_num = tag & 0x1F
                _handle_context_field(context_num, value, info)

            pos = next_pos
    except ValueError:
        return info  # частично заполнено

    # Если ничего не извлекли — не Kerberos
    if info.msg_type is None and info.cname is None and info.sname is None:
        return None

    return info


def _handle_context_field(
    context_num: int, value: bytes, info: KerberosInfo,
) -> None:
    """
    Обработать [context N].

    Для KDC-REQ:
      [1] pvno, [2] msg-type, [4] sname, [6] realm, [1] в KDC-REP — msg-type.
    Для AP-REQ:
      [0] pvno, [1] msg-type, [2] ap-options, [3] ticket, [4] authenticator.
    """
    # --- msg_type ---
    # msg-type обычно INTEGER внутри [context N]
    if context_num in (1, 2):
        # может быть pvno (INTEGER) или msg-type (INTEGER) — оба INTEGER
        # pvno всегда 5, msg-type — что-то из 10..30
        try:
            tag, _, inner, _ = _read_tlv(value, 0)
            if tag == TAG_INTEGER and inner:
                n = int.from_bytes(inner, "big")
                if 10 <= n <= 30:  # характерные значения msg-type
                    info.msg_type = n
        except ValueError:
            pass
        return

    # --- cname / sname (PrincipalName) ---
    # PrincipalName ::= SEQUENCE { name-type [0], name-string [1] SEQUENCE OF GeneralString }
    if context_num in (1, 2, 4):  # [1] cname в KDC-REP, [2] в AS-REQ/TGS-REQ
        name = _parse_principal_name(value)
        if name:
            # эвристика: если context_num == 4 → это sname (service)
            # иначе cname
            if context_num == 4:
                info.sname = name
            elif info.cname is None:
                info.cname = name
        return

    # --- realm ---
    # Realm ::= GeneralString
    if context_num in (3, 6, 8):  # [3] в KDC-REP, [6] в KDC-REQ
        try:
            tag, _, inner, _ = _read_tlv(value, 0)
            if tag == TAG_GENERAL_STRING:
                text = inner.decode("ascii", errors="ignore")
                if text:
                    if info.crealm is None and context_num == 3:
                        info.crealm = text
                    elif info.realm is None:
                        info.realm = text
        except ValueError:
            pass


def _parse_principal_name(data: bytes) -> str | None:
    """
    Извлечь имя из PrincipalName.

    PrincipalName ::= SEQUENCE {
      name-type    [0] Int32,
      name-string  [1] SEQUENCE OF KerberosString
    }

    name-string обычно содержит один элемент: "rgaines" или "DESKTOP-xxx$".
    """
    try:
        # Пропускаем внешний [context N] если есть
        pos = 0
        if data and (data[0] & 0xE0) == TAG_CONTEXT:
            _, _, data, _ = _read_tlv(data, 0)

        # Теперь ожидаем SEQUENCE (PrincipalName)
        if not data or data[0] != TAG_SEQUENCE:
            return None

        _, _, seq_content, _ = _read_tlv(data, 0)

        # Проходим по [0] name-type и [1] name-string
        pos = 0
        while pos < len(seq_content):
            tag, _, value, next_pos = _read_tlv(seq_content, pos)
            if tag & 0xE0 == TAG_CONTEXT and (tag & 0x1F) == 1:
                # name-string — SEQUENCE OF GeneralString
                return _extract_first_string(value)
            pos = next_pos
    except (ValueError, IndexError):
        pass

    return None


def _extract_first_string(data: bytes) -> str | None:
    """Достать первую строку из SEQUENCE OF GeneralString."""
    try:
        if not data or data[0] != TAG_SEQUENCE:
            return None
        _, _, content, _ = _read_tlv(data, 0)

        pos = 0
        if pos >= len(content):
            return None
        tag, _, value, _ = _read_tlv(content, pos)
        if tag != TAG_GENERAL_STRING:
            return None

        text = value.decode("ascii", errors="ignore")
        return text or None
    except (ValueError, IndexError):
        return None