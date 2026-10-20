"""
Минимальный DER-парсер для X.509. Только чтение, без валидации.

DER — это ASN.1 с ограничениями:
  - definite-length (никогда indefinite)
  - только primitive SEQUENCE/SET (никаких constructed строк)
  - уникальные тэги в SET (для нас неважно)

Формат: [tag(1)] [length(1..5)] [value(length)]
  - tag: 0x30 = SEQUENCE, 0x31 = SET, 0x06 = OID, 0x02 = INTEGER, ...
  - length:
    - < 0x80 — короткий, значение длины прямо в байте
    - >= 0x80 — long form: младшие 7 бит = число байт длины
  - value — вложенная структура или примитив

Зачем свой:
  - проект держит scapy только для DNS, тут своё
  - нам нужны 4 поля: subject CN, issuer, validity, SAN
  - полный X.509 — 2000+ LOC, избыточно

Ограничения:
  - не поддерживаем indefinite-length (0x80) — X.509 его не использует
  - не поддерживаем high-tag-number (tag & 0x1F == 0x1F) — в X.509
    не встречается, кроме редких extension'ов
  - ошибки → DerError, не падаем молча
"""
from __future__ import annotations

from dataclasses import dataclass, field

# === Константы тэгов (universal class, low-tag) ===

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18

# Контекстные тэги (используются в X.509 extensions и в SAN)
# Class 0b10 (context-specific), constructed = bit 0x20
TAG_CTX_0 = 0xA0
TAG_CTX_1 = 0xA1
TAG_CTX_2 = 0xA2
TAG_CTX_3 = 0xA3


class DerError(ValueError):
    """Некорректный DER — длина не сходится, тэг не поддерживается."""


@dataclass
class DerNode:
    """Узел DER-дерева.

    tag             — сырой байт тэга (0x30, 0x06, 0xA2, ...)
    tag_class       — 0=universal, 1=application, 2=context, 3=private
    constructed     — True для SEQUENCE/SET/context-constructed
    value           — сырые байты значения (для primitive) или всего
                      вложенного содержимого (для constructed)
    children        — распарсенные вложенные узлы (только constructed)
    """
    tag: int
    tag_class: int
    constructed: bool
    value: bytes
    children: list[DerNode] = field(default_factory=list)

    @property
    def is_primitive(self) -> bool:
        return not self.constructed

    @property
    def is_universal(self) -> bool:
        return self.tag_class == 0


def _parse_length(data: bytes, pos: int) -> tuple[int, int]:
    """Вернуть (length, new_pos). Бросает DerError, если данных мало."""
    if pos >= len(data):
        raise DerError("length: unexpected end of data")
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise DerError("indefinite length not supported in DER")
    if num_bytes > 4:
        raise DerError(f"length too large: {num_bytes} bytes")
    if pos + 1 + num_bytes > len(data):
        raise DerError("length: truncated long-form")
    length = int.from_bytes(data[pos + 1:pos + 1 + num_bytes], "big")
    return length, pos + 1 + num_bytes


def parse_der(data: bytes) -> DerNode:
    """Распарсить один DER-объект из начала data.

    Возвращает корневой узел. Остаток data игнорируется —
    X.509 сертификат занимает всё, что передали, но при вложенных
    вызовах (parse внутри parse) мы работаем с куском.
    """
    node, _end = _parse_one(data, 0)
    return node


def _parse_one(data: bytes, pos: int) -> tuple[DerNode, int]:
    """Распарсить один TLV начиная с pos. Вернуть (node, new_pos)."""
    if pos >= len(data):
        raise DerError("tag: unexpected end of data")

    tag = data[pos]
    tag_class = (tag >> 6) & 0x03
    constructed = bool(tag & 0x20)
    low_tag = tag & 0x1F

    if low_tag == 0x1F:
        raise DerError("high-tag-number form not supported")

    length, val_start = _parse_length(data, pos + 1)
    val_end = val_start + length
    if val_end > len(data):
        raise DerError(
            f"value truncated: need {length}, have {len(data) - val_start}"
        )

    value = data[val_start:val_end]
    children: list[DerNode] = []

    if constructed:
        inner_pos = 0
        while inner_pos < len(value):
            child, inner_pos = _parse_one(value, inner_pos)
            children.append(child)

    return DerNode(
        tag=tag,
        tag_class=tag_class,
        constructed=constructed,
        value=value,
        children=children,
    ), val_end


# === Хелперы для примитивов ===

def as_int(node: DerNode) -> int:
    """INTEGER → int. В DER всегда big-endian, знаковый."""
    if node.tag != TAG_INTEGER:
        raise DerError(f"expected INTEGER (0x02), got 0x{node.tag:02X}")
    return int.from_bytes(node.value, "big", signed=True)


def as_oid(node: DerNode) -> str:
    """OID → строковое представление '2.5.29.17'.

    DER-кодирование OID: первая пара (a.b) упакована в один байт
    (a * 40 + b), затем base-128 с continuation bit.
    """
    if node.tag != TAG_OID:
        raise DerError(f"expected OID (0x06), got 0x{node.tag:02X}")
    if not node.value:
        raise DerError("empty OID")

    # Первый байт: a * 40 + b, где a ∈ {0,1,2}
    first = node.value[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]

    # Остальные — base-128 с продолжением
    val = 0
    for byte in node.value[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            arcs.append(val)
            val = 0
    if val:
        raise DerError("truncated OID continuation")

    return ".".join(str(a) for a in arcs)


def as_str(node: DerNode) -> str:
    """Строковые типы → str. UTF8String / PrintableString / IA5String."""
    if node.tag not in (
        TAG_UTF8_STRING, TAG_PRINTABLE_STRING, TAG_IA5_STRING,
    ):
        raise DerError(
            f"expected string, got tag 0x{node.tag:02X}"
        )
    return node.value.decode("utf-8", errors="replace")


def as_time(node: DerNode) -> tuple[str, str] | None:
    """UTCTime / GeneralizedTime → ISO-строка 'YYYY-MM-DDTHH:MM:SS'.

    UTCTime: YYMMDDHHMMSSZ (или YYMMDDHHMMZ)
    GeneralizedTime: YYYYMMDDHHMMSSZ

    Возвращает None, если формат неизвестен — не падаем на битых cert.
    """
    if node.tag == TAG_UTC_TIME:
        s = node.value.decode("ascii", errors="ignore").strip()
        if len(s) < 12:
            return None
        # YY → YYYY (по RFC 5280: 50-99 → 1950-1999, 00-49 → 2000-2049)
        yy = int(s[0:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        try:
            month, day = int(s[2:4]), int(s[4:6])
            hour, minute = int(s[6:8]), int(s[8:10])
            # YYMMDDHHMMSSZ = 13 символов; YYMMDDHHMMZ = 11 (без сек).
            # Раньше было >= 14 — резало секунды в 0.
            sec = int(s[10:12]) if len(s) >= 12 else 0
        except ValueError:
            return None
        return (
            f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{sec:02d}",
            "utc",
        )

    if node.tag == TAG_GENERALIZED_TIME:
        s = node.value.decode("ascii", errors="ignore").strip()
        if len(s) < 14:
            return None
        try:
            year = int(s[0:4])
            month, day = int(s[4:6]), int(s[6:8])
            hour, minute, sec = int(s[8:10]), int(s[10:12]), int(s[12:14])
        except ValueError:
            return None
        return (
            f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{sec:02d}",
            "generalized",
        )

    return None