"""
Извлечение полей из X.509 Certificate поверх x509_der.

Что берём:
  - subject_cn: последний CN в Subject
  - issuer_cn:  последний CN в Issuer
  - is_self_signed: issuer_raw == subject_raw (байтовое равенство)
  - not_before / not_after: из Validity (ISO-строки)
  - san_dns / san_ips: из extension 2.5.29.17

Чего НЕ делаем:
  - не валидируем подпись (нужен публичный ключ issuer)
  - не разбираем certificate chain (только отдельный сертификат)
  - не парсим KeyUsage, ExtendedKeyUsage, BasicConstraints и т.п.
    (для триажа не нужно; добавим по мере правил)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from paradox.x509_der import (
    TAG_CTX_0,
    TAG_CTX_3,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    DerError,
    DerNode,
    as_oid,
    as_str,
    as_time,
    parse_der,
)

# OID, которые нам нужны
CN_OID = "2.5.4.3"          # commonName (2.5.4.3)
SAN_OID = "2.5.29.17"       # subjectAltName


@dataclass
class Certificate:
    subject_cn: str | None = None
    issuer_cn: str | None = None
    is_self_signed: bool = False
    not_before: str | None = None
    not_after: str | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ips: list[str] = field(default_factory=list)


def parse_certificate(der: bytes) -> Certificate:
    """Распарсить DER сертификата. Бросает DerError на структурных ошибках."""
    root = parse_der(der)
    if root.tag != TAG_SEQUENCE or not root.children:
        raise DerError(
            f"Certificate: expected SEQUENCE, got tag 0x{root.tag:02X}"
        )

    tbs = root.children[0]
    if tbs.tag != TAG_SEQUENCE or not tbs.children:
        raise DerError("TBSCertificate: expected SEQUENCE")

    # version [0] EXPLICIT — если есть, сдвигаем индексы на 1
    idx = 1 if tbs.children[0].tag == TAG_CTX_0 else 0

    # [idx] serialNumber, [idx+1] signature, [idx+2] issuer,
    # [idx+3] validity, [idx+4] subject, [idx+5] subjectPublicKeyInfo
    if len(tbs.children) < idx + 5:
        raise DerError(
            f"TBSCertificate: too few fields ({len(tbs.children)})"
        )

    issuer_node = tbs.children[idx + 2]
    validity_node = tbs.children[idx + 3]
    subject_node = tbs.children[idx + 4]

    issuer_cn = _extract_last_cn(issuer_node)
    subject_cn = _extract_last_cn(subject_node)

    # Self-signed: побайтовое сравнение DER-содержимого Name.
    # Обычно совпадает точно, если issuer и subject идентичны.
    is_self_signed = issuer_node.value == subject_node.value

    not_before, not_after = _parse_validity(validity_node)

    san_dns: list[str] = []
    san_ips: list[str] = []
    for child in tbs.children[idx + 5:]:
        if child.tag == TAG_CTX_3:
            san_dns, san_ips = _parse_extensions_for_san(child)
            break

    return Certificate(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        is_self_signed=is_self_signed,
        not_before=not_before,
        not_after=not_after,
        san_dns=san_dns,
        san_ips=san_ips,
    )


def _extract_last_cn(name_node: DerNode) -> str | None:
    """Последний CN из RDNSequence. None если CN нет."""
    cn: str | None = None
    for rdn in name_node.children:
        for attr in rdn.children:
            if len(attr.children) < 2:
                continue
            try:
                if attr.children[0].tag != TAG_OID:
                    continue
                if as_oid(attr.children[0]) != CN_OID:
                    continue
                cn = as_str(attr.children[1])
            except DerError:
                continue
    return cn


def _parse_validity(node: DerNode) -> tuple[str | None, str | None]:
    if len(node.children) < 2:
        return None, None
    nb = as_time(node.children[0])
    na = as_time(node.children[1])
    return (
        nb[0] if nb else None,
        na[0] if na else None,
    )


def _parse_extensions_for_san(
    ext_node: DerNode,
) -> tuple[list[str], list[str]]:
    """Extensions [3] EXPLICIT → SEQUENCE OF Extension. Найти SAN."""
    if not ext_node.children:
        return [], []
    # ext_node.children[0] — SEQUENCE OF Extension
    seq = ext_node.children[0]
    for ext in seq.children:
        if len(ext.children) < 2:
            continue
        try:
            if ext.children[0].tag != TAG_OID:
                continue
            if as_oid(ext.children[0]) != SAN_OID:
                continue
        except DerError:
            continue
        for c in ext.children[1:]:
            if c.tag == TAG_OCTET_STRING:
                return _parse_san(c.value)
    return [], []


def _parse_san(der_bytes: bytes) -> tuple[list[str], list[str]]:
    """SubjectAltName = SEQUENCE OF GeneralName.

    dNSName     — context [2] IA5String (тег 0x82)
    iPAddress   — context [7] OCTET STRING (тег 0x87)
    Остальные GeneralName (email, URI, directory) игнорируем — не нужны.
    """
    dns_names: list[str] = []
    ips: list[str] = []
    try:
        root = parse_der(der_bytes)
    except DerError:
        return dns_names, ips

    if root.tag != TAG_SEQUENCE:
        return dns_names, ips

    for gn in root.children:
        if gn.tag_class != 2:
            continue
        low_tag = gn.tag & 0x1F

        if low_tag == 2:  # dNSName
            name = gn.value.decode("ascii", errors="ignore").strip()
            if name:
                dns_names.append(name)

        elif low_tag == 7:  # iPAddress
            if len(gn.value) == 4:
                ips.append(".".join(str(b) for b in gn.value))
            elif len(gn.value) == 16:
                parts = [
                    f"{gn.value[i]:02x}{gn.value[i + 1]:02x}"
                    for i in range(0, 16, 2)
                ]
                ips.append(":".join(parts))

    return dns_names, ips
