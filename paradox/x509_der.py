"""Совместимый фасад DER-парсера.

Реализация — в ``paradox.der``: один TLV-ридер для X.509 и Kerberos.
Импорт из этого модуля сохранён: x509_cert и tls_cert тянут отсюда
константы тэгов и хелперы.
"""
from __future__ import annotations

from paradox.der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_CTX_0,
    TAG_CTX_1,
    TAG_CTX_2,
    TAG_CTX_3,
    TAG_GENERALIZED_TIME,
    TAG_IA5_STRING,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_PRINTABLE_STRING,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_UTC_TIME,
    TAG_UTF8_STRING,
    DerError,
    DerNode,
    as_int,
    as_oid,
    as_str,
    as_time,
    parse_der,
)

__all__ = [
    "TAG_BIT_STRING",
    "TAG_BOOLEAN",
    "TAG_CTX_0",
    "TAG_CTX_1",
    "TAG_CTX_2",
    "TAG_CTX_3",
    "TAG_GENERALIZED_TIME",
    "TAG_IA5_STRING",
    "TAG_INTEGER",
    "TAG_NULL",
    "TAG_OCTET_STRING",
    "TAG_OID",
    "TAG_PRINTABLE_STRING",
    "TAG_SEQUENCE",
    "TAG_SET",
    "TAG_UTC_TIME",
    "TAG_UTF8_STRING",
    "DerError",
    "DerNode",
    "as_int",
    "as_oid",
    "as_str",
    "as_time",
    "parse_der",
]
