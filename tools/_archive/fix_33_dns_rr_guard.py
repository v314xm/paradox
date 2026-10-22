"""Fix #33: AttributeError на rr.type в DNSExtractor.

Крафтовый/битый DNS-ответ (NXDOMAIN с answer-секцией, RDATA нулевой
длины, неизвестный тип) роняет `rr.type` с AttributeError. В pipeline
это ловится через except Exception — пакет теряется, NXDOMAIN не
учитывается, счётчик extractor_errors растёт.

Решение: try/except вокруг чтения rr.type. Битые RR пропускаются,
остальные (если есть) обрабатываются. Пакет не теряется целиком.

Найдено тестом test_nxdomain_counted_by_src_and_ts.
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, assert_applied

FIX_ID = "33-dns-rr-guard"
TITLE = "dns.py: защита от битых DNS RR (AttributeError: type)"

REL = "paradox/extractors/dns.py"

_OLD = """        if dns.qr == 1 and dns.an:
            for rr in dns.an:
                # SOA/MX/TXT и др. могут не иметь rdata — читаем
                # только для известных типов. Без этой проверки
                # rr.rdata падает с AttributeError.
                if rr.type not in (1, 28, 5):
                    continue
                raw = getattr(rr, 'rdata', None)
                if raw is None:
                    continue"""

_NEW = """        if dns.qr == 1 and dns.an:
            for rr in dns.an:
                # SOA/MX/TXT и др. могут не иметь rdata — читаем
                # только для известных типов. Без этой проверки
                # rr.rdata падает с AttributeError.
                #
                # v1.3.1: rr.type тоже может падать — крафтовый
                # DNS-ответ с битым RR бросает AttributeError или
                # ValueError. try/except сохраняет остальные RR.
                try:
                    rr_type = rr.type
                except (AttributeError, ValueError):
                    continue
                if rr_type not in (1, 28, 5):
                    continue
                raw = getattr(rr, 'rdata', None)
                if raw is None:
                    continue"""


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)
    assert_applied(root, REL, "except (AttributeError, ValueError)")
    return changed