"""Извлечение фактов из CaptureState + Findings.

Факты — атомарные утверждения (source, subject, predicate, value).
Правила contradictions работают с фактами, не с findings напрямую:
так проще тестировать и комбинировать источники (finding + flow +
+ dns + arp).

Ключевые идеи:

1. ``value`` — необязателен. Если находка говорит «X атакует кого-то»
   (port_scan по десяткам хостов) или «X резолвит DGA»
   (nxdomain_burst — множество несозданных доменов), конкретный
   контр-субъект неизвестен. Роль — известна. Правило
   victim_makes_attack проверяет subject, а не value: pivot остаётся
   pivot'ом и без точного адресата.

2. Полярность findings (кто атакует, кто жертва) синхронизирована
   с entities.py (блок role_tags). Если меняешь там — меняй здесь.

3. Разные источники — разные функции ``extract_*``. Правила вызывают
   ту, которая им нужна, а не общий ``extract_facts``. Это даёт
   независимое тестирование и избегает лишней работы: правилу
   mac_ip_conflict не нужны attack-факты.

Реализация разложена по источникам: ``facts_attack``, ``facts_net``,
``facts_tls``. Этот модуль — совместимая точка импорта для правил,
тестов и monkeypatch на ``facts.extract_tls_cert_facts``.
"""
from __future__ import annotations

from paradox.contradictions.facts_attack import extract_attack_facts
from paradox.contradictions.facts_net import (
    extract_arp_facts,
    extract_asymmetry_facts,
    extract_direct_ip_facts,
    extract_protocol_on_port_facts,
)
from paradox.contradictions.facts_role import extract_role_facts
from paradox.contradictions.facts_tls import (
    _base_domain,
    _classify_ja3,
    _collect_ips_for,
    extract_ja3_ua_facts,
    extract_tls_cert_facts,
    extract_tls_host_facts,
)

__all__ = [
    "_base_domain",
    "_classify_ja3",
    "_collect_ips_for",
    "extract_arp_facts",
    "extract_attack_facts",
    "extract_asymmetry_facts",
    "extract_direct_ip_facts",
    "extract_ja3_ua_facts",
    "extract_protocol_on_port_facts",
    "extract_role_facts",
    "extract_tls_cert_facts",
    "extract_tls_host_facts",
]
