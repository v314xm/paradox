"""Автоматическое объяснение уверенности (confidence) детекторов.

Функция build_reasons принимает evidence и возвращает список строк,
описывающих, на основании чего детектор сделал вывод. Подписи
двуязычные: в английском отчёте не должно остаться русских названий
полей.
"""
from __future__ import annotations

from paradox.i18n import is_english

# Словарь: ключ в evidence -> человекочитаемое название
LABELS = {
    "packets_total": "Всего пакетов",
    "unique_src_ports": "Уникальных src-портов",
    "unique_dst_ports": "Уникальных dst-портов",
    "flow_count": "Количество потоков",
    "bytes_total": "Всего байт",
    "attempts": "Попыток",
    "queries": "Запросов",
    "nxdomain_count": "NXDOMAIN-ответов",
    "duration": "Длительность (сек)",
    "packets": "Пакетов",
    "bytes_sent": "Байт отправлено",
    "bytes_recv": "Байт получено",
    "dst_ports": "Целевых портов",
    "src_ips": "Уникальных источников",
    "dst_ips": "Уникальных назначений",
    "domains": "Доменов",
    "entropy": "Энтропия",
    "payload_size": "Размер payload",
    "sample": "Пример",
    "rule": "YARA-правило",
    "tags": "Теги",
    "filename": "Имя файла",
    "ja3": "JA3-отпечаток",
    "ja3s": "JA3S-отпечаток",
    "sni": "SNI",
    "user_agent": "User-Agent",
    "host": "Хост",
    "uri": "URI",
    "method": "HTTP-метод",
}

LABELS_EN = {
    "packets_total": "Total packets",
    "unique_src_ports": "Unique source ports",
    "unique_dst_ports": "Unique destination ports",
    "flow_count": "Flows",
    "bytes_total": "Total bytes",
    "attempts": "Attempts",
    "queries": "Queries",
    "nxdomain_count": "NXDOMAIN answers",
    "duration": "Duration (s)",
    "packets": "Packets",
    "bytes_sent": "Bytes sent",
    "bytes_recv": "Bytes received",
    "dst_ports": "Destination ports",
    "src_ips": "Unique sources",
    "dst_ips": "Unique destinations",
    "domains": "Domains",
    "entropy": "Entropy",
    "payload_size": "Payload size",
    "sample": "Sample",
    "rule": "YARA rule",
    "tags": "Tags",
    "filename": "Filename",
    "ja3": "JA3 fingerprint",
    "ja3s": "JA3S fingerprint",
    "sni": "SNI",
    "user_agent": "User-Agent",
    "host": "Host",
    "uri": "URI",
    "method": "HTTP method",
}


def build_reasons(evidence: dict) -> list[str]:
    if not evidence:
        return []

    labels = LABELS_EN if is_english() else LABELS
    reasons = []
    # 1. Известные ключи
    for k, v in evidence.items():
        if k in labels:
            reasons.append(f"{labels[k]}: {v}")

    # 2. Если ничего не нашли (неизвестные ключи) — выводим первые 3 пары
    if not reasons:
        for k, v in list(evidence.items())[:3]:
            reasons.append(f"{k}: {v}")

    return reasons
