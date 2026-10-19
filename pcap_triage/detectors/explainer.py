"""Автоматическое объяснение уверенности (confidence) детекторов.

Функция build_reasons принимает evidence и возвращает список строк,
описывающих, на основании чего детектор сделал вывод.
"""
from __future__ import annotations

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

def build_reasons(evidence: dict) -> list[str]:
    if not evidence:
        return []

    reasons = []
    # 1. Известные ключи
    for k, v in evidence.items():
        if k in LABELS:
            reasons.append(f"{LABELS[k]}: {v}")

    # 2. Если ничего не нашли (неизвестные ключи) — выводим первые 3 пары
    if not reasons:
        for k, v in list(evidence.items())[:3]:
            reasons.append(f"{k}: {v}")

    return reasons
