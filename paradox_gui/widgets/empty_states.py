"""
EmptyState helpers для findings и contradictions.
"""
from __future__ import annotations

from PySide6.QtWidgets import QLabel


def findings_empty_label(n_flows: int, n_http: int, n_entities: int) -> QLabel:
    _DETECTORS = __import__(
        'paradox.pipeline', fromlist=['DETECTORS'],
    ).DETECTORS
    label = QLabel(
        "<i style='color:#a0a0b0;'>Аномалий не обнаружено.</i><br><br>"
        f"<span style='color:#a0a0b0;font-size:12px;'>"
        f"Проверено {n_flows} flow, {n_http} HTTP-сессий, "
        f"{n_entities} сущностей. Ни один из {len(_DETECTORS)} детекторов не сработал."
        f"</span>"
    )
    label.setWordWrap(True)
    label.setStyleSheet("padding: 12px 4px;")
    return label


def contradictions_empty_label() -> QLabel:
    label = QLabel(
        "<i style='color:#a0a0b0;'>Согласованность между слоями "
        "подтверждена.</i><br><br>"
        "<span style='color:#a0a0b0;font-size:12px;'>"
        "7 правил проверили: SNI vs HTTP Host, MAC vs IP, "
        "JA3 vs User-Agent, роли vs поведение."
        "</span>"
    )
    label.setWordWrap(True)
    label.setStyleSheet("padding: 12px 4px;")
    return label
