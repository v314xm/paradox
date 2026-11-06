"""Карточка одного провайдера в QuickCheckWindow."""
from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from paradox_gui.i18n import tr


def _verdict(provider_name: str, data: dict | None, error: str | None) -> str:
    if error:
        return "error"
    if not data:
        return "empty"
    # Провайдер-специфичная эвристика.
    if provider_name == "shodan_internetdb":
        if data.get("vulns"):
            return "bad"
        return "info"
    if provider_name == "abuseipdb":
        score = data.get("abuseConfidenceScore", 0)
        if score >= 50:
            return "bad"
        if score >= 10:
            return "warn"
        return "clean"
    if provider_name == "virustotal":
        stats = (data.get("data") or {}).get("attributes", {}).get(
            "last_analysis_stats", {},
        )
        mal = stats.get("malicious", 0)
        if mal >= 5:
            return "bad"
        if mal >= 1:
            return "warn"
        return "clean"
    if provider_name == "greynoise":
        if data.get("classification") in ("malicious",):
            return "bad"
        if data.get("noise"):
            return "warn"
        return "clean"
    if provider_name in ("urlhaus", "threatfox", "malwarebazaar"):
        if data.get("query_status") == "ok":
            return "bad"
        return "clean"
    if provider_name == "alienvault_otx":
        pulses = (data.get("pulse_info") or {}).get("count", 0)
        if pulses >= 3:
            return "bad"
        if pulses >= 1:
            return "warn"
        return "clean"
    if provider_name == "urlscan":
        results = data.get("results") or []
        if results:
            return "warn"
        return "clean"
    return "info"


def _short_summary(provider_name: str, data: dict | None,
                   error: str | None, ioc_type: str) -> str:
    """Одна-две строки «что это значит»."""
    if error:
        return error
    if not data:
        return "Нет данных у провайдера."
    if provider_name == "shodan_internetdb":
        ports = data.get("ports") or []
        hosts = data.get("hostnames") or []
        vulns = data.get("vulns") or []
        parts = []
        if ports:
            parts.append(f"Порты: {', '.join(map(str, ports[:10]))}")
        if hosts:
            parts.append(f"Хосты: {', '.join(hosts[:3])}")
        if vulns:
            parts.append(f"Уязвимости: {', '.join(vulns[:5])}")
        return " · ".join(parts) or "IP в базе Shodan, деталей нет."
    if provider_name == "abuseipdb":
        score = data.get("abuseConfidenceScore", 0)
        return (
            f"Score {score}/100 · ISP: {data.get('isp', '?')} · "
            f"Страна: {data.get('countryCode', '?')} · "
            f"Отчётов: {data.get('totalReports', 0)}"
        )
    if provider_name == "virustotal":
        stats = (data.get("data") or {}).get("attributes", {}).get(
            "last_analysis_stats", {},
        )
        if stats:
            return (
                f"malicious: {stats.get('malicious', 0)}, "
                f"suspicious: {stats.get('suspicious', 0)}, "
                f"harmless: {stats.get('harmless', 0)}, "
                f"undetected: {stats.get('undetected', 0)}"
            )
        return "Есть запись, но без анализа."
    if provider_name == "greynoise":
        return (
            f"noise: {data.get('noise')}, riot: {data.get('riot')}, "
            f"classification: {data.get('classification', '?')}"
        )
    if provider_name == "alienvault_otx":
        pulses = (data.get("pulse_info") or {})
        return (
            f"Пульсов: {pulses.get('count', 0)} · "
            f"первый: {pulses.get('pulses', [{}])[0].get('name', '?')[:60] if pulses.get('pulses') else '—'}"
        )
    if provider_name in ("urlhaus", "threatfox", "malwarebazaar"):
        if data.get("query_status") == "ok":
            n = len(data.get("data") or data.get("urls") or [])
            return f"Найдено: {n} записей"
        return "Нет данных."
    if provider_name == "urlscan":
        results = data.get("results") or []
        return f"Сканов: {len(results)}"
    return json.dumps(data, ensure_ascii=False)[:200]


class ProviderCard(QFrame):
    """Одна карточка-провайдер. Заголовок + summary + разворачиваемые детали."""

    def __init__(self, provider_name: str, result, ioc: str, ioc_type: str,
                 link: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("providerCard")

        self._build_ui(provider_name, result, ioc, ioc_type, link)

    def _build_ui(self, provider_name, result, ioc, ioc_type, link) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(6)

        data = result.data if result.ok else None
        error = None if result.ok else (result.error or "ошибка")
        verdict = _verdict(provider_name, data, error)

        # --- header row: [имя провайдера] [вердикт-точка] [кнопка] ---
        header = QHBoxLayout()
        header.setSpacing(8)

        name_lbl = QLabel(provider_name)
        name_lbl.setObjectName("providerName")
        header.addWidget(name_lbl)

        verdict_lbl = QLabel(tr(f"provider.verdict.{verdict}"))
        verdict_lbl.setObjectName("verdict")
        verdict_lbl.setProperty("verdict", verdict)
        header.addWidget(verdict_lbl)

        header.addStretch(1)

        if link:
            open_btn = QPushButton(tr("provider.open"))
            open_btn.setObjectName("small")
            open_btn.clicked.connect(
                lambda: QDesktopServices.openUrl(_qurl(link))
            )
            header.addWidget(open_btn)

        outer.addLayout(header)

        # --- summary ---
        summary = _short_summary(provider_name, data, error, ioc_type)
        s_lbl = QLabel(summary)
        s_lbl.setWordWrap(True)
        s_lbl.setObjectName("providerSummary")
        outer.addWidget(s_lbl)

        # --- details (свёрнуто по умолчанию) ---
        if data:
            self._details = QTextEdit()
            self._details.setReadOnly(True)
            self._details.setPlainText(
                json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
            )
            self._details.setMaximumHeight(220)
            self._details.setVisible(False)
            outer.addWidget(self._details)

            toggle = QPushButton(tr("provider.show_details"))
            toggle.setObjectName("small")
            toggle.setCheckable(True)
            toggle.toggled.connect(self._details.setVisible)
            toggle.toggled.connect(
                lambda c: toggle.setText(
                    tr("provider.hide_details") if c
                    else tr("provider.show_details")
                )
            )
            outer.addWidget(toggle, 0, Qt.AlignmentFlag.AlignLeft)


def _qurl(url: str):
    from PySide6.QtCore import QUrl
    return QUrl(url)
