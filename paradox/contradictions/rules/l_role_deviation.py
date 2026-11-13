"""
Правило role_deviation: поведение хоста противоречит базовой роли.

Хост классифицируется по OUI MAC («паспорт»): workstation, server,
network_device. Затем наблюдается, что он делает в трафике: отвечает
как веб-сервер (80/443), как SMB-сервер (445) или сканирует сеть.

Если «паспорт» и поведение не сходятся — противоречие:
  workstation + acting_as_webserver → critical (веб-шелл /
      несанкционированный сервис на пользовательской машине);
  workstation + acting_as_smb_server → high (самопальный share);
  workstation/server + acting_as_scanner → high (компрометация
      и разведка изнутри);
  network_device + acting_as_smb_server/scanner → high/medium
      (скомпрометированное сетевое устройство).

Отклонений, которые НЕ генерим:
  server + acting_as_webserver/smb_server — сервер легитимно сервер;
  network_device + acting_as_webserver — веб-интерфейс управления
      маршрутизатора/коммутатора это норма.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.models import CaptureState, Finding

# (assigned_role, observed_behavior) → severity.
# Отсутствие пары = легитимное сочетание, противоречия нет.
_DEVIATION_SEVERITY: dict[tuple[str, str], str] = {
    ("workstation", "acting_as_webserver"): "critical",
    ("workstation", "acting_as_smb_server"): "high",
    ("workstation", "acting_as_scanner"): "high",
    ("server", "acting_as_scanner"): "high",
    ("network_device", "acting_as_smb_server"): "high",
    ("network_device", "acting_as_scanner"): "medium",
}

_SEVERITY_CONFIDENCE = {"critical": 0.85, "high": 0.7, "medium": 0.6}

_ROLE_LABEL = {
    "workstation": "рабочая станция",
    "server": "сервер",
    "network_device": "сетевое устройство",
}

_BEHAVIOR_LABEL = {
    "acting_as_webserver": "отвечает как веб-сервер (80/443)",
    "acting_as_smb_server": "отвечает как SMB-сервер (445)",
    "acting_as_scanner": "сканирует сеть",
}


class RoleDeviationRule:
    name = "role_deviation"
    severity_base = "high"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from paradox.contradictions.facts import extract_role_facts
        return extract_role_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        roles: dict[str, Fact] = {}
        behaviors: dict[str, list[Fact]] = {}

        for f in facts:
            if f.predicate == "assigned_role":
                roles[f.subject] = f
            elif f.predicate == "observed_behavior":
                behaviors.setdefault(f.subject, []).append(f)

        out: list[Contradiction] = []
        for subject, role_fact in roles.items():
            role = role_fact.value
            for b_fact in behaviors.get(subject, []):
                behavior = b_fact.value
                severity = _DEVIATION_SEVERITY.get((role, behavior))
                if severity is None:
                    continue
                out.append(Contradiction(
                    rule=self.name,
                    subject=subject,
                    facts=[role_fact, b_fact],
                    severity=severity,
                    confidence=_SEVERITY_CONFIDENCE[severity],
                    likely_causes=self._causes(role, behavior),
                    resolution_hint=self._hint(subject, role_fact, b_fact),
                ))

        out.sort(key=lambda c: (-c.priority, -c.confidence, c.subject))
        return out

    @staticmethod
    def _causes(role: str, behavior: str) -> list[str]:
        """Причины, первая — самая вероятная для данной пары."""
        if behavior == "acting_as_scanner":
            return [
                "Компрометация: хост разведывает сеть изнутри",
                "Легитимный агент мониторинга или сканер уязвимостей",
                "Неправильно настроенное приложение, рассылающее пробы",
            ]
        if behavior == "acting_as_webserver":
            return [
                "Веб-шелл или несанкционированный веб-сервис",
                "Легитимный локальный сервис (админка, агент, dev-сервер)",
                "Хост перепрофилирован, но «паспорт» (OUI) не обновлён",
            ]
        return [
            "Несанкционированный файловый обмен на хосте",
            "Легитимный служебный share (если хост — сервер/общий)",
            "Хост перепрофилирован, но «паспорт» (OUI) не обновлён",
        ]

    @staticmethod
    def _hint(subject: str, role_fact: Fact, b_fact: Fact) -> str:
        role = role_fact.value
        behavior = b_fact.value
        role_txt = _ROLE_LABEL.get(role, role)
        beh_txt = _BEHAVIOR_LABEL.get(behavior, behavior)
        mac = role_fact.evidence.get("mac") or "?"

        if behavior == "acting_as_scanner":
            targets = b_fact.evidence.get("targets", "?")
            ports = b_fact.evidence.get("distinct_ports", "?")
            return (
                f"{subject}: по OUI {mac} — {role_txt}, но инициировал "
                f"соединения к {targets} целям на {ports} портах. "
                f"Проверить, легитимен ли такой охват для этого хоста."
            )
        served = b_fact.evidence.get("served_bytes", "?")
        return (
            f"{subject}: по OUI {mac} — {role_txt}, но {beh_txt} "
            f"(отдано {served} Б). Проверить, легитимен ли такой "
            f"сервис на этом хосте."
        )
