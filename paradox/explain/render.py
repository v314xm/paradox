"""Сборка текста объяснения из шаблона и данных находки.

Шаблоны в `catalog.py` / `contradiction_catalog.py` — обычные строки с
подстановками `{key}`. Значения берутся из полей находки и из
скалярных ключей `evidence`. Правило одно: отсутствующее значение не
должно ронять отчёт — оно печатается как «—».
"""
from __future__ import annotations

import re

from paradox.i18n import L, is_english
from paradox.taxonomy import phase_for

PHASE_LABELS_RU: dict[str, str] = {
    "recon": "Разведка",
    "initial_access": "Первичный доступ",
    "execution": "Выполнение",
    "persistence": "Закрепление",
    "credential_access": "Доступ к учётным данным",
    "lateral_movement": "Боковое перемещение",
    "c2": "Управляющий канал (C2)",
    "exfiltration": "Эксфильтрация",
    "impact": "Воздействие",
    "other": "Прочее",
}

PHASE_LABELS_EN: dict[str, str] = {
    "recon": "Reconnaissance",
    "initial_access": "Initial access",
    "execution": "Execution",
    "persistence": "Persistence",
    "credential_access": "Credential access",
    "lateral_movement": "Lateral movement",
    "c2": "Command and control (C2)",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "other": "Other",
}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_MISSING = "—"
_MAX_LIST_ITEMS = 3

#: Служебные значения, которые в текст идут по-русски.
#: Ключ — поле evidence, значение — карта «машинное → человеческое».
_VALUE_LABELS: dict[str, dict[str, str]] = {
    "direction": {
        "outbound": "наружу",
        "inbound": "внутрь",
        "internal": "внутри сети",
    },
    "kind": {
        "contains": "имя содержит бренд",
        "levenshtein": "имя отличается опечаткой",
    },
}

_VALUE_LABELS_EN: dict[str, dict[str, str]] = {
    "direction": {
        "outbound": "outbound",
        "inbound": "inbound",
        "internal": "within the network",
    },
    "kind": {
        "contains": "name contains the brand",
        "levenshtein": "name differs by a typo",
    },
}


def phase_label(finding_type: str) -> str:
    labels = PHASE_LABELS_EN if is_english() else PHASE_LABELS_RU
    return labels.get(phase_for(finding_type), L("Прочее", "Other"))


def _fmt(value) -> str:
    if value is None:
        return _MISSING
    if isinstance(value, bool):
        return L("да", "yes") if value else L("нет", "no")
    if isinstance(value, float):
        if value.is_integer():
            return _fmt(int(value))
        if abs(value) >= 10_000:
            # Средний размер тела не должен печататься как 30522.4.
            return _fmt(int(round(value)))
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if isinstance(value, int):
        # Разряды: «132 329 214» читается, «132329214» — нет.
        if abs(value) >= 10_000:
            return f"{value:,}".replace(",", " ")
        return str(value)
    if isinstance(value, (list, tuple)):
        head = [_fmt(v) for v in list(value)[:_MAX_LIST_ITEMS]]
        tail = "" if len(value) <= _MAX_LIST_ITEMS else " …"
        return ", ".join(head) + tail
    return str(value)


def _evidence_scalars(evidence) -> dict[str, str]:
    """Плоские значения evidence + короткие списки скаляров."""
    out: dict[str, str] = {}
    if not isinstance(evidence, dict):
        return out
    for key, value in evidence.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, (list, tuple)) and not all(
            isinstance(v, (str, int, float)) for v in value
        ):
            continue
        name = str(key)
        text = _fmt(value)
        labels = (_VALUE_LABELS_EN if is_english() else _VALUE_LABELS).get(name)
        if labels and isinstance(value, str):
            text = labels.get(value, text)
        out[name] = text
    return out


def build_context(finding: dict) -> dict[str, str]:
    """Словарь подстановок для шаблонов объяснения."""
    ctx = _evidence_scalars(finding.get("evidence"))
    ctx.update({
        "value": _fmt(finding.get("value")),
        "type": _fmt(finding.get("type")),
        "src": _fmt(finding.get("src_ip")),
        "dst": _fmt(finding.get("dst_ip")),
        "port": _fmt(finding.get("dst_port")),
        "conf": _fmt(finding.get("confidence")),
        "severity": _fmt(finding.get("severity")),
    })
    return ctx


def render(template: str, ctx: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(
        lambda m: ctx.get(m.group(1), _MISSING), template,
    )


def confidence_note(confidence) -> str:
    if not isinstance(confidence, (int, float)):
        return ""
    shown = f"{confidence:.2f}"
    if confidence >= 0.85:
        return L(
            f"Уверенность {shown} — высокая: сработали все признаки "
            f"правила. Это по-прежнему эвристика, а не доказательство.",
            f"Confidence {shown} — high: every signal of the rule fired. "
            f"This is still a heuristic, not proof.",
        )
    if confidence >= 0.6:
        return L(
            f"Уверенность {shown} — средняя: признаки совпали, но "
            f"легитимные объяснения не исключены (см. ниже).",
            f"Confidence {shown} — medium: the signals matched, but "
            f"legitimate explanations are not excluded (see below).",
        )
    return L(
        f"Уверенность {shown} — низкая: это сигнал к ручной проверке, "
        f"а не вывод. Один такой находки мало для вердикта.",
        f"Confidence {shown} — low: this is a prompt for manual review, "
        f"not a conclusion. One such finding is not enough for a verdict.",
    )


def facts_summary(contradiction: dict) -> str:
    """Компактная строка «источник: предикат = значение» по фактам."""
    parts: list[str] = []
    for fact in contradiction.get("facts") or ():
        source = fact.get("source", "?")
        predicate = fact.get("predicate", "?")
        value = fact.get("value", "?")
        parts.append(f"{source}: {predicate} = {value}")
    return "; ".join(parts[:_MAX_LIST_ITEMS])
