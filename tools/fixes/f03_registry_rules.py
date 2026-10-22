"""f03: registry.py — run_all(state, findings, config, rules=) + try/except."""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f03: contradictions/registry.py — rules param + try/except"
FILES = ["paradox/contradictions/registry.py"]

_OLD = '''def run_all(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
) -> list[Contradiction]:
    """Прогнать все правила. Возвращает отфильтрованные + отсортированные."""
    out: list[Contradiction] = []
    for rule in RULES:
        facts = rule.extract_facts(state, findings, config)
        out.extend(rule.find_contradictions(facts))

    out.sort(key=lambda c: (
        SEVERITY_ORDER.get(c.severity, 99),
        -c.confidence,
        c.subject,
    ))
    return out'''

_NEW = '''def run_all(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
    rules: list[ContradictionRule] | None = None,
) -> list[Contradiction]:
    """Прогнать все правила. Возвращает отфильтрованные + отсортированные.

    rules — опциональный список правил (default — глобальный RULES).
    Позволяет вызывающему коду отключать правила без monkey-patch.
    Каждое правило обёрнуто в try/except: одно упавшее не валит
    остальные. Ошибки считаются в state.extractor_errors с префиксом
    "rule:<name>" — видны в summary отчёта.
    """
    active = list(rules) if rules is not None else RULES
    out: list[Contradiction] = []
    for rule in active:
        try:
            facts = rule.extract_facts(state, findings, config)
            out.extend(rule.find_contradictions(facts))
        except Exception:
            rule_name = type(rule).__name__
            key = f"rule:{rule_name}"
            prev = state.extractor_errors[key]
            state.extractor_errors[key] = prev + 1
            if getattr(config, "debug_log_extractor_errors", False) and prev == 0:
                import logging
                logging.exception(
                    "contradiction rule %s failed (first occurrence)",
                    rule_name,
                )

    out.sort(key=lambda c: (
        SEVERITY_ORDER.get(c.severity, 99),
        -c.confidence,
        c.subject,
    ))
    return out'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "rules: list[ContradictionRule] | None = None")
    assert_applied(root, FILES[0], "active = list(rules) if rules is not None else RULES")
    assert_applied(root, FILES[0], 'key = f"rule:{rule_name}"')
