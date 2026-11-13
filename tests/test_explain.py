"""Объяснения находок: покрытие типов и качество текста.

Страж тот же, что у `test_taxonomy.py`: новый тип находки без
объяснения валит прогон. Иначе вкладка объяснений тихо покажет
«объяснение не описано» для половины детекторов.

Вторая группа проверок — про качество: текст читает человек, поэтому в
нём не должно быть имён полей evidence и идентификаторов MITRE (они
показаны чипами в шапке окна).
"""
from __future__ import annotations

import re

import pytest

from paradox.contradictions.registry import RULES
from paradox.explain import (
    FINDING_SPECS,
    RULE_SPECS,
    Explanation,
    explain_contradiction,
    explain_finding,
    explanation_for,
)
from paradox.explain.render import build_context, render
from paradox.models import CaptureState
from paradox.pipeline.report import _explained
from paradox.taxonomy import SEVERITY_BY_TYPE
from tests.test_taxonomy import _collect_detector_types

#: Имена полей, которых не должно быть в тексте для человека.
_INTERNAL_TOKENS = (
    "evidence",
    "payload_samples",
    "body_samples",
    "user_agents",
    "http_status_known",
    "likely_causes",
    "resolution_hint",
)
_MITRE_ID = re.compile(r"T\d{4}")


def _finding(ftype: str = "beaconing", **overrides) -> dict:
    base = {
        "type": ftype,
        "value": "10.0.0.5 -> 203.0.113.9",
        "confidence": 0.8,
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.9",
        "dst_port": 443,
        "severity": "medium",
        "evidence": {},
    }
    base.update(overrides)
    return base


# ---------- покрытие ----------


def test_every_detector_type_has_explanation():
    missing = sorted(_collect_detector_types() - set(FINDING_SPECS))
    assert not missing, (
        "типы findings без объяснения в paradox/explain/catalog.py:\n  "
        + "\n  ".join(missing)
    )


def test_every_contradiction_rule_has_explanation():
    missing = sorted({r.name for r in RULES} - set(RULE_SPECS))
    assert not missing, (
        "правила contradictions без объяснения в "
        "paradox/explain/contradiction_catalog.py:\n  "
        + "\n  ".join(missing)
    )


def test_every_taxonomy_type_has_explanation():
    """Типы, которых сейчас не выдаёт ни один детектор, тоже описаны.

    `carved_file` приходит из timeline, `sni_mismatch` и `cloud_tunnel`
    остались в таксономии как исторические имена.
    """
    missing = sorted(set(SEVERITY_BY_TYPE) - set(FINDING_SPECS))
    assert not missing, (
        "типы таксономии без объяснения в paradox/explain/catalog.py:\n  "
        + "\n  ".join(missing)
    )


def test_no_explanation_for_unknown_types():
    """Опечатка в имени типа не должна копиться мёртвой записью."""
    extra = sorted(set(FINDING_SPECS) - set(SEVERITY_BY_TYPE))
    assert not extra, f"в каталоге есть записи для неизвестных типов: {extra}"


def test_specs_are_complete():
    for ftype, spec in FINDING_SPECS.items():
        assert spec.headline.strip(), f"{ftype}: пустой headline"
        assert spec.why.strip(), f"{ftype}: пустой why"
        assert spec.next_steps, f"{ftype}: нет next_steps"
        assert spec.beginner.strip(), f"{ftype}: пустой beginner"


def test_rule_specs_are_complete():
    for rule, spec in RULE_SPECS.items():
        assert spec.headline.strip(), f"{rule}: пустой headline"
        assert spec.why.strip(), f"{rule}: пустой why"
        assert spec.next_steps, f"{rule}: нет next_steps"


def test_texts_do_not_leak_internal_field_names():
    bad = []
    specs = list(FINDING_SPECS.items()) + list(RULE_SPECS.items())
    for name, spec in specs:
        text = " ".join(
            (spec.headline, spec.why, spec.beginner,
             *spec.next_steps, *spec.alternatives)
        ).lower()
        bad.extend(
            f"{name}: {token}" for token in _INTERNAL_TOKENS
            if token in text
        )
    assert not bad, "в текстах для человека имена полей:\n  " + "\n  ".join(bad)


def test_why_explains_instead_of_listing_techniques():
    """MITRE показан чипами в шапке — в прозе он только мешает."""
    bad = [
        ftype for ftype, spec in FINDING_SPECS.items()
        if _MITRE_ID.search(spec.why) or _MITRE_ID.search(spec.beginner)
    ]
    assert not bad, f"идентификаторы MITRE в why/beginner: {bad}"


# ---------- текст ----------


@pytest.mark.parametrize("ftype", sorted(FINDING_SPECS))
def test_explanation_has_no_unfilled_placeholders(ftype):
    exp = explain_finding(_finding(ftype))
    texts = (exp.headline, exp.why, exp.beginner, *exp.next_steps)
    for text in texts:
        assert "{" not in text and "}" not in text, (ftype, text)


def test_headline_uses_concrete_values():
    exp = explain_finding(_finding("beaconing"))
    assert "10.0.0.5" in exp.headline
    assert "203.0.113.9" in exp.headline


def test_unknown_type_falls_back_to_generic_text():
    exp = explain_finding(_finding("plugin_type"))
    assert "plugin_type" in exp.headline
    assert "10.0.0.5" in exp.headline
    assert exp.next_steps


def test_confidence_note_matches_level():
    high = explain_finding(_finding(confidence=0.9))
    medium = explain_finding(_finding(confidence=0.7))
    low = explain_finding(_finding(confidence=0.4))

    assert "0.90" in high.confidence_note
    assert "0.70" in medium.confidence_note
    assert "0.40" in low.confidence_note
    assert high.confidence_note != low.confidence_note


def test_finding_carries_phase_and_techniques():
    exp = explain_finding(_finding("beaconing"))
    assert exp.phase == "Управляющий канал (C2)"
    assert "T1071.001" in exp.techniques


def test_contradiction_reuses_likely_causes():
    contradiction = {
        "rule": "sni_host_mismatch",
        "subject": "10.0.0.5",
        "severity": "high",
        "confidence": 0.72,
        "likely_causes": ["Domain fronting", "MITM-прокси"],
        "resolution_hint": "SNI != Host",
        "facts": [
            {
                "source": "sni",
                "subject": "10.0.0.5",
                "predicate": "connects_to",
                "value": "cdn.example",
                "ts": 1.0,
                "confidence": 0.9,
                "evidence": {},
            },
        ],
    }
    exp = explain_contradiction(contradiction)

    assert exp.alternatives == ("Domain fronting", "MITM-прокси")
    # «Что произошло» — готовая проза правила с конкретными значениями.
    assert exp.headline == "SNI != Host"
    assert exp.next_steps
    assert "0.72" in exp.confidence_note


def test_unknown_rule_falls_back():
    exp = explain_contradiction({"rule": "custom_rule", "subject": "1.2.3.4"})
    assert "1.2.3.4" in exp.headline
    assert exp.next_steps


def test_big_numbers_are_grouped():
    exp = explain_finding(
        _finding("large_transfer", evidence={"total_bytes": 132329214}),
    )
    assert "132 329 214" in exp.headline


def test_float_sizes_are_grouped_not_raw():
    ctx = build_context({"evidence": {"avg_body_bytes": 30522.4}})
    assert render("{avg_body_bytes}", ctx) == "30 522"


def test_direction_is_written_in_russian():
    outbound = explain_finding(_finding(
        "large_transfer",
        evidence={"total_bytes": 132329214, "direction": "outbound"},
    ))
    inbound = explain_finding(_finding(
        "large_transfer",
        evidence={"total_bytes": 132329214, "direction": "inbound"},
    ))

    assert "наружу" in outbound.headline
    assert "внутрь" in inbound.headline


def test_typosquatting_kind_is_explained():
    exp = explain_finding(_finding(
        "typosquatting",
        value="dng-microsoftds.com",
        evidence={"brand": "microsoft", "kind": "contains", "queries": 1},
    ))
    assert "содержит бренд" in exp.headline


# ---------- сериализация и Markdown ----------


def test_explanation_roundtrip_and_markdown():
    exp = explain_finding(_finding("beaconing"))
    again = Explanation.from_dict(exp.to_dict())

    assert again.headline == exp.headline
    assert again.next_steps == exp.next_steps
    assert again.alternatives == exp.alternatives
    assert again.phase == exp.phase

    md = again.to_markdown()
    assert "**Что произошло.**" in md
    assert "**Что делать дальше.**" in md
    assert "1. " in md
    assert "**Уверенность.**" in md


def test_explanation_for_uses_stored_text():
    row = _finding(
        "beaconing",
        explanation={"headline": "готовый текст", "why": ""},
    )
    assert explanation_for(row).headline == "готовый текст"


def test_explanation_for_computes_when_report_is_old():
    """Старый отчёт без ключа explanation не должен давать пустое окно."""
    row = _finding("beaconing")
    assert "explanation" not in row
    assert "10.0.0.5" in explanation_for(row).headline


def test_explanation_for_detects_contradiction():
    row = {
        "rule": "sni_host_mismatch",
        "subject": "10.0.0.5",
        "confidence": 0.7,
        "likely_causes": ["Domain fronting"],
        "resolution_hint": "SNI != Host",
    }
    exp = explanation_for(row)

    assert exp.headline == "SNI != Host"
    assert exp.alternatives == ("Domain fronting",)


# ---------- отчёт ----------


def test_report_row_gets_explanation():
    state = CaptureState()
    row = _explained(
        _finding("beaconing"), explain_finding, state, "finding",
    )

    assert row["explanation"]["headline"]
    assert "explain:finding" not in state.extractor_errors


def test_explanation_failure_does_not_break_row():
    def boom(_row):
        raise RuntimeError("boom")

    state = CaptureState()
    row = _explained(_finding("beaconing"), boom, state, "finding")

    assert "explanation" not in row
    assert row["type"] == "beaconing"
    assert state.extractor_errors["explain:finding"] == 1
