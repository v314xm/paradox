"""Тесты автогенерации confidence_reasons."""
from paradox.models import Finding
from paradox.detectors.explainer import build_reasons


def test_build_reasons_empty():
    assert build_reasons({}) == []


def test_build_reasons_known_keys():
    ev = {"packets_total": 100, "unique_src_ports": 50}
    reasons = build_reasons(ev)
    assert "Всего пакетов: 100" in reasons
    assert "Уникальных src-портов: 50" in reasons


def test_build_reasons_unknown_keys():
    ev = {"foo": "bar", "baz": 42}
    reasons = build_reasons(ev)
    assert len(reasons) == 2
    assert "foo: bar" in reasons


def test_finding_auto_reasons():
    f = Finding(
        type="test",
        value="test",
        confidence=0.8,
        evidence={"packets_total": 10},
    )
    assert f.confidence_reasons == ["Всего пакетов: 10"]


def test_finding_custom_reasons_override():
    f = Finding(
        type="test",
        value="test",
        confidence=0.8,
        evidence={"packets_total": 10},
        confidence_reasons=["Своя причина"],
    )
    assert f.confidence_reasons == ["Своя причина"]
