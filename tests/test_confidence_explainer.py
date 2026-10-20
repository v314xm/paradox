"""Тесты Confidence explainer (P0.4)."""
from paradox.models import Finding


def test_confidence_reasons_default():
    """По умолчанию список причин пуст."""
    f = Finding(
        type="test", 
        value="test_value", 
        confidence=0.5
    )
    assert hasattr(f, "confidence_reasons")
    assert f.confidence_reasons == []

def test_confidence_reasons_add():
    """Можно добавлять причины."""
    f = Finding(
        type="dga", 
        value="DGA domain", 
        confidence=0.8
    )
    f.confidence_reasons.append("Высокая энтропия")
    f.confidence_reasons.append("Много NXDOMAIN")

    assert len(f.confidence_reasons) == 2
    assert "Высокая энтропия" in f.confidence_reasons

def test_confidence_reasons_to_dict():
    """Причины попадают в сериализованный JSON."""
    f = Finding(
        type="dga", 
        value="DGA domain", 
        confidence=0.8
    )
    f.confidence_reasons.append("Причина 1")

    d = f.to_dict()
    assert "confidence_reasons" in d
    assert d["confidence_reasons"] == ["Причина 1"]
