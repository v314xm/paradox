"""GUI: окно объяснений находки и противоречия."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _finding(**overrides) -> dict:
    base = {
        "type": "beaconing",
        "value": "10.0.0.5 -> 203.0.113.9",
        "confidence": 0.8,
        "severity": "medium",
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.9",
        "dst_port": 443,
        "evidence": {"count": 40},
    }
    base.update(overrides)
    return base


def _contradiction() -> dict:
    return {
        "rule": "sni_host_mismatch",
        "subject": "10.0.0.5",
        "severity": "high",
        "confidence": 0.72,
        "likely_causes": ["Domain fronting", "MITM-прокси"],
        "resolution_hint": "SNI=cdn.example ≠ Host=evil.example",
    }


def _texts(dialog) -> list[str]:
    from PySide6.QtWidgets import QLabel
    return [w.text() for w in dialog.findChildren(QLabel)]


def test_dialog_renders_stored_explanation(qapp):
    from paradox_gui.dialogs.explanation_dialog import ExplanationDialog

    row = _finding(explanation={
        "headline": "Хост держал регулярный канал.",
        "why": "Это похоже на C2.",
        "next_steps": ["Сверьте домен.", "Посмотрите тело."],
        "alternatives": ["Телеметрия ОС."],
        "confidence_note": "Уверенность 0.80 — средняя.",
        "beginner": "Компьютер стучится по расписанию.",
        "phase": "Управляющий канал (C2)",
        "techniques": ["T1071.001"],
    })
    dlg = ExplanationDialog(row)
    texts = _texts(dlg)

    assert "beaconing" in dlg.windowTitle()
    assert "Хост держал регулярный канал." in texts
    assert any("Сверьте домен." in t for t in texts)
    assert any("Это похоже на C2." in t for t in texts)

    # Дополнительные блоки свёрнуты, пока не нажат свой чип.
    assert not dlg._beginner_box.isVisibleTo(dlg)
    dlg.btn_beginner.setChecked(True)
    assert dlg._beginner_box.isVisibleTo(dlg)
    assert any("Компьютер стучится" in t for t in _texts(dlg))

    assert not dlg._alternatives_box.isVisibleTo(dlg)
    dlg.btn_alternatives.setChecked(True)
    assert dlg._alternatives_box.isVisibleTo(dlg)
    assert any("Телеметрия ОС." in t for t in _texts(dlg))


def test_dialog_computes_when_report_is_old(qapp):
    """Отчёт без ключа explanation: окно считает текст на месте."""
    from paradox_gui.dialogs.explanation_dialog import ExplanationDialog

    dlg = ExplanationDialog(_finding())

    assert any("10.0.0.5" in t for t in _texts(dlg))
    assert dlg.btn_copy.isEnabled()


def test_dialog_renders_contradiction(qapp):
    from paradox_gui.dialogs.explanation_dialog import ExplanationDialog

    dlg = ExplanationDialog(_contradiction())
    texts = _texts(dlg)

    assert "SNI=cdn.example ≠ Host=evil.example" in texts
    assert any("Domain fronting" in t for t in texts)


def test_copy_puts_markdown_on_clipboard(qapp):
    from PySide6.QtWidgets import QApplication

    from paradox_gui.dialogs.explanation_dialog import ExplanationDialog

    dlg = ExplanationDialog(_finding())
    dlg.btn_copy.click()

    text = QApplication.clipboard().text()
    assert "**Что произошло.**" in text
    assert "**Что делать дальше.**" in text


def test_action_panel_emits_explanation(qapp):
    from paradox_gui.widgets.finding_actions import FindingActionsPanel

    panel = FindingActionsPanel()
    seen: list[dict] = []
    panel.explanation_requested.connect(seen.append)

    assert not panel.btn_explain.isEnabled()
    panel.set_finding(_finding())
    assert panel.btn_explain.isEnabled()

    panel.btn_explain.click()
    assert seen and seen[0]["type"] == "beaconing"


def test_contradiction_card_emits_explanation(qapp):
    from PySide6.QtWidgets import QPushButton

    from paradox_gui.i18n import tr
    from paradox_gui.widgets.contradiction_card import ContradictionCard

    card = ContradictionCard(_contradiction())
    seen: list[dict] = []
    card.explanation_requested.connect(seen.append)

    button = next(
        b for b in card.findChildren(QPushButton)
        if b.text() == tr("contra.card_explain")
    )
    button.click()

    assert seen and seen[0]["rule"] == "sni_host_mismatch"


def test_finding_dialog_has_explain_button(qapp):
    from PySide6.QtWidgets import QPushButton

    from paradox_gui.dialogs.finding_dialog import FindingDialog
    from paradox_gui.i18n import tr

    dlg = FindingDialog(_finding())

    assert any(
        b.text() == tr("finding.explain")
        for b in dlg.findChildren(QPushButton)
    )
