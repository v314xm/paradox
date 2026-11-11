"""GUI: окно TLS-сертификатов."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _report(items):
    return {
        "certificates": {
            "total": len(items),
            "parse_errors": 2,
            "truncated": False,
            "items": items,
        },
    }


def test_dialog_lists_certificates(qapp):
    from paradox_gui.dialogs.certificates_dialog import CertificatesDialog

    dialog = CertificatesDialog(_report([{
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.9",
        "dst_port": 443,
        "subject_cn": "example.org",
        "issuer_cn": "Example CA",
        "self_signed": True,
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2026-01-01T00:00:00+00:00",
        "san_dns": ["example.org", "www.example.org"],
        "san_ips": [],
    }]))

    table = dialog.table
    assert table.rowCount() == 1
    assert table.item(0, 0).text() == "10.0.0.5 → 203.0.113.9:443"
    assert table.item(0, 1).text() == "example.org"
    assert "www.example.org" in table.item(0, 1).toolTip()
    assert table.item(0, 2).text() == "Example CA"
    assert table.item(0, 3).text() == "2025-01-01 → 2026-01-01"
    assert table.item(0, 4).text() == "да"


def test_dialog_shows_empty_state(qapp):
    from paradox_gui.dialogs.certificates_dialog import CertificatesDialog

    dialog = CertificatesDialog(_report([]))
    assert not hasattr(dialog, "table")
