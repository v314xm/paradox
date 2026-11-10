"""GUI: вкладка «Код инжекта» показывает payload текстом, без HTML."""
import base64
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _report(payload: bytes, patterns=("&&", "id;"), extra_samples=()):
    samples = [{
        "direction": "request",
        "method": "POST",
        "host": "victim.local",
        "uri": "/api/cmd",
        "content_type": "text/plain",
        "size": len(payload),
        "truncated": False,
        "is_text": True,
        "text_b64": base64.b64encode(payload).decode("ascii"),
    }]
    samples.extend(extra_samples)
    return {
        "findings": [{
            "type": "command_injection",
            "value": "10.0.0.5 → /api/cmd",
            "evidence": {
                "matched_patterns": list(patterns),
                "payload_samples": samples,
            },
        }],
    }


def test_payload_is_shown_as_plain_text(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    payload = b'file=up\n&& id;\n<script>alert(1)</script>'
    view.update_data(_report(payload))

    assert len(view.payloads()) == 1
    shown = view.viewer().toPlainText()
    assert "&& id;" in shown
    # HTML не рендерится: разметка остаётся текстом.
    assert "<script>alert(1)</script>" in shown
    assert view.viewer().isReadOnly()


def test_control_characters_are_stripped(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(b"ok\x00\x1b[31mred\r\nline2"))

    shown = view.viewer().toPlainText()
    assert "\x00" not in shown
    assert "\x1b" not in shown
    assert "\r" not in shown
    assert "line2" in shown


def test_matched_patterns_are_highlighted(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(b"a && b; id; c"))

    selections = view.viewer().extraSelections()
    assert len(selections) == 2


def test_empty_report_shows_empty_state(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data({"findings": []})

    assert view.payloads() == []
    assert view.viewer().toPlainText() == ""


def test_binary_sample_falls_back_to_hexdump(qapp):
    from paradox_gui.views.payload_view import PayloadView

    payload = bytes(range(64))
    report = _report(payload)
    report["findings"][0]["evidence"]["payload_samples"][0]["is_text"] = False

    view = PayloadView()
    view.update_data(report)
    shown = view.viewer().toPlainText()

    assert "00000000" in shown
    assert "|" in shown


def test_body_samples_from_old_reports_are_shown(qapp):
    from paradox_gui.views.payload_view import PayloadView

    report = {
        "findings": [{
            "type": "command_injection",
            "value": "10.0.0.5 → /old",
            "evidence": {
                "matched_patterns": ["&&"],
                "methods": ["POST"],
                "hosts": ["victim.local"],
                "uri": "/old",
                "body_samples": ["up && id;"],
            },
        }],
    }
    view = PayloadView()
    view.update_data(report)

    assert len(view.payloads()) == 1
    assert "up && id;" in view.viewer().toPlainText()


def test_preview_renders_sanitized_html(qapp):
    from paradox_gui.views.payload_view import PayloadView

    payload = (
        b"<html><body><table><tr><td>Hello</td></tr></table>"
        b'<img src="http://tracker.example/p.png">'
        b"<script>alert(1)</script></body></html>"
    )
    view = PayloadView()
    view.update_data(_report(payload))

    view._preview_btn.setChecked(True)

    rendered = view._preview.toHtml()
    assert not view._preview.isHidden()
    assert "Hello" in rendered
    assert "tracker.example" not in rendered
    assert "alert(1)" not in rendered


def test_preview_skips_multipart_envelope(qapp):
    from paradox_gui.views.payload_view import PayloadView

    body = (
        b"------b\r\n"
        b'Content-Disposition: form-data; name="file"; '
        b'filename="shell.php"\r\n\r\n'
        b"<?php echo '<h2>Uploaded</h2>'; ?>\r\n"
        b"------b--"
    )
    view = PayloadView()
    view.update_data(_report(body))

    view._preview_btn.setChecked(True)

    rendered = view._preview.toPlainText()
    assert "Uploaded" in rendered
    assert "form-data" not in rendered


def test_preview_has_no_control_pictures(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(b"cmd=a\x00b%0dline2", patterns=()))

    view._preview_btn.setChecked(True)

    rendered = view._preview.toPlainText()
    assert "␀" not in rendered
    assert "line2" in rendered


def test_preview_is_disabled_for_binary(qapp):
    from paradox_gui.views.payload_view import PayloadView

    report = _report(bytes(range(64)))
    report["findings"][0]["evidence"]["payload_samples"][0]["is_text"] = False

    view = PayloadView()
    view.update_data(report)

    assert not view._preview_btn.isEnabled()
    assert view._preview.isHidden()


def test_url_decoded_payload_reads_like_code(qapp):
    from paradox_gui.views.payload_view import PayloadView

    body = (
        b'username=anonymous%00]]%0dlocal+h+%3d+io.popen("whoami")'
        b'%0dlocal+r+%3d+h%3aread("*a")%0dh%3aclose()%0dprint(r)%0d--'
        b"&password="
    )
    view = PayloadView()
    view.update_data(_report(body, patterns=("io.popen", "whoami")))

    shown = view.viewer().toPlainText()
    assert 'local h = io.popen("whoami")' in shown
    assert "local r = h:read" in shown
    assert "␀" in shown
    assert "%0d" not in shown
    assert view.viewer().extraSelections()


def test_url_decode_can_be_switched_off(qapp):
    from paradox_gui.views.payload_view import PayloadView

    body = b'username=a%00b%0dlocal+h+%3d+io.popen("x")'
    view = PayloadView()
    view.update_data(_report(body, patterns=("io.popen",)))

    view._variant_combo.setCurrentIndex(0)
    shown = view.viewer().toPlainText()

    assert "%0d" in shown
    assert "local+h" in shown


def test_url_decode_is_disabled_for_plain_text(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(b"a && b; id; c"))

    assert not view._variant_combo.isEnabled()
    assert "&&" in view.viewer().toPlainText()


def test_payload_window_holds_the_view(qapp):
    from paradox_gui.views.payload_window import PayloadWindow

    window = PayloadWindow()
    window.set_report(_report(b"a && b; id; c"))

    assert len(window.view.payloads()) == 1
    assert "&&" in window.view.viewer().toPlainText()

    window.clear()
    assert window.view.payloads() == []
