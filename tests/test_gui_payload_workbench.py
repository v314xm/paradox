"""GUI: поиск, multipart-части, hex-страницы и инспектор payload'а."""
import base64
import os
import zlib

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _sample(payload: bytes, **extra) -> dict:
    sample = {
        "direction": "request",
        "method": "POST",
        "host": "victim.local",
        "uri": "/upload",
        "content_type": "application/octet-stream",
        "size": len(payload),
        "truncated": False,
        "is_text": True,
        "sha256": "a" * 64,
        "text_b64": base64.b64encode(payload).decode("ascii"),
    }
    sample.update(extra)
    return sample


def _report(*samples: dict, patterns=()) -> dict:
    return {
        "findings": [{
            "type": "command_injection",
            "value": "10.0.0.5 → /upload",
            "evidence": {
                "matched_patterns": list(patterns),
                "payload_samples": list(samples),
            },
        }],
    }


def _part(kind: str, data: bytes, **extra) -> dict:
    part = {
        "kind": kind,
        "name": "appeal_id" if kind == "field" else "me",
        "filename": "" if kind == "field" else "me.bin",
        "content_type": "" if kind == "field" else "application/octet-stream",
        "offset": 0 if kind == "field" else 70000,
        "size": len(data),
        "sha256": "b" * 64,
        "excerpt_size": len(data),
        "excerpt_truncated": False,
        "excerpt_b64": base64.b64encode(data).decode("ascii"),
    }
    part.update(extra)
    return part


def test_search_counts_and_navigates(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(_sample(b"alpha beta alpha")))

    view._search.setText("alpha")

    assert view._search_count.text() == "1/2"
    assert len(view.viewer().extraSelections()) == 2
    view._goto_hit(1)
    assert view._search_count.text() == "2/2"

    view._search_case.setChecked(True)
    view._search.setText("ALPHA")
    assert view._search_count.text() == "0"


def test_multipart_part_can_be_selected(qapp):
    from paradox_gui.views.payload_view import PayloadView

    body = b"a" * 64
    file_data = b"hello from the uploaded file"
    sample = _sample(
        body,
        parts=[
            _part("field", b"9e35ed-00e9-4ca6"),
            _part("file", file_data),
        ],
    )
    view = PayloadView()
    view.update_data(_report(sample))

    assert len(view.parts()) == 2
    assert not view._parts_combo.isHidden()
    view._parts_combo.setCurrentIndex(2)

    assert view.current_bytes() == file_data
    assert "hello from the uploaded file" in view.viewer().toPlainText()
    assert "offset" in view._meta.text()


def test_hex_pages_move_by_4kb(qapp):
    from paradox_gui.views.payload_view import PayloadView

    payload = bytes(range(256)) * 40
    view = PayloadView()
    view.update_data(_report(_sample(payload)))
    view._hex_box.setChecked(True)

    assert "00000000" in view.viewer().toPlainText()
    view._change_hex_page(1)
    shown = view.viewer().toPlainText()
    assert "00001000" in shown
    assert "0x00001000" in view._hex_offset.text()


def test_inspector_shows_iocs_and_hashes(qapp):
    from paradox_gui.views.payload_view import PayloadView

    payload = (
        b"url=http://evil.example/x ip=10.0.0.5 "
        b"mail=bad@evil.example " + b"c" * 64
    )
    view = PayloadView()
    view.update_data(_report(_sample(payload)))
    view._inspector_btn.setChecked(True)

    rendered = view._inspector.toHtml()
    assert view.analysis() is not None
    assert "evil.example" in rendered
    assert "10.0.0.5" in rendered
    assert "SHA256" in rendered
    assert "c" * 64 in rendered


def test_inspector_lists_embedded_pe(qapp):
    from paradox_gui.views.payload_view import PayloadView

    data = bytearray(0x200)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\0\0"
    data[0x44:0x46] = (0x8664).to_bytes(2, "little")
    data[0x46:0x48] = (0).to_bytes(2, "little")
    view = PayloadView()
    view.update_data(_report(_sample(bytes(data))))
    view._inspector_btn.setChecked(True)

    assert "PE @ 0x" in view._inspector.toHtml()
    assert not view._embedded_row_widget.isHidden()
    assert view._embedded_combo.count() == 1


def test_same_payload_occurrences(qapp):
    from paradox_gui.views.payload_view import PayloadView

    first = _sample(b"same body", sha256="d" * 64)
    second = _sample(b"same body", sha256="d" * 64, uri="/second")
    view = PayloadView()
    view.update_data(_report(first, second))

    assert len(view.occurrences()) == 2


def test_deobfuscated_variant_is_selected(qapp):
    from paradox_gui.views.payload_view import PayloadView

    code = b"echo 'deobf';"
    compressor = zlib.compressobj(wbits=-15)
    packed = compressor.compress(code) + compressor.flush()
    encoded = base64.b64encode(packed)
    body = b"<?php eval(gzinflate(base64_decode('" + encoded + b"'))); ?>"
    view = PayloadView()
    view.update_data(_report(_sample(body)))

    assert "echo 'deobf';" in view.viewer().toPlainText()
    labels = [
        view._variant_combo.itemText(i)
        for i in range(view._variant_combo.count())
    ]
    assert any("Deflate" in label for label in labels)


def test_export_markdown_redacts_secrets(qapp):
    from paradox_gui.views.payload_view import PayloadView

    view = PayloadView()
    view.update_data(_report(_sample(
        b"password=hunter2 url=http://evil.example/x",
    )))

    markdown = view._export_markdown()

    assert "hunter2" not in markdown
    assert "<redacted>" in markdown
    assert "http://evil.example/x" in markdown
    assert "SHA256" in markdown
