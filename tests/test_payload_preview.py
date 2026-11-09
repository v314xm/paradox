"""Статический предпросмотр payload'а: разметка без исполнения."""
from paradox_gui.payload_preview import render_safe_html


def test_scripts_and_handlers_are_removed():
    out = render_safe_html(
        b'<div onclick="alert(1)"><script>alert(2)</script><b>ok</b></div>'
    )

    lowered = out.lower()
    assert "<script" not in lowered
    assert "alert(1)" not in out
    assert "alert(2)" not in out
    assert "<b>ok</b>" in out


def test_forms_images_iframes_and_meta_are_dropped():
    out = render_safe_html(
        b'<form action="http://evil"><input name="x"></form>'
        b'<img src="http://evil/p.png">'
        b'<iframe src="http://evil"></iframe>'
        b'<meta http-equiv="refresh" content="0;url=http://evil">'
    )

    lowered = out.lower()
    for bad in ("<form", "<input", "<img", "<iframe", "<meta"):
        assert bad not in lowered
    assert "evil" not in out


def test_links_keep_text_but_lose_href():
    out = render_safe_html(b'<a href="http://evil/x">click</a>')

    assert "href" not in out.lower()
    assert "click" in out


def test_php_and_asp_blocks_become_placeholder():
    out = render_safe_html(
        b"<p>hi</p><?php sys" b"tem($_GET['c']); ?><% Response.Write(1) %>"
    )

    assert "system(" not in out
    assert "Response.Write" not in out
    assert "{ серверный код }" in out
    assert "<p>hi</p>" in out


def test_markup_inside_php_strings_is_previewed():
    out = render_safe_html(
        b"<?php\n@session_start();\n"
        b"echo '<table><tr><td>ok</td></tr></table>';\n?>"
    )

    assert "<table><tr><td>ok</td></tr></table>" in out
    assert "session_start" not in out
    assert "<?" not in out


def test_php_without_markup_keeps_placeholder():
    out = render_safe_html(b"<?php echo 1 + 1; ?>")

    assert "{ серверный код }" in out
    assert "echo" not in out


def test_multipart_envelope_is_skipped():
    body = (
        b"------b\r\n"
        b'Content-Disposition: form-data; name="file"; '
        b'filename="shell.php"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"<?php echo '<h1>Files</h1>'; ?>\r\n"
        b"------b--"
    )

    out = render_safe_html(body)

    assert "<h1>Files</h1>" in out
    assert "Content-Disposition" not in out
    assert "filename" not in out


def test_multipart_with_several_parts_shows_only_markup():
    body = (
        b"------b\r\n"
        b'Content-Disposition: form-data; name="up"\r\n\r\n'
        b"up\r\n"
        b"------b\r\n"
        b'Content-Disposition: form-data; name="file"; '
        b'filename="shell.php"\r\n\r\n'
        b"<?php echo '<h1>Files</h1>'; ?>\r\n"
        b"------b--"
    )

    out = render_safe_html(body)

    assert "<h1>Files</h1>" in out
    assert "form-data" not in out
    assert "filename" not in out
    assert "\r\nup" not in out


def test_plain_text_keeps_line_breaks():
    out = render_safe_html(b"line1\nline2\nline3")

    assert "<pre>" in out
    assert "line1\nline2\nline3" in out


def test_bom_is_not_shown():
    assert "\ufeff" not in render_safe_html(b"\xef\xbb\xbf<h1>x</h1>")
    assert "ï»¿" not in render_safe_html("ï»¿<h1>x</h1>".encode())


def test_script_body_is_dropped_entirely():
    out = render_safe_html(b"<script>var x = 1;</script>tail")

    assert "var x" not in out
    assert "tail" in out


def test_unbalanced_markup_is_closed():
    out = render_safe_html(b"<div><b>x")

    assert out.endswith("</b></div>")


def test_control_characters_are_removed():
    out = render_safe_html(b"<p>a\x00b</p>")

    assert "\x00" not in out
    assert "ab" in out


def test_plain_text_survives():
    out = render_safe_html(b"GET /index.php HTTP/1.1")

    assert "GET /index.php HTTP/1.1" in out
