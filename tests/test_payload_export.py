"""Экспорт payload'а в Markdown с редакцией секретов."""
from paradox.payload_analysis import analyze_payload
from paradox.payload_export import build_markdown, redact_secrets


def test_redact_secrets_hides_values():
    text = (
        "password=hunter2 token: abcdef123456\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload\n"
        "url=http://evil.example/x"
    )

    redacted = redact_secrets(text)

    assert "hunter2" not in redacted
    assert "abcdef123456" not in redacted
    assert "eyJhbGci" not in redacted
    assert "<redacted>" in redacted
    assert "http://evil.example/x" in redacted


def test_build_markdown_contains_metadata_and_redacts_body():
    body = (
        b"POST /login HTTP/1.1\n"
        b"password=hunter2\n"
        b"http://evil.example/x"
    )
    analysis = analyze_payload(body)
    markdown = build_markdown(
        data=body,
        analysis=analysis,
        meta={
            "finding_type": "command_injection",
            "finding_value": "10.0.0.5 -> victim",
            "direction": "request",
            "method": "POST",
            "host": "victim.local",
            "uri": "/login",
            "content_type": "text/plain",
            "truncated": False,
        },
        occurrences=[{"type": "command_injection", "value": "again"}],
    )

    assert "# Payload: command_injection" in markdown
    assert analysis.sha256 in markdown
    assert "http://evil.example/x" in markdown
    assert "hunter2" not in markdown
    assert "## IOC" in markdown
    assert "## Тот же payload" in markdown
