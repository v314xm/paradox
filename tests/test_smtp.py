"""Тесты SMTP экстрактора."""
from paradox.extractors.smtp import (
    SMTPExtractor,
    _clean_address,
    parse_smtp_line,
)
from paradox.models import CaptureState


class _Rec:
    """Заглушка PacketRecord."""
    def __init__(self, payload: bytes, src_port: int = 54321,
                 dst_port: int = 25, src_ip: str = "192.168.1.1"):
        self.payload = payload
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = "10.0.0.5"


# ---------- _clean_address ----------

def test_clean_address_simple():
    assert _clean_address("<user@example.com>") == "user@example.com"


def test_clean_address_bounce():
    assert _clean_address("<>") == ""


def test_clean_address_no_brackets():
    assert _clean_address("user@example.com") == "user@example.com"


def test_clean_address_with_spaces():
    assert _clean_address("  <user@example.com>  ") == "user@example.com"


def test_clean_address_lowercase():
    assert _clean_address("<USER@EXAMPLE.COM>") == "user@example.com"


# ---------- parse_smtp_line ----------

def test_parse_ehlo():
    assert parse_smtp_line("EHLO mail.example.com") == (
        "helo", "mail.example.com",
    )


def test_parse_helo():
    assert parse_smtp_line("HELO client.local") == (
        "helo", "client.local",
    )


def test_parse_mail_from():
    assert parse_smtp_line("MAIL FROM:<alice@example.com>") == (
        "mail_from", "alice@example.com",
    )


def test_parse_rcpt_to():
    assert parse_smtp_line("RCPT TO:<bob@target.com>") == (
        "rcpt_to", "bob@target.com",
    )


def test_parse_x_mailer():
    assert parse_smtp_line("X-Mailer: Microsoft Outlook 16.0") == (
        "mailer", "Microsoft Outlook 16.0",
    )


def test_parse_user_agent():
    assert parse_smtp_line("User-Agent: PHPMailer 6.0") == (
        "mailer", "PHPMailer 6.0",
    )


def test_parse_unknown_line():
    assert parse_smtp_line("250 OK") is None
    assert parse_smtp_line("DATA") is None
    assert parse_smtp_line("") is None


def test_parse_empty_after_colon():
    """MAIL FROM: <> — bounce, пустой адрес."""
    assert parse_smtp_line("MAIL FROM:<>") is None


# ---------- SMTPExtractor ----------

def test_extractor_helo():
    rec = _Rec(b"EHLO attacker.example.com\r\n")
    state = CaptureState()
    SMTPExtractor().process(rec, state)
    assert state.smtp_helo_by_src["192.168.1.1"] == "attacker.example.com"


def test_extractor_multiple_lines():
    payload = (
        b"EHLO mail.attacker.com\r\n"
        b"MAIL FROM:<sender@attacker.com>\r\n"
        b"RCPT TO:<victim@target.com>\r\n"
    )
    state = CaptureState()
    SMTPExtractor().process(_Rec(payload), state)
    assert state.smtp_helo_by_src["192.168.1.1"] == "mail.attacker.com"
    assert "sender@attacker.com" in state.smtp_from_by_src["192.168.1.1"]
    assert "victim@target.com" in state.smtp_rcpt_by_src["192.168.1.1"]


def test_extractor_multiple_rcpt():
    payload = (
        b"MAIL FROM:<attacker@evil.com>\r\n"
        b"RCPT TO:<a@victim.com>\r\n"
        b"RCPT TO:<b@victim.com>\r\n"
        b"RCPT TO:<c@victim.com>\r\n"
    )
    state = CaptureState()
    SMTPExtractor().process(_Rec(payload), state)
    assert state.smtp_rcpt_by_src["192.168.1.1"] == {
        "a@victim.com", "b@victim.com", "c@victim.com",
    }


def test_extractor_mailer():
    payload = (
        b"DATA\r\n"
        b"X-Mailer: PHPMailer 6.6.0\r\n"
        b"User-Agent: custom-bot/1.0\r\n"
    )
    state = CaptureState()
    SMTPExtractor().process(_Rec(payload), state)
    assert state.smtp_mailer_by_src["192.168.1.1"] == {
        "PHPMailer 6.6.0", "custom-bot/1.0",
    }


def test_extractor_ignores_server_responses():
    """src_port=25 — это сервер, не наш клиент."""
    rec = _Rec(b"220 mail.example.com ESMTP\r\n", src_port=25, dst_port=54321)
    state = CaptureState()
    SMTPExtractor().process(rec, state)
    assert not state.smtp_helo_by_src


def test_extractor_ignores_non_smtp_port():
    rec = _Rec(b"EHLO mail.example.com\r\n", dst_port=8080)
    state = CaptureState()
    SMTPExtractor().process(rec, state)
    assert not state.smtp_helo_by_src


def test_extractor_587_submission():
    rec = _Rec(b"EHLO client.example.com\r\n", dst_port=587)
    state = CaptureState()
    SMTPExtractor().process(rec, state)
    assert state.smtp_helo_by_src["192.168.1.1"] == "client.example.com"


def test_extractor_empty_payload():
    state = CaptureState()
    SMTPExtractor().process(_Rec(b""), state)
    assert not state.smtp_helo_by_src


def test_extractor_multiple_srcs_isolated():
    state = CaptureState()
    SMTPExtractor().process(
        _Rec(b"EHLO a.com\r\n", src_ip="1.1.1.1"), state,
    )
    SMTPExtractor().process(
        _Rec(b"EHLO b.com\r\n", src_ip="2.2.2.2"), state,
    )
    assert state.smtp_helo_by_src == {
        "1.1.1.1": "a.com",
        "2.2.2.2": "b.com",
    }
