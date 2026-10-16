"""
SMTP-экстрактор (TCP 25 / 587).

Из plaintext SMTP-трафика извлекает:
  - EHLO / HELO — домен-отправитель (объявляет клиент)
  - MAIL FROM — адрес отправителя
  - RCPT TO — адреса получателей
  - X-Mailer / User-Agent из DATA — реальный клиент/mass-mailer

Пишет в CaptureState:
  smtp_helo_by_src, smtp_from_by_src, smtp_rcpt_by_src,
  smtp_mailer_by_src.

Свой парсер, без scapy. SMTP — построчный ASCII-протокол.
Обрабатываем только plaintext: 465 (SMTPS) — TLS, не наш случай.
"""
from __future__ import annotations

from pcap_triage.models import CaptureState
from pcap_triage.parsers import PacketRecord


# Порты SMTP, где ожидаем plaintext.
SMTP_PORTS = frozenset({25, 587})

# Маркеры заголовков в DATA, которые нас интересуют.
_MAILER_HEADERS = (b"x-mailer:", b"user-agent:")


def _clean_address(raw: str) -> str:
    """
    Очистить адрес в MAIL FROM / RCPT TO.
    Формат: <user@host> или <> (для bounce).
    Возвращает 'user@host' или '' для <>.
    """
    s = raw.strip()
    lt = s.find("<")
    gt = s.rfind(">")
    if lt != -1 and gt > lt:
        s = s[lt + 1:gt]
    return s.strip().lower()


def parse_smtp_line(line: str) -> tuple[str, str] | None:
    """
    Разобрать одну SMTP-строку.

    Возвращает (kind, value) или None:
      ("helo", "client.example.com")
      ("mail_from", "user@example.com")
      ("rcpt_to", "victim@example.com")
      ("mailer", "Microsoft Outlook 16.0")
    """
    s = line.strip()
    if not s:
        return None

    # Case-insensitive верхние команды.
    upper = s.upper()

    if upper.startswith("EHLO ") or upper.startswith("HELO "):
        parts = s.split(None, 1)
        if len(parts) == 2:
            return ("helo", parts[1].strip())
        return None

    if upper.startswith("MAIL FROM:"):
        addr = _clean_address(s[len("MAIL FROM:"):])
        return ("mail_from", addr) if addr else None

    if upper.startswith("RCPT TO:"):
        addr = _clean_address(s[len("RCPT TO:"):])
        return ("rcpt_to", addr) if addr else None

    # Заголовки DATA.
    lower = s.lower()
    for hdr in ("x-mailer:", "user-agent:"):
        if lower.startswith(hdr):
            val = s[len(hdr):].strip()
            if val:
                return ("mailer", val)

    return None


class SMTPExtractor:
    """
    SMTP-экстрактор. Работает поверх PacketRecord.

    Поскольку у нас нет TCP-reassembly внутри экстрактора (reassembler
    работает отдельно и пишет в tcp_streams), парсим прямо из payload.
    Многострочный MAIL/RCPT из одного пакета поймаем, если он пришёл
    целиком. Для типичного SMTP это норма.
    """
    name = "smtp"
    layer = 0

    def process(self, record: PacketRecord, state: CaptureState) -> None:
        if record.src_port not in SMTP_PORTS and record.dst_port not in SMTP_PORTS:
            return
        if not record.payload:
            return

        # Клиентские команды — со стороны клиента, у которого dst_port SMTP.
        # Если src_port SMTP — это ответы сервера, не наша сторона.
        if record.src_port in SMTP_PORTS:
            return
        if not record.src_ip:
            return

        src_ip = record.src_ip

        try:
            text = record.payload.decode("ascii", errors="ignore")
        except Exception:
            return

        for line in text.split("\n"):
            parsed = parse_smtp_line(line)
            if parsed is None:
                continue
            kind, value = parsed

            if kind == "helo":
                state.smtp_helo_by_src[src_ip] = value
            elif kind == "mail_from":
                state.smtp_from_by_src.setdefault(src_ip, set()).add(value)
            elif kind == "rcpt_to":
                state.smtp_rcpt_by_src.setdefault(src_ip, set()).add(value)
            elif kind == "mailer":
                state.smtp_mailer_by_src.setdefault(src_ip, set()).add(value)
