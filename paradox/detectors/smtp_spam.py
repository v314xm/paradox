"""
SMTP spam детектор.

Признак массовой рассылки: с одного src много уникальных RCPT TO.
Типично для компрометированного хоста-спамбота или newsletter-
сервиса (последнее — FP, но реже встречается в корпоративном
pcap, чем первое).

Данные берём из state.smtp_rcpt_by_src и state.smtp_mailer_by_src
(заполняет SMTPExtractor).

Confidence по количеству уникальных получателей:
  50–199      0.7
  200–999     0.8
  1000+       0.9

Дополнительный сигнал: если X-Mailer/UA содержит масс-мейлерные
маркеры — пишем в evidence. На confidence не влияет: маркеры
слишком общие (PHPMailer есть у половины CMS).
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding

# Подстроки в X-Mailer / User-Agent, частые у масс-мейлеров.
# На confidence не влияют — только в evidence для аналитика.
_MASS_MAILER_MARKERS = (
    "phpmailer",
    "swiftmailer",
    "mass",
    "bulk",
    "sender",
    "mailer",
    "bot",
)


class SMTP_SpamDetector:
    """
    SMTP спам: 50+ уникальных RCPT TO с одного src.

    Не проверяет содержимое писем (нет body) — только envelope.
    Если в evidence попадает 200+ получателей с одним MAIL FROM —
    это с большой вероятностью спам-бот.
    """
    name = "smtp_spam"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        threshold = config.smtp_spam_min_recipients

        for src_ip, rcpt_set in state.smtp_rcpt_by_src.items():
            count = len(rcpt_set)
            if count < threshold:
                continue

            if count >= 1000:
                confidence = 0.9
            elif count >= 200:
                confidence = 0.8
            else:
                confidence = 0.7

            # Ищем масс-мейлерные маркеры.
            mailers = state.smtp_mailer_by_src.get(src_ip, set())
            matched_markers: list[str] = []
            for m in mailers:
                low = m.lower()
                for marker in _MASS_MAILER_MARKERS:
                    if marker in low and marker not in matched_markers:
                        matched_markers.append(marker)

            # HELO — для evidence.
            helo = state.smtp_helo_by_src.get(src_ip, "")

            # FROM-адреса — берём один (обычно их немного).
            from_addrs = sorted(state.smtp_from_by_src.get(src_ip, set()))
            from_sample = from_addrs[0] if from_addrs else ""

            # v1.1: dst из flows SMTP-портов.
            dst_counts = {}
            for key in state.flows:
                if key.src_ip == src_ip and key.dst_port in (25, 465, 587):
                    dst_counts[key.dst_ip] = dst_counts.get(key.dst_ip, 0) + 1
            top_dsts = sorted(
                ({"ip": ip, "count": c} for ip, c in dst_counts.items()),
                key=lambda d: -d["count"],
            )[:5]

            evidence = {
                "src_ip": src_ip,
                "recipients_count": count,
                "threshold": threshold,
                "helo": helo,
                "from_sample": from_sample,
                "mailer_markers": sorted(matched_markers),
                "top_dst_ips": top_dsts,
                "recipients_sample": sorted(rcpt_set)[:10],
            }

            findings.append(Finding(
                type="smtp_spam",
                value=f"{src_ip} -> {count} recipients",
                confidence=confidence,
                evidence=evidence,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
