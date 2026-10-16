"""
SSH brute force детектор.

Перебор паролей по SSH: с одного src к одной паре (dst_ip, dst_port)
приходит много SSH-баннеров. Один баннер = одна сессия (RFC 4253).

Confidence по количеству:
  20-49 попыток — 0.75
  50-99         — 0.85
  100+          — 0.95

Severity: high (из _SEVERITY_BY_TYPE в models.py).

Что фильтруем:
  - Единичные попытки (обычные SSH-сессии).
  - Разные dst — легитимные множественные подключения.
"""
from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SSHBruteForceDetector:
    """
    SSH brute force: 20+ баннеров от одного src к одной паре
    (dst_ip, dst_port). Аналог ftp_brute_force, но через SSH-порты.
    """
    name = "ssh_brute_force"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        threshold = config.ssh_brute_force_min_flows

        for (src, dst, port), count in state.ssh_client_attempts.items():
            if count < threshold:
                continue

            if count >= 100:
                confidence = 0.95
            elif count >= 50:
                confidence = 0.85
            else:
                confidence = 0.75

            findings.append(Finding(
                type="ssh_brute_force",
                value=f"{src} -> {dst}:{port}",
                confidence=confidence,
                evidence={
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "attempts": count,
                    "threshold": threshold,
                },
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
