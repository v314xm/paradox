"""KerberoastingDetector — запросы сервисных тикетов, особенно в RC4.

Обычный пользователь тоже получает TGS на сервис, к которому идёт,
поэтому один SPN — не сигнал. Смотрим на два признака:

  - RC4 (etype 23) в TGS-REQ: тикет, который потом ломают офлайн;
    современный клиент просит AES, RC4 — осознанный downgrade;
  - перечисление: 3+ разных сервисных SPN с одного хоста.

Один SPN без RC4 и 1–2 SPN — молчим: это штатный доступ к сервису.
"""
from collections import Counter

from paradox.config import Config
from paradox.models import CaptureState, Finding

RC4_HMAC = 23


class KerberoastingDetector:
    name = "kerberoasting"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        if not state.kerberos_tgs_requests:
            return []

        per_pair: dict[tuple[str, str], dict] = {}
        for (client, kdc, spn), count in (
            state.kerberos_tgs_requests.items()
        ):
            bucket = per_pair.setdefault(
                (client, kdc), {"spns": Counter(), "total": 0},
            )
            bucket["spns"][spn] += count
            bucket["total"] += count

        rc4_by_pair: Counter = Counter()
        etypes_by_pair: dict[tuple[str, str], set[int]] = {}
        for (client, kdc, etype), count in state.kerberos_etypes.items():
            etypes_by_pair.setdefault((client, kdc), set()).add(etype)
            if etype == RC4_HMAC:
                rc4_by_pair[(client, kdc)] += count

        findings: list[Finding] = []
        for (client, kdc), bucket in per_pair.items():
            spns = bucket["spns"]
            distinct = len(spns)
            rc4 = rc4_by_pair[(client, kdc)]

            if rc4:
                severity, confidence = "high", 0.8
            elif distinct >= 5:
                severity, confidence = "medium", 0.6
            elif distinct >= 3:
                severity, confidence = "low", 0.5
            else:
                continue

            suffix = ", RC4" if rc4 else ""
            findings.append(Finding(
                type="kerberoasting",
                value=f"{distinct} SPN{suffix}",
                src_ip=client,
                dst_ip=kdc or None,
                dst_port=88,
                severity=severity,
                confidence=confidence,
                evidence={
                    "spns": sorted(spns),
                    "spn_requests": bucket["total"],
                    "distinct_spns": distinct,
                    "rc4_requests": rc4,
                    "etypes": sorted(etypes_by_pair.get((client, kdc), ())),
                },
            ))

        findings.sort(key=lambda f: (f.src_ip or "", f.value))
        return findings
