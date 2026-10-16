"""
TyposquattingDetector — подделки под известные бренды.

Логика:
  - contains:    бренд — подстрока в SLD (event-datamicrosoft.live)
  - levenshtein: SLD близок к бренду (micr0soft.com)

Ключевое: матчинг идёт ТОЛЬКО по SLD (registered domain,
второй уровень справа). Поддомены игнорируются:
  googleads.g.doubleclick.net -> SLD doubleclick, не google
  app.loadimpact.com          -> SLD loadimpact, не app

Точное совпадение SLD с брендом (google.com) — не typosquat.

Levenshtein дополнительно ограничен длиной:
  - SLD < 5 символов не считается (app/web/mail — обычные имена)
  - SLD короче бренда на 2+ — не считается

v0.9.0: двухуровневые TLD (co.uk, com.au, co.jp, ...) поддержаны
через domain_utils. bbc.co.uk → SLD "bbc", не "co". Полный Public
Suffix List не тянем — только реальные кейсы.
"""
from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                cur[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return prev[-1]


def _registered_label(domain: str) -> str:
    """
    v0.9.0: SLD без поддоменов и TLD с поддержкой двухуровневых TLD.

    googleads.g.doubleclick.net -> doubleclick
    a.b.foo.co.uk              -> foo
    """
    from pcap_triage.domain_utils import registered_label
    return registered_label(domain)


def _check_squat(sld: str, brand: str, lev_threshold: int) -> str | None:
    """Вернуть kind ('contains'/'levenshtein') если SLD — подделка бренда."""
    if not sld or not brand:
        return None
    if "." in brand:                # goo.gl, aws.amazon.com — не label-бренды
        return None
    if sld == brand:                # сам бренд (google.se -> SLD google)
        return None

    # --- contains ---
    # brand в начале SLD — sub-brand (microsoftstore) — не typosquat.
    # brand в конце с очень коротким префиксом (s-microsoft, i-paypal)
    # — трекинговые домены корпораций — не typosquat.
    # Всё остальное (event-datamicrosoft) — contains-typosquat.
    if brand in sld:
        pos = sld.find(brand)
        if pos == 0:
            pass
        elif pos + len(brand) == len(sld) and pos <= 3:
            pass
        else:
            return "contains"

    # --- levenshtein ---
    if len(sld) < 5:
        return None
    if len(sld) < len(brand) - 1:
        return None
    if sld[0] != brand[0] or sld[-1] != brand[-1]:
        return None
    lev = levenshtein(sld, brand)
    if lev > lev_threshold:
        return None
    if lev / max(len(sld), len(brand)) > 0.25:
        return None
    return "levenshtein"


class TyposquattingDetector:
    name = "typosquatting"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        brands = config.protected_brands
        allowlist = config.legitimate_brand_domains
        lev_threshold = config.typosquatting_levenshtein_threshold

        findings: list[Finding] = []
        for qname, count in state.dns_queries.items():
            domain = qname.lower().strip(".")
            if not domain:
                continue

            # Allowlist: сам домен или его поддомен
            if any(domain == a or domain.endswith("." + a) for a in allowlist):
                continue

            sld = _registered_label(domain)
            if not sld:
                continue

            match: tuple[str, str] | None = None
            for brand in brands:
                kind = _check_squat(sld, brand, lev_threshold)
                if kind:
                    match = (brand, kind)
                    break

            if not match:
                continue

            brand, kind = match
            confidence = 0.75 if kind == "levenshtein" else 0.65
            findings.append(Finding(
                type="typosquatting",
                value=domain,
                confidence=confidence,
                evidence={
                    "brand": brand,
                    "kind": kind,
                    "label": sld,
                    "queries": count,
                },
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings