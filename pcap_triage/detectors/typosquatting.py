from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


def levenshtein(a: str, b: str) -> int:
    """Классический редакторский distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            ))
        prev = curr
    return prev[-1]


class TyposquattingDetector:
    """
    Домены, похожие на известные бренды:
      - contains  : label содержит имя бренда ("event-datamicrosoft.live")
      - levenshtein: label близок к имени бренда ("micr0soft", "gnail")

    Домены из legitimate_brand_domains игнорируются.
    """
    name = "typosquatting"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for name, count in state.dns_queries.items():
            if self._is_legitimate(name, config):
                continue

            match = self._check(name, config)
            if match is None:
                continue

            kind, brand, label = match

            findings.append(Finding(
                type="typosquatting",
                value=name,
                confidence=0.65 if kind == "contains" else 0.75,
                evidence={
                    "kind": kind,
                    "brand": brand,
                    "label": label,
                    "queries": count,
                },
            ))

        return findings

    def _is_legitimate(self, name: str, config: Config) -> bool:
        # mDNS-зона (.local) — служебная, не DNS. Сюда попадают
        # сервисные записи вроде _googlecast._tcp.local.
        # Сейчас mDNS не парсится (порт 5353 не 53), но на будущее —
        # когда вернём mDNS отдельным экстрактором — эта защита
        # избавит от ложных срабатываний.
        if name.endswith(".local"):
            return True

        for legit in config.legitimate_brand_domains:
            if name == legit or name.endswith("." + legit):
                return True
        return False

    def _check(self, name: str, config: Config) -> tuple[str, str, str] | None:
        label = name.split(".")[0]

        for brand in config.protected_brands:
            # contains: имя бренда как часть label
            if brand in label and label != brand:
                return ("contains", brand, label)

            # levenshtein: label целиком похож на имя бренда
            if abs(len(label) - len(brand)) > config.typosquatting_levenshtein_threshold:
                continue
            dist = levenshtein(label, brand)
            if 0 < dist <= config.typosquatting_levenshtein_threshold:
                return ("levenshtein", brand, label)

        return None