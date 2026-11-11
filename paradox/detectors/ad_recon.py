"""ADReconDetector — перечисление каталога через LDAP.

ADRecon и ручная разведка тянут из каталога одно и то же: SPN,
членство в группах, флаги учётных записей, делегирование, ACL. Смотрим
по клиенту на пересечение запрошенных атрибутов с
`taxonomy.AD_RECON_ATTRIBUTES`.

Почему не «много поисков» само по себе: доменный клиент штатно читает
rootDSE при входе, это норма. Сигнал — именно чувствительные атрибуты,
а rootDSE усиливает его, когда вместе с ними просят SPN.
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.taxonomy import AD_RECON_ATTRIBUTES


class ADReconDetector:
    name = "ad_recon"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        clients = set(state.ldap_searches_by_src) | set(
            state.ldap_sensitive_attrs_by_src,
        )

        findings: list[Finding] = []
        for client in clients:
            sensitive = sorted(
                set(state.ldap_sensitive_attrs_by_src.get(client, ()))
                & AD_RECON_ATTRIBUTES,
            )
            if not sensitive:
                continue
            root_dse = state.ldap_root_dse_by_src.get(client, 0)
            searches = state.ldap_searches_by_src.get(client, 0)

            spn_probe = (
                root_dse > 0 and "serviceprincipalname" in sensitive
            )
            if len(sensitive) < 4 and not spn_probe:
                continue
            if searches < 2 and not spn_probe:
                continue

            if len(sensitive) >= 6:
                severity, confidence = "high", 0.75
            else:
                severity, confidence = "medium", 0.6

            findings.append(Finding(
                type="ad_recon",
                value=f"{len(sensitive)} атрибутов, {searches} поисков",
                src_ip=client,
                dst_port=389,
                severity=severity,
                confidence=confidence,
                evidence={
                    "sensitive_attributes": sensitive,
                    "ldap_searches": searches,
                    "root_dse_searches": root_dse,
                    "spn_probe": spn_probe,
                },
            ))

        findings.sort(key=lambda f: (f.src_ip or "", f.value))
        return findings
