"""
IPCheckServiceDetector — обращения к сервисам проверки внешнего IP
(ip-api.com, ifconfig.me, ipinfo.io). Типичный шаг malware и скриптов
для подтверждения интернет-доступа перед C2.

Матчинг по четырём источникам:
  - DNS-запрос к домену сервиса (state.dns_queries)
  - SNI в TLS ClientHello (flow.sni)
  - HTTP Host в запросе (flow.http_host)
  - Прямой IP-запрос (flow.dst_ip в config.ip_check_service_ips)

Все источники дают одно и то же value — каноническое имя сервиса
(например, "ip-api.com"). Если клиент резолвит домен через DNS и потом
стучится на известный IP — все три источника сольются в один finding
с sources={dns, sni, direct_ip}. Это делает результат стабильным.
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding


class IPCheckServiceDetector:
    name = "ip_check_service"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        services = config.ip_check_services
        service_ips = config.ip_check_service_ips

        # value (имя сервиса) -> {sources: set, extra: dict}
        hits: dict[str, dict] = {}

        def _touch(value: str, source: str, extra: dict | None = None) -> None:
            h = hits.setdefault(value, {"sources": set(), "extra": {}})
            h["sources"].add(source)
            if extra:
                h["extra"].update(extra)

        # 1. DNS
        for qname, count in state.dns_queries.items():
            domain = qname.lower().strip(".")
            if domain in services:
                _touch(domain, "dns", {"queries": count})

        # 2. SNI / 3. HTTP Host / 4. direct IP
        for key, flow in state.flows.items():
            if flow.sni:
                sni = flow.sni.lower().strip(".")
                if sni in services:
                    _touch(sni, "sni",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"})

            if flow.http_host:
                host = flow.http_host.split(":", 1)[0].lower().strip(".")
                if host in services:
                    _touch(host, "http_host",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"})

            # direct IP — используем каноническое имя сервиса как value,
            # чтобы finding слился с DNS/SNI-находками
            service_name = service_ips.get(key.dst_ip)
            if service_name:
                _touch(service_name, "direct_ip",
                       {"flow": f"{key.src_ip} -> {key.dst_ip}"})

        findings: list[Finding] = []
        for value, h in hits.items():
            findings.append(Finding(
                type="ip_check_service",
                value=value,
                confidence=0.7,
                evidence={
                    "sources": sorted(h["sources"]),
                    **h["extra"],
                },
            ))

        findings.sort(key=lambda f: f.value)
        return findings
