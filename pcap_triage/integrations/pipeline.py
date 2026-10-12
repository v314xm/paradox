"""
Высокоуровневая функция обогащения.

Работает с findings в виде dict (то, что отдаёт run_pipeline).
Дополнительно поддерживает объекты Finding — для тестов и будущих
изменений в pipeline.

Пустые результаты провайдеров не прикрепляются к findings.
"""
from pcap_triage.config import Config
from pcap_triage.integrations.cache import EnrichmentCache
from pcap_triage.integrations.enricher import (
    EnricherOrchestrator,
    collect_iocs_from_findings,
)
from pcap_triage.integrations.shodan_internetdb import (
    ShodanInternetDBEnricher,
)


def build_default_orchestrator(config: Config) -> EnricherOrchestrator:
    """Собрать оркестратор с провайдерами по умолчанию."""
    providers = [
        ShodanInternetDBEnricher(),
    ]
    cache = EnrichmentCache(config.enrichment_cache_path)
    return EnricherOrchestrator(providers, cache, config)


def attach_enrichment_to_findings(
    findings: list,
    enrichment_map: dict,
) -> None:
    """
    Прикрепить результаты обогащения в evidence["enrichment"].

    Работает и с list[dict], и с list[Finding].

    enrichment_map: {(ioc_type, ioc): [EnrichmentResult, ...]}
    Пустые записи (только ошибки или пустой data) не прикрепляются.
    """
    for f in findings:
        ev = _get_evidence(f)
        attached: dict = {}

        def _try_attach(ioc_type: str, ioc: str) -> None:
            if not isinstance(ioc, str) or not ioc:
                return
            results = enrichment_map.get((ioc_type, ioc))
            if not results:
                return
            per_ioc: dict = {}
            for r in results:
                if r.ok and r.data:
                    per_ioc[r.source] = r.data
            if per_ioc:
                attached[ioc] = per_ioc

        for field in ("dst_ip", "src_ip", "ip"):
            _try_attach("ip", ev.get(field))

        for field in ("base_domain", "sni", "host", "domain"):
            _try_attach("domain", ev.get(field))

        if attached:
            ev["enrichment"] = attached
            _set_evidence(f, ev)


def enrich_findings(findings: list, config: Config) -> dict:
    """
    Собрать IOC из findings, обогатить, прикрепить обратно.

    Возвращает статистику:
      {
        "iocs_total": N,
        "iocs_enriched": M,
        "cache_hits": X,
        "cache_misses": Y,
        "rate_limited": Z,
        "provider_calls": K,
        "errors": E,
      }
    """
    iocs = collect_iocs_from_findings(findings)
    if not iocs:
        return {
            "iocs_total": 0,
            "iocs_enriched": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "rate_limited": 0,
            "provider_calls": 0,
            "errors": 0,
        }

    orch = build_default_orchestrator(config)
    try:
        enrichment_map = orch.enrich(iocs)
        attach_enrichment_to_findings(findings, enrichment_map)
        stats = dict(orch.stats)
        stats["iocs_total"] = len(iocs)
        stats["iocs_enriched"] = len(enrichment_map)
        return stats
    finally:
        orch.close()


# ---------- helpers: работают и с dict, и с Finding ----------

def _get_evidence(f) -> dict:
    """Получить evidence как dict (из Finding или из dict-finding)."""
    if isinstance(f, dict):
        ev = f.get("evidence")
        if not isinstance(ev, dict):
            ev = {}
            f["evidence"] = ev
        return ev
    # Finding (dataclass)
    if f.evidence is None:
        f.evidence = {}
    return f.evidence


def _set_evidence(f, ev: dict) -> None:
    """Записать evidence обратно (для dict — уже мутирован in-place)."""
    if not isinstance(f, dict):
        f.evidence = ev