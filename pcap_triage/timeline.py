"""
Timeline / kill-chain reconstruction.

Собирает из findings и contradictions хронологию событий с
kill-chain-фазами. Нового анализа не делает — только упорядочивает
уже найденное по времени и группирует по фазам атаки.

Появился в v0.8.0.

Схема события:

    TimelineEvent:
        ts           — unix timestamp, момент события
        kind         — "finding" | "contradiction"
        type         — f.type / c.rule
        subject      — обычно IP (кто «герой» события)
        severity     — critical | high | medium | low | info
        confidence
        phase        — kill-chain фаза
        chain_order  — число для сортировки фаз (10, 20, 30, ...)
        description  — краткое человекочитаемое
        mitre_id     — T-номер (для findings из mitre_map)
        ref_id       — индекс в исходном списке

Сортировка:
    1. ts          — хронология
    2. chain_order — внутри одного ts: сначала разведка, потом C2
    3. subject     — стабильность
    4. type        — финальный tie-break

Детерминированно: одинаковый вход → побитово одинаковый список.
"""
from __future__ import annotations

from dataclasses import dataclass

from pcap_triage.models import Finding


# Маппинг тип finding → kill-chain фаза.
# Тип вне мапы → phase="other", chain_order=999 (в конце).
_PHASE_BY_TYPE: dict[str, str] = {
    # Reconnaissance
    "port_scan": "recon",
    "web_scanner": "recon",

    # Initial Access
    "vulnerable_path": "initial_access",
    "brute_force": "initial_access",
    "ftp_brute_force": "initial_access",
    "typosquatting": "initial_access",

    # Execution
    "command_injection": "execution",
    "script_download": "execution",
    "carved_file": "execution",

    # Command and Control
    "beaconing": "c2",
    "dns_tunneling": "c2",
    "dga_domain": "c2",
    "cloud_tunnel": "c2",
    "cloud_tunnel_domain": "c2",
    "ja3_malware": "c2",
    "ip_check_service": "c2",
    "sni_without_dns": "c2",
    "sni_mismatch": "c2",
    "suspicious_port": "c2",
    "nxdomain_burst": "c2",

    # Lateral Movement
    "lateral_movement": "lateral_movement",

    # Exfiltration
    "large_transfer": "exfiltration",
}

# Численный порядок фаз. Чем меньше — тем раньше в kill-chain.
_PHASE_ORDER: dict[str, int] = {
    "recon":             10,
    "initial_access":    20,
    "execution":         30,
    "persistence":       40,
    "lateral_movement":  50,
    "c2":                60,
    "exfiltration":      70,
    "impact":            80,
    "other":             999,
}

# Маппинг rule contradictions → фаза.
_PHASE_BY_RULE: dict[str, str] = {
    "victim_makes_attack":    "lateral_movement",
    "mac_ip_conflict":        "initial_access",  # ARP-spoof = MITM
    "sni_host_mismatch":      "c2",
    "ja3_ua_mismatch":        "c2",
    "reverse_asymmetry":      "exfiltration",
    "port_service_mismatch":  "c2",
    "direct_ip_no_dns":       "c2",
    "sni_without_dns":        "c2",
    "dns_answer_mismatch":    "c2",
    "sni_cert_mismatch":      "c2",
    "self_signed_cert":       "c2",
    "expired_cert":           "c2",
}


@dataclass
class TimelineEvent:
    ts: float
    kind: str              # "finding" | "contradiction"
    type: str
    subject: str
    severity: str
    confidence: float
    phase: str
    chain_order: int
    description: str
    mitre_id: str | None = None
    ref_id: int | None = None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "kind": self.kind,
            "type": self.type,
            "subject": self.subject,
            "severity": self.severity,
            "confidence": self.confidence,
            "phase": self.phase,
            "chain_order": self.chain_order,
            "description": self.description,
            "mitre_id": self.mitre_id,
            "ref_id": self.ref_id,
        }


def _phase_for_finding(ftype: str) -> tuple[str, int]:
    phase = _PHASE_BY_TYPE.get(ftype, "other")
    return phase, _PHASE_ORDER[phase]


def _phase_for_rule(rule: str) -> tuple[str, int]:
    phase = _PHASE_BY_RULE.get(rule, "other")
    return phase, _PHASE_ORDER[phase]


def _describe_finding(f: Finding) -> str:
    src = f.src_ip or "?"
    dst = f.dst_ip or "?"
    return f"{src} → {dst}: {f.type} ({f.value})"


def _describe_contradiction(c) -> str:
    rule = getattr(c, "rule", "?")
    subj = getattr(c, "subject", "?")
    hint = (getattr(c, "resolution_hint", None) or "").strip()
    if hint:
        return f"{subj}: {rule} — {hint[:120]}"
    return f"{subj}: {rule}"


def _event_from_finding(f: Finding, idx: int) -> TimelineEvent | None:
    """None если нет first_seen — сортировать нечем."""
    if f.first_seen is None:
        return None
    phase, order = _phase_for_finding(f.type)
    return TimelineEvent(
        ts=f.first_seen,
        kind="finding",
        type=f.type,
        subject=f.src_ip or "",
        severity=f.severity,
        confidence=f.confidence,
        phase=phase,
        chain_order=order,
        description=_describe_finding(f),
        mitre_id=f.mitre_id,
        ref_id=idx,
    )


def _event_from_contradiction(c, idx: int) -> TimelineEvent | None:
    """
    ts = max(facts.ts) — момент, когда последний подтверждающий
    факт уже произошёл. Раньше не было бы видно противоречия.
    """
    facts = getattr(c, "facts", None) or []
    if not facts:
        return None
    ts_values = [getattr(f, "ts", 0.0) or 0.0 for f in facts]
    ts = max(ts_values) if ts_values else 0.0
    if ts <= 0.0:
        return None
    rule = getattr(c, "rule", "")
    phase, order = _phase_for_rule(rule)
    return TimelineEvent(
        ts=ts,
        kind="contradiction",
        type=rule,
        subject=getattr(c, "subject", ""),
        severity=getattr(c, "severity", "medium"),
        confidence=float(getattr(c, "confidence", 0.5)),
        phase=phase,
        chain_order=order,
        description=_describe_contradiction(c),
        mitre_id=None,
        ref_id=idx,
    )


def build_timeline(
    findings: list[Finding],
    contradictions: list | None = None,
) -> list[TimelineEvent]:
    """
    Собрать timeline из findings и contradictions.

    - Findings без first_seen пропускаются.
    - Contradictions без facts или с ts <= 0 пропускаются.
    - Сортировка: ts → chain_order → subject → type → kind.

    Детерминированно: одинаковый вход → одинаковый список.
    """
    events: list[TimelineEvent] = []
    for i, f in enumerate(findings):
        ev = _event_from_finding(f, i)
        if ev is not None:
            events.append(ev)
    if contradictions:
        for i, c in enumerate(contradictions):
            ev = _event_from_contradiction(c, i)
            if ev is not None:
                events.append(ev)

    events.sort(key=lambda e: (
        e.ts,
        e.chain_order,
        e.subject,
        e.type,
        e.kind,
    ))
    return events


def summarize_by_phase(events: list[TimelineEvent]) -> list[dict]:
    """
    Сгруппировать события по фазам kill-chain.

    Возвращает список dict'ов, отсортированный по chain_order:
        [{"phase": "recon", "chain_order": 10, "count": N,
          "events": [<dict>, ...]}, ...]
    """
    by_phase: dict[str, list[TimelineEvent]] = {}
    for ev in events:
        by_phase.setdefault(ev.phase, []).append(ev)
    out: list[dict] = []
    for phase, evs in by_phase.items():
        out.append({
            "phase": phase,
            "chain_order": _PHASE_ORDER.get(phase, 999),
            "count": len(evs),
            "events": [e.to_dict() for e in evs],
        })
    out.sort(key=lambda d: d["chain_order"])
    return out
