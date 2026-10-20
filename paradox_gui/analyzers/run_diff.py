"""
Сравнение двух отчётов run_pipeline.

Чистая логика, без Qt — тестируется независимо.
Ключи для сопоставления:
  findings       → (type, value)
  contradictions → (rule, subject)
Порядок в списках сохраняется — UI не должен мерцать.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FindingDiff:
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)   # {"old", "new", "changes"}
    unchanged: list[dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)


@dataclass
class DiffResult:
    old_meta: dict
    new_meta: dict
    findings: FindingDiff
    contradictions_added: list[dict] = field(default_factory=list)
    contradictions_removed: list[dict] = field(default_factory=list)
    summary_changes: dict[str, tuple] = field(default_factory=dict)

    def has_changes(self) -> bool:
        return bool(
            self.findings.total
            or self.contradictions_added
            or self.contradictions_removed
            or self.summary_changes
        )


def _finding_key(f: dict) -> tuple[str, str]:
    return (str(f.get("type", "")), str(f.get("value", "")))


def _contra_key(c: dict) -> tuple[str, str]:
    return (str(c.get("rule", "")), str(c.get("subject", "")))


_SUMMARY_FIELDS = (
    "packets", "flows", "findings", "contradictions",
    "unique_dns_queries", "nxdomain_count",
    "tcp_streams", "http_objects", "carved_files",
)


def diff_reports(old: dict, new: dict) -> DiffResult:
    """Сравнить два отчёта run_pipeline."""
    old_f = {_finding_key(f): f for f in (old.get("findings") or [])}
    new_f = {_finding_key(f): f for f in (new.get("findings") or [])}

    fdiff = FindingDiff()
    for k, nf in new_f.items():
        if k not in old_f:
            fdiff.added.append(nf)
        else:
            of = old_f[k]
            changes = {}
            for field_name in ("confidence", "severity", "mitre_id"):
                ov = of.get(field_name)
                nv = nf.get(field_name)
                if ov != nv:
                    changes[field_name] = (ov, nv)
            if changes:
                fdiff.changed.append({"old": of, "new": nf, "changes": changes})
            else:
                fdiff.unchanged.append(nf)
    for k, of in old_f.items():
        if k not in new_f:
            fdiff.removed.append(of)

    old_c = {_contra_key(c): c for c in (old.get("contradictions") or [])}
    new_c = {_contra_key(c): c for c in (new.get("contradictions") or [])}
    ca = [c for k, c in new_c.items() if k not in old_c]
    cr = [c for k, c in old_c.items() if k not in new_c]

    old_s = old.get("summary") or {}
    new_s = new.get("summary") or {}
    sdiff: dict[str, tuple] = {}
    for f in _SUMMARY_FIELDS:
        ov, nv = old_s.get(f), new_s.get(f)
        if ov != nv and ov is not None and nv is not None:
            sdiff[f] = (ov, nv)

    return DiffResult(
        old_meta=old.get("provenance") or {},
        new_meta=new.get("provenance") or {},
        findings=fdiff,
        contradictions_added=ca,
        contradictions_removed=cr,
        summary_changes=sdiff,
    )
