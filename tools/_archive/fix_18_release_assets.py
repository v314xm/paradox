# tools/fix_18_release_assets.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import FixError

FIX_ID = "18-release-assets"
TITLE = "Релиз: tools/build_icon.py + README.md + CHANGELOG.md"

REL_BUILD_ICON = "tools/build_icon.py"
REL_README = "README.md"
REL_CHANGELOG = "CHANGELOG.md"

BUILD_ICON = r'''"""Генерация paradox.ico из существующего render_logo().

Использование:
    python tools/build_icon.py

Создаёт paradox.ico в корне проекта. Файл коммитится в репозиторий.
"""
from __future__ import annotations
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("error: PySide6 not installed")
        return 1

    app = QApplication.instance() or QApplication(sys.argv)  # noqa: F841

    from paradox_gui.logo import render_logo

    pm = render_logo(256)
    if pm.isNull():
        print("error: render_logo() returned null pixmap")
        return 1

    out = project_root / "paradox.ico"
    if not pm.save(str(out), "ICO"):
        print(f"error: failed to save {out}")
        return 1

    size_kb = out.stat().st_size / 1024
    print(f"wrote {out} ({size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

README = r"""# Paradox

**Offline pcap triage.** 18 detectors, 12 contradiction rules, attack graph,
Threat Intel, STIX 2.1. No cloud: everything runs on the analyst's machine.

Paradox extracts network facts from pcap and looks for inconsistencies
between data layers: DNS vs SNI, JA3 vs User-Agent, MAC vs IP, roles vs behavior.

## Features

- 9 extractors: flow, DNS, host_identity, ARP-history, NBNS, Kerberos,
  TLS (SNI + JA3), HTTP, NDP (IPv6). Plus DHCP, SMTP, SSH banner.
- 18 detectors: DGA, port_scan, suspicious_port, NXDOMAIN burst,
  cloud_tunnel, ip_check_service, typosquatting, SNI mismatch, JA3-malware,
  brute_force (HTTP/FTP/SSH), beaconing, DNS-tunneling, lateral movement,
  large_transfer, vulnerable_path, command_injection, SMTP spam, YARA.
- 12 contradiction rules: victim_makes_attack (pivot), mac_ip_conflict,
  sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry, port_service_mismatch,
  direct_ip_no_dns, sni_without_dns, dns_answer_mismatch, sni_cert_mismatch,
  self_signed_cert, expired_cert.
- 4 analyzers: Confidence Explainer, What-If, Absence, Host Story.
- Threat Intel: Shodan InternetDB (no key), AbuseIPDB, VirusTotal, OTX,
  URLScan, GreyNoise, urlhaus, malwarebazaar, threatfox.
- Export: JSON, Markdown, STIX 2.1 (deterministic UUIDv5), conn.log,
  IOC files (suricata.rules, KQL/Splunk queries).

## Quick start

**Windows .exe**: download release, unpack, run Paradox.exe.

**From source:**

    git clone https://github.com/v314xm/paradox.git
    cd paradox
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python -m paradox_gui
    python -m paradox <file.pcap>

## Architecture

    paradox/            # core (no Qt)
    ├── extractors/     # 12 extractors
    ├── detectors/      # 18 detectors
    ├── contradictions/ # 12 contradiction rules
    ├── analyzers/      # attack_graph, counterfactual, story, absence, ndp
    ├── integrations/   # Threat Intel (registry, cache, rate limit)
    ├── reporters/      # JSON, Markdown, flow, IOC
    └── pipeline.py     # run_pipeline(), run_multi_pipeline()

    paradox_gui/        # PySide6
    ├── views/          # Run, History, Enrichment, Settings, IPv6, Timeline,
    │                   # Export, Diff
    ├── widgets/        # DropZone, FindingsTable, SummaryGrid, ...
    ├── dialogs/        # Finding, Contradiction, AttackGraph, HostStory
    ├── i18n/           # ru/en
    └── workers/        # AnalysisWorker (QThread), EnrichmentWorker

## Build .exe

1. Generate icon:
       python tools/build_icon.py

2. Build:
       python tools/build_installer.py

Add `icon='paradox.ico'` to the `EXE(...)` call in your .spec.

## Development

    pip install -r requirements.txt
    pre-commit install
    pytest
    ruff check .

## Author

© 2026 Andrey Grigoryev (v314xm)
"""

CHANGELOG = r"""# Changelog

All notable changes documented here.
Format inspired by Keep a Changelog.

## [1.2.0] — 2026-10-22

First public release after internal iteration.

### Added — Core
- SSH brute force detector (20+ banners to one server).
- SMTP spam detector (50+ unique RCPT TO per host).
- YARA detector based on rules from rules/default.yar.
- scanner_candidate role for hosts that only scan (port_scan, web_scanner).
- AttackEdge.weight: edges with multiple finding types get higher score
  and look thicker in the graph.
- Threat Intel cache (SQLite, per-source TTL).
- IOC export: iocs.txt, iocs.csv, iocs.json, suricata.rules,
  queries.txt (KQL + Splunk).

### Added — GUI
- DiffView: compare two JSON reports, load from History in one click.
  Export diff to Markdown.
- Global exception handler: QMessageBox with traceback instead of silent crash.
- File-size guards: warn on pcap > 500 MB, multi-pcap > 500 MB, JSON > 100 MB.
- Splash screen with progress; logo drawn in code.
- i18n: 100% GUI coverage (RU / EN), switching on the fly.
- Dark theme, unified QSS from theme.py.
- Multi-pcap: merge several files into one report.

### Fixed
- STIX export lost single-dot domains (example.com).
- STIX export used uuid4 — SIEM dedup was broken. Now uuid5.
- AttackGraphDialog: time-slider and path-selection overwrote setOpacity.
- settings_rehydrate: Mapping fields silently reverted to default.
- attack_graph._detect_entry_impact: internal dst wrongly treated as impact target.
- Duplicate field declarations in TimelineEvent and PacketRecord.
- fix_06 (History→Diff) was not idempotent.

### Changed
- Config remains frozen; override via object.__setattr__ + explicit __post_init__.
- _build_report() extracted from run_pipeline/run_multi_pipeline.
- All GUI fixes go through tools/apply_fixes.py — idempotent, with --dry-run.
"""


def _create_file(root: Path, rel: str, content: str) -> bool:
    path = root / rel
    if path.exists():
        print(f"  [skip] {rel} (already exists)")
        return False
    if fix_utils.DRY_RUN:
        print(f"  [dry-run] would create: {path}")
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"  [created] {rel}")
    return True


def apply(root: Path) -> bool:
    changed = False
    for rel, content in [
        (REL_BUILD_ICON, BUILD_ICON),
        (REL_README, README),
        (REL_CHANGELOG, CHANGELOG),
    ]:
        if _create_file(root, rel, content):
            changed = True
    return changed
