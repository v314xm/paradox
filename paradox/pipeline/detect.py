"""Прогон детекторов и обогащение MITRE."""
from __future__ import annotations

from collections.abc import Callable

from paradox.config import Config
from paradox.detectors.ad_recon import ADReconDetector
from paradox.detectors.beaconing import BeaconingDetector
from paradox.detectors.brute_force import BruteForceDetector
from paradox.detectors.cloud_tunnel import CloudTunnelDetector
from paradox.detectors.command_injection import CommandInjectionDetector
from paradox.detectors.dcsync import DCSyncDetector
from paradox.detectors.dga import DGADetector
from paradox.detectors.dns_tunneling import DNSTunnelingDetector
from paradox.detectors.encoded_payload import EncodedPayloadDetector
from paradox.detectors.ftp_brute_force import FTPBruteForceDetector
from paradox.detectors.http_binary_upload import HttpBinaryUploadDetector
from paradox.detectors.ip_check_service import IPCheckServiceDetector
from paradox.detectors.ja3_malware import JA3MalwareDetector
from paradox.detectors.ja3s_malware import JA3SMalwareDetector
from paradox.detectors.kerberoasting import KerberoastingDetector
from paradox.detectors.large_transfer import LargeTransferDetector
from paradox.detectors.lateral_movement import LateralMovementDetector
from paradox.detectors.long_connections import LongConnectionDetector
from paradox.detectors.nxdomain_burst import NXDOMAINBurstDetector
from paradox.detectors.php_payload import PhpPayloadDetector
from paradox.detectors.port_scan import PortScanDetector
from paradox.detectors.rare_external_ip import RareExternalIPDetector
from paradox.detectors.smtp_spam import SMTP_SpamDetector
from paradox.detectors.sni_mismatch import SNIMismatchDetector
from paradox.detectors.ssh_brute_force import SSHBruteForceDetector
from paradox.detectors.suspicious_port import SuspiciousPortDetector
from paradox.detectors.typosquatting import TyposquattingDetector
from paradox.detectors.vulnerable_path import VulnerablePathDetector
from paradox.detectors.webshell_markers import WebShellMarkersDetector
from paradox.detectors.yara_detector import YARADetector
from paradox.models import CaptureState
from paradox.pipeline.errors import PipelineCancelled

# Порядок детекторов не важен — они независимы.
DETECTORS = [
    DGADetector(),
    PortScanDetector(),
    SuspiciousPortDetector(),
    NXDOMAINBurstDetector(),
    CloudTunnelDetector(),
    IPCheckServiceDetector(),
    TyposquattingDetector(),
    SNIMismatchDetector(),
    RareExternalIPDetector(),
    EncodedPayloadDetector(),
    JA3MalwareDetector(),
    JA3SMalwareDetector(),
    BruteForceDetector(),
    FTPBruteForceDetector(),
    BeaconingDetector(),
    LongConnectionDetector(),
    DNSTunnelingDetector(),
    SSHBruteForceDetector(),       # v0.9.0
    SMTP_SpamDetector(),           # v0.9.0
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
    CommandInjectionDetector(),
    HttpBinaryUploadDetector(),
    PhpPayloadDetector(),
    WebShellMarkersDetector(),
    YARADetector(),
    KerberoastingDetector(),       # v1.6
    ADReconDetector(),             # v1.6
    DCSyncDetector(),              # v1.6
]



def _detect(
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str, int, int], None] | None = None,
    detectors: list | None = None,
):
    # v1.4: детекторы — параметром, без monkey-patch глобального
    # DETECTORS (thread-safe для параллельных воркеров).
    # Каждый детектор обёрнут в try/except: один упавший не валит
    # остальные. Ошибки считаются в state.extractor_errors с префиксом
    # "detector:<name>" — их видно в summary отчёта.
    active = list(detectors) if detectors is not None else list(DETECTORS)

    # Пользовательские детекторы из ~/.paradox/plugins (если включены).
    # Ошибки загрузки считаются в summary, но пайплайн не валят.
    from paradox.detector_plugins import load_detector_plugins

    plugin_result = load_detector_plugins(
        config, reserved_names={d.name for d in active},
    )
    if plugin_result.detectors:
        active.extend(plugin_result.detectors)
    if plugin_result.errors:
        state.extractor_errors["plugin"] += len(plugin_result.errors)

    findings = []
    total = len(active)
    for i, det in enumerate(active):
        if should_stop is not None and should_stop():
            raise PipelineCancelled()
        if on_phase is not None:
            on_phase("detect", i, total, det.name)
        try:
            findings.extend(det.run(state, config))
        except Exception:
            key = f"detector:{det.name}"
            prev = state.extractor_errors[key]
            state.extractor_errors[key] = prev + 1
            if getattr(config, "debug_log_extractor_errors", False) and prev == 0:
                import logging
                logging.exception(
                    "detector %s failed (first occurrence)", det.name,
                )
        if on_phase is not None:
            on_phase("detect", i + 1, total, det.name)

    # Обогащение MITRE-техниками. Instance-level (detector заполнил сам —
    # например large_transfer с direction) приоритетнее type-map.
    from paradox.detectors.mitre_map import get_techniques
    for f in findings:
        if not f.mitre_techniques:
            f.mitre_techniques = get_techniques(f.type)
    return findings
