"""Тесты описаний для tooltip'ов."""
from pcap_triage.config import Config
from pcap_triage_gui.field_help import (
    FIELD_HELP,
    SECTION_BY_TITLE,
    SECTION_HELP,
    get_field_help,
    get_section_help,
)


def test_field_help_non_empty():
    assert len(FIELD_HELP) >= 40, f"описаний слишком мало: {len(FIELD_HELP)}"


def test_field_help_describes_key_fields():
    required = {
        "beaconing_min_connections",
        "nxdomain_burst_window_sec",
        "dga_entropy_threshold",
        "large_transfer_min_bytes",
        "output_dir",
    }
    missing = required - set(FIELD_HELP)
    assert not missing, f"нет описаний для: {sorted(missing)}"


def test_field_help_keys_exist_in_config():
    cfg = Config()
    unknown = [k for k in FIELD_HELP if not hasattr(cfg, k)]
    assert not unknown, f"описаны поля, которых нет в Config: {unknown}"


def test_get_field_help_fallback():
    text = get_field_help("no_such_field_xyz")
    assert "no_such_field_xyz" in text


def test_section_help_non_empty():
    assert len(SECTION_HELP) >= 10


def test_section_by_title_covers_all_sections():
    for key in ("thresholds", "detectors", "contradictions",
                "allowlist", "dga", "brute", "network",
                "reports", "threatintel", "perf", "general"):
        assert key in SECTION_HELP, f"нет описания секции {key}"


def test_get_section_help_known():
    assert "beaconing" in get_section_help("thresholds").lower() or            "порог" in get_section_help("thresholds").lower()
