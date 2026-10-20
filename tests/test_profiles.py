"""Тесты профилей."""
from paradox.config import Config
from paradox_gui.profiles import (
    ALL_PROFILES,
    DEFAULT_PROFILE_KEY,
    get_profile,
    profile_keys,
)


def test_default_profile_exists():
    p = get_profile(DEFAULT_PROFILE_KEY)
    assert p is not None
    assert p.overrides == {}
    assert p.disabled_detectors == frozenset()
    assert p.disabled_contradictions == frozenset()


def test_profile_keys_unique():
    keys = profile_keys()
    assert len(keys) == len(set(keys))


def test_all_profiles_have_title_and_description():
    for p in ALL_PROFILES:
        assert p.title
        assert p.description


def test_ctf_profile_overrides_valid():
    p = get_profile("ctf")
    cfg = Config()
    for k in p.overrides:
        assert hasattr(cfg, k), f"нет поля {k} в Config"


def test_corporate_profile_overrides_valid():
    p = get_profile("corporate")
    cfg = Config()
    for k in p.overrides:
        assert hasattr(cfg, k), f"нет поля {k} в Config"


def test_ctf_lowers_thresholds():
    """CTF должен ловить больше, чем default."""
    ctf = get_profile("ctf").overrides
    assert ctf["beaconing_min_connections"] < 20
    assert ctf["nxdomain_burst_threshold"] < 5
    assert ctf["dga_min_label_length"] < 12


def test_corporate_raises_thresholds():
    corp = get_profile("corporate").overrides
    assert corp["beaconing_min_connections"] > 20
    assert corp["nxdomain_burst_threshold"] > 5
    assert corp["dga_min_label_length"] > 12


def test_corporate_disables_noisy_detectors():
    corp = get_profile("corporate")
    assert "typosquatting" in corp.disabled_detectors
    assert "vulnerable_path" in corp.disabled_detectors


def test_unknown_profile_returns_none():
    assert get_profile("nope") is None
