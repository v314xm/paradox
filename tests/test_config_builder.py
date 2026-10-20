"""Тесты сборки Config с overrides.

Проверяют семантику, от которой зависит RunView._run_analysis:
после overrides производные поля пересчитаны, валидация выполнена,
output_dir создан, пользовательский dga_allowlist не затёрт.
"""
import pytest

from paradox_gui.config_builder import build_config_with_overrides


def test_default_config_when_no_overrides():
    cfg = build_config_with_overrides({})
    # Дефолтная сборка dga_allowlist прошла:
    assert "trycloudflare.com" in cfg.dga_allowlist  # cloud_tunnel
    assert "ip-api.com" in cfg.dga_allowlist         # ip_check


def test_cloud_tunnel_override_flows_into_dga_allowlist():
    cfg = build_config_with_overrides({
        "cloud_tunnel_domains": frozenset({"example.test"}),
    })
    assert "example.test" in cfg.dga_allowlist


def test_user_dga_allowlist_wins_over_rebuild():
    custom = frozenset({"keep.me", "and.me"})
    cfg = build_config_with_overrides({"dga_allowlist": custom})
    assert cfg.dga_allowlist == custom


def test_output_dir_created_after_override(tmp_path):
    target = tmp_path / "reports_override"
    cfg = build_config_with_overrides({"output_dir": target})
    assert target.is_dir()
    assert cfg.output_dir == target


def test_invalid_value_raises():
    with pytest.raises(ValueError):
        build_config_with_overrides({"nxdomain_burst_threshold": -1})


def test_brute_force_excluded_ports_rebuilt_from_dc_service_ports():
    cfg = build_config_with_overrides({
        "dc_service_ports": frozenset({88, 389}),
    })
    assert cfg.brute_force_excluded_ports == frozenset({88, 389})
