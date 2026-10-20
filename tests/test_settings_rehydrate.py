"""Тесты восстановления типов из JSON-store."""
from pathlib import Path

from paradox.config import Config
from paradox_gui.settings_rehydrate import rehydrate, rehydrate_overrides


def test_rehydrate_int():
    assert rehydrate(10, 42) == 42
    assert isinstance(rehydrate(10, 42), int)


def test_rehydrate_bool():
    assert rehydrate(True, 0) is False
    assert rehydrate(True, 1) is True


def test_rehydrate_float():
    assert rehydrate(1.0, "3.14") == 3.14


def test_rehydrate_path():
    assert rehydrate(Path("a"), "/tmp/b") == Path("/tmp/b")


def test_rehydrate_frozenset_int():
    assert rehydrate(frozenset({1, 2}), [3, 4]) == frozenset({3, 4})


def test_rehydrate_frozenset_str():
    assert rehydrate(frozenset({"a"}), ["x", "y"]) == frozenset({"x", "y"})


def test_rehydrate_tuple():
    assert rehydrate(("a", "b"), ["x", "y"]) == ("x", "y")


def test_rehydrate_overrides_int_field():
    cfg = Config()
    out = rehydrate_overrides({"nxdomain_burst_threshold": 10}, cfg)
    assert out == {"nxdomain_burst_threshold": 10}
    assert isinstance(out["nxdomain_burst_threshold"], int)


def test_rehydrate_overrides_drops_unknown():
    cfg = Config()
    out = rehydrate_overrides(
        {"nxdomain_burst_threshold": 10, "no_such_field": 999},
        cfg,
    )
    assert out == {"nxdomain_burst_threshold": 10}


def test_rehydrate_overrides_path():
    cfg = Config()
    out = rehydrate_overrides({"output_dir": "reports_custom"}, cfg)
    assert out["output_dir"] == Path("reports_custom")


def test_rehydrate_overrides_frozenset():
    cfg = Config()
    out = rehydrate_overrides({"suspicious_ports": [22, 4444]}, cfg)
    assert out["suspicious_ports"] == frozenset({22, 4444})