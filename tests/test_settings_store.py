"""Тесты SettingsStore."""
import json
from pathlib import Path

import pytest

from paradox_gui.settings_store import (
    SettingsStore,
    default_settings_path,
)


@pytest.fixture
def store(tmp_path: Path) -> SettingsStore:
    return SettingsStore(tmp_path / "settings.json")


def test_load_missing_returns_empty(store):
    data = store.load()
    assert data["overrides"] == {}
    assert data["disabled_detectors"] == []
    assert data["disabled_contradictions"] == []


def test_save_load_roundtrip(store):
    store.save({
        "overrides": {"nxdomain_burst_window_sec": 120, "output_dir": Path("/tmp/x")},
        "disabled_detectors": ["beaconing"],
        "disabled_contradictions": ["SniWithoutDnsRule"],
    })
    data = store.load()
    assert data["overrides"]["nxdomain_burst_window_sec"] == 120
    assert Path(data["overrides"]["output_dir"]) == Path("/tmp/x")
    assert data["disabled_detectors"] == ["beaconing"]
    assert data["disabled_contradictions"] == ["SniWithoutDnsRule"]


def test_save_is_atomic(store):
    store.save({"overrides": {"a": 1}})
    assert [p.name for p in store.path.parent.iterdir()] == ["settings.json"]


def test_corrupt_json_falls_back_to_empty(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{not json", encoding="utf-8")
    assert store.load()["overrides"] == {}


def test_normalize_dedups_and_sorts(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps({
        "disabled_detectors": ["B", "A", "B"],
        "disabled_contradictions": ["X", "X"],
    }), encoding="utf-8")
    data = store.load()
    assert data["disabled_detectors"] == ["A", "B"]
    assert data["disabled_contradictions"] == ["X"]


def test_clear_removes_file(store):
    store.save({"overrides": {"a": 1}})
    store.clear()
    assert not store.path.exists()


def test_default_settings_path_under_appdata(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setattr("sys.platform", "win32")
    p = default_settings_path()
    assert str(p).startswith(str(tmp_path))
    assert p.name == "settings.json"


def test_save_partial_keeps_untouched_sections(store):
    store.save({
        "overrides": {"a": 1},
        "disabled_detectors": ["D"],
        "disabled_contradictions": ["C"],
    })
    store.save_partial(overrides={"a": 2})
    data = store.load()
    assert data["overrides"] == {"a": 2}
    assert data["disabled_detectors"] == ["D"]
    assert data["disabled_contradictions"] == ["C"]


def test_save_partial_writes_only_given_sections(store):
    store.save_partial(disabled_detectors={"x", "y"})
    data = store.load()
    assert data["disabled_detectors"] == ["x", "y"]
    assert data["overrides"] == {}
    assert data["disabled_contradictions"] == []


def test_save_partial_no_args_is_noop(store):
    store.save({"overrides": {"a": 1}})
    store.save_partial()
    assert store.load()["overrides"] == {"a": 1}
