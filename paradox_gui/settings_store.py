"""Persistent settings storage for the Paradox GUI.

Stores user overrides and disabled detectors / contradictions as JSON
in the per-user config directory. The store is intentionally dumb: it
knows nothing about Config, detectors or the rest of the app. It
normalizes its own schema and guarantees atomic writes.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def default_settings_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "Paradox" / "settings.json"


def _empty() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "overrides": {},
        "disabled_detectors": [],
        "disabled_contradictions": [],
        "language": "ru",
    }


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({str(v) for v in value if isinstance(v, (str, int))})


def _normalize(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return _empty()
    overrides = raw.get("overrides", {})
    if not isinstance(overrides, dict):
        overrides = {}
    result = {
        "schema_version": SCHEMA_VERSION,
        "overrides": _jsonable(overrides),
        "disabled_detectors": _str_list(raw.get("disabled_detectors", [])),
        "disabled_contradictions": _str_list(raw.get("disabled_contradictions", [])),
    }
    if isinstance(raw.get("active_profile"), str):
        result["active_profile"] = raw["active_profile"]
    if isinstance(raw.get("language"), str):
        result["language"] = raw["language"]
    return result


class SettingsStore:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path: Path = Path(path) if path is not None else default_settings_path()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return _empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _empty()
        return _normalize(raw)

    def save(self, data: dict[str, Any]) -> None:
        normalized = _normalize(data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(
            json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    def save_partial(
        self,
        *,
        overrides: dict | None = None,
        disabled_detectors=None,
        disabled_contradictions=None,
        language: str | None = None,
    ) -> dict[str, Any]:
        """Мердж: незаданные секции сохраняют текущее значение."""
        current = self.load()
        if overrides is not None:
            current["overrides"] = overrides
        if disabled_detectors is not None:
            current["disabled_detectors"] = list(disabled_detectors)
        if disabled_contradictions is not None:
            current["disabled_contradictions"] = list(disabled_contradictions)
        if language is not None:
            current["language"] = language
        self.save(current)
        return current

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
