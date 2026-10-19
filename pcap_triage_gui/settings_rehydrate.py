"""Восстановление типов значений из JSON-store.

Store хранит всё в JSON-совместимом виде: Path → str, frozenset → list.
При загрузке надо вернуть исходные типы, иначе ядро упадёт: например
Config.dga_allowlist ожидает frozenset, а получит list.

Тип определяем по образцу — дефолтному значению поля Config.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


_MISSING = object()

def rehydrate(default: Any, raw: Any) -> Any:
    """Привести raw к типу default.

    Если default — None, вернуть raw без изменений.
    MappingProxyType (ip_check_service_ips, port_service_allowed и т.п.)
    из GUI не редактируется, поэтому тут no-op.
    """
    if default is None:
        return raw
    if isinstance(default, bool):
        return bool(raw)
    if isinstance(default, int) and not isinstance(default, bool):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    if isinstance(default, Path):
        return Path(str(raw))
    if isinstance(default, frozenset):
        if default:
            sample = next(iter(default))
            if isinstance(sample, int):
                return frozenset(int(x) for x in raw)
            return frozenset(str(x) for x in raw)
        return frozenset(raw)
    if isinstance(default, tuple):
        if isinstance(raw, (list, tuple)):
            return tuple(raw)
        return (raw,)
    if isinstance(default, Mapping):
        return default
    return raw


def rehydrate_overrides(overrides: dict, defaults: Any) -> dict:
    """Пропустить overrides через rehydrate по образцу полей Config.

    Поля, которых нет в Config, отбрасываются. Поля с дефолтом None
    (например, yara_rules_path) сохраняются как есть — их тип не
    навязать, а терять ввод пользователя нельзя.
    """
    out: dict[str, Any] = {}
    for key, value in overrides.items():
        default = getattr(defaults, key, _MISSING)
        if default is _MISSING:
            continue
        out[key] = rehydrate(default, value)
    return out
