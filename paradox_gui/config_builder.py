"""Сборка Config с пользовательскими overrides.

Вынесено из RunView._run_analysis, чтобы:
- тестировать без Qt (QApplication не нужен);
- держать одну точку правды для семантики override + __post_init__.
"""
from __future__ import annotations

from typing import Any


def build_config_with_overrides(overrides: dict[str, Any] | None = None):
    """Собрать Config, наложив overrides.

    Config — frozen dataclass. Обычный setattr упадёт, поэтому
    используем object.__setattr__. Но он обходит __post_init__,
    в котором:
      - пересобирается dga_allowlist (extra | cloud_tunnel | ip_check);
      - brute_force_excluded_ports = alias на dc_service_ports;
      - выполняется _validate();
      - создаётся output_dir.mkdir().
    Поэтому после наложения overrides явно вызываем __post_init__() —
    он идемпотентен.

    Исключение — dga_allowlist. __post_init__ собирает его из
    _dga_allowlist_extra | cloud_tunnel_domains | ip_check_services.
    Вкладка DGA отдаёт готовый список — если пользователь его задал,
    его правка важнее автосборки. Возвращаем поверх.

    Raises:
        ValueError: невалидные значения (Config._validate).
        OSError: не удалось создать output_dir.
    """
    from paradox.config import Config

    config = Config()
    overrides = overrides or {}

    for key, value in overrides.items():
        if hasattr(config, key):
            object.__setattr__(config, key, value)

    if overrides:
        config.__post_init__()
        if "dga_allowlist" in overrides:
            object.__setattr__(
                config, "dga_allowlist", overrides["dga_allowlist"],
            )

    return config