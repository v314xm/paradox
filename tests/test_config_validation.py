"""Валидация Config: таблица правил даёт те же сообщения, что и раньше."""
import dataclasses

import pytest

from paradox.config import _VALIDATION_RULES, Config


def test_default_config_is_valid():
    Config()


def test_every_rule_points_to_a_real_field():
    cfg = Config()

    assert all(hasattr(cfg, rule.field) for rule in _VALIDATION_RULES)


def test_rule_message_is_reported():
    with pytest.raises(ValueError) as exc:
        Config(file_carve_min_size=0)

    assert "file_carve_min_size must be > 0" in str(exc.value)


def test_ports_rule_reports_range():
    with pytest.raises(ValueError) as exc:
        Config(suspicious_ports=frozenset({0, 70000}))

    assert (
        "suspicious_ports must be in range 1..65535" in str(exc.value)
    )


def test_multiple_errors_are_all_listed():
    with pytest.raises(ValueError) as exc:
        Config(beaconing_max_jitter_ratio=2.0, plugins_dir="   ")

    message = str(exc.value)
    assert "beaconing_max_jitter_ratio must be in (0, 1]" in message
    assert "plugins_dir must not be empty" in message


def test_replace_revalidates():
    cfg = Config()

    with pytest.raises(ValueError) as exc:
        dataclasses.replace(cfg, absence_top_n=0)

    assert "absence_top_n must be > 0" in str(exc.value)
