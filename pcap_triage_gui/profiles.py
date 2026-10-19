"""Профили настроек: пресеты overrides.

Профиль — это:
  - overrides: dict {поле Config: значение}
  - disabled_detectors: set[str]
  - disabled_contradictions: set[str]

Применяется из SettingsView. Ничего не хранит сам — только описывает
набор значений. Активный профиль — метаданное в settings.json.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Profile:
    key: str
    title: str
    description: str
    overrides: dict[str, Any] = field(default_factory=dict)
    disabled_detectors: frozenset[str] = field(default_factory=frozenset)
    disabled_contradictions: frozenset[str] = field(default_factory=frozenset)


def _profiles() -> tuple[Profile, ...]:
    return (
        Profile(
            key="default",
            title="По умолчанию",
            description=(
                "Заводские пороги ядра. Хороший баланс полноты и шума "
                "для большинства pcap."
            ),
        ),
        Profile(
            key="ctf",
            title="CTF / паранойя",
            description=(
                "Сниженные пороги: ловим больше, но и ложных "
                "срабатываний больше. Для соревнований и разбора "
                "незнакомого трафика."
            ),
            overrides={
                "beaconing_min_connections": 10,
                "beaconing_min_duration_sec": 300,
                "nxdomain_burst_threshold": 3,
                "typosquatting_levenshtein_threshold": 1,
                "dga_min_label_length": 8,
                "dga_entropy_threshold": 3.0,
                "large_transfer_min_bytes": 10 * 1024 * 1024,
                "port_scan_min_distinct_dsts": 5,
            },
        ),
        Profile(
            key="corporate",
            title="Корпоративная сеть / тихо",
            description=(
                "Повышенные пороги и отключены шумные детекторы. "
                "Меньше ложных, выше требования к сигналу. "
                "Для мониторинга в рабочей сети."
            ),
            overrides={
                "beaconing_min_connections": 40,
                "beaconing_min_duration_sec": 1200,
                "nxdomain_burst_threshold": 10,
                "dga_min_label_length": 15,
                "large_transfer_min_bytes": 200 * 1024 * 1024,
                "port_scan_min_distinct_dsts": 20,
            },
            disabled_detectors=frozenset({
                "typosquatting",
                "vulnerable_path",
            }),
            disabled_contradictions=frozenset({
                "SelfSignedCertRule",
                "ExpiredCertRule",
            }),
        ),
    )


ALL_PROFILES: tuple[Profile, ...] = _profiles()
DEFAULT_PROFILE_KEY = "default"


def get_profile(key: str) -> Profile | None:
    for p in ALL_PROFILES:
        if p.key == key:
            return p
    return None


def profile_keys() -> tuple[str, ...]:
    return tuple(p.key for p in ALL_PROFILES)
