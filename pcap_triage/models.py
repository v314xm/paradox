from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    type: str
    value: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: float | None = None
    last_seen: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FlowKey:
    """
    Направленный 5-tuple. Направление НЕ нормализуется:
    A→B и B→A — два разных ключа. Для MVP считаем полудуплексно.

    TODO: канонизировать (сортировка ip:port пары), когда понадобится
    полная сессия — для exfiltration-детекторов, где важно
    соотношение bytes_sent/bytes_recv.
    """
    proto: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None


@dataclass
class FlowStats:
    packets: int = 0
    bytes_sent: int = 0
    first_ts: float | None = None
    last_ts: float | None = None

    # TODO: не хранить все timestamps для долгих захватов.
    # Заменить на онлайн-агрегаты (Welford) + reservoir sampling.
    timestamps: list[float] = field(default_factory=list)

    # протокол-специфичные поля — заполняются L2-экстракторами
    sni: str | None = None
    ja3: str | None = None
    http_host: str | None = None
    http_user_agent: str | None = None

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts


@dataclass
class CaptureState:
    # DNS
    dns_queries: Counter = field(default_factory=Counter)
    dns_nxdomain: Counter = field(default_factory=Counter)
    dns_nxdomain_by_src: Counter = field(default_factory=Counter)

    # flows
    flows: dict[FlowKey, FlowStats] = field(default_factory=dict)

    # meta
    packet_count: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    extractor_errors: Counter = field(default_factory=Counter)