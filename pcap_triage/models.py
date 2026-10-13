from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any




@dataclass
class HostIdentity:
    """Профиль хоста: IP ↔ MAC ↔ hostname ↔ username ↔ realm."""
    ip: str
    mac: str | None = None
    hostnames: set[str] = field(default_factory=set)
    username: str | None = None
    realm: str | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostnames": sorted(self.hostnames),
            "username": self.username,
            "realm": self.realm,
        }

@dataclass
class Finding:
    type: str
    value: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: float | None = None
    last_seen: float | None = None
    mitre_techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FlowKey:
    """
    Направленный 5-tuple. Направление НЕ нормализуется:
    A→B и B→A — два разных ключа.

    Для двунаправленной агрегации использовать make_session_key.
    """
    proto: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None


@dataclass(frozen=True)
class SessionKey:
    """
    Двунаправленный ключ сессии.

    Нормализует пару (IP, port) так, что A→B и B→A дают один ключ.
    Порядок детерминирован: сначала по (ip, port) меньшая сторона.
    """
    ip_lo: str
    port_lo: int | None
    ip_hi: str
    port_hi: int | None
    proto: str


def make_session_key(key: FlowKey) -> SessionKey:
    """Построить SessionKey из FlowKey. Нормализует направление."""
    side_a = (key.src_ip, key.src_port or 0)
    side_b = (key.dst_ip, key.dst_port or 0)
    if side_a <= side_b:
        lo, hi = side_a, side_b
    else:
        lo, hi = side_b, side_a
    return SessionKey(
        ip_lo=lo[0], port_lo=lo[1] or None,
        ip_hi=hi[0], port_hi=hi[1] or None,
        proto=key.proto,
    )


@dataclass
class FlowStats:
    packets: int = 0
    bytes_sent: int = 0
    first_ts: float | None = None
    last_ts: float | None = None


    # TODO: не хранить все timestamps для долгих захватов.
    # Заменить на онлайн-агрегаты (Welford) + reservoir sampling.
    timestamps: list[float] = field(default_factory=list)

    # инициатор сессии: True если src отправил первый SYN,
    # False если src получил SYN (то есть инициатор — dst),
    # None если первый пакет захвата — не SYN (mid-stream)
    initiated_by_src: bool | None = None

        # протокол-специфичные поля — заполняются L2-экстракторами
    sni: str | None = None
    ja3: str | None = None
    ja3s: str | None = None
    http_host: str | None = None
    http_user_agent: str | None = None
    http_method: str | None = None
    http_uri: str | None = None

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

    # DNS по источнику: src_ip → {qname: count}
    dns_queries_by_src: dict[str, Counter] = field(default_factory=dict)

    # flows
    flows: dict[FlowKey, FlowStats] = field(default_factory=dict)

    # SNI по сессии: работает для обоих направлений
    session_sni: dict[SessionKey, str] = field(default_factory=dict)

    # meta
    packet_count: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    extractor_errors: Counter = field(default_factory=Counter)

    # счётчики неподдержанных пакетов (для отчёта)
    unsupported: dict[str, int] = field(default_factory=dict)

    # заготовка под rate limit VT
    enrichment_budget_exhausted: bool = False

    # IP → HostIdentity (MAC, hostname)
    host_identities: dict[str, HostIdentity] = field(default_factory=dict)
    # TCP reassembly: склеенные потоки по FlowKey
    tcp_streams: dict[FlowKey, bytes] = field(default_factory=dict)
    carved_files: list = field(default_factory=list)
    tcp_streams_truncated: set[FlowKey] = field(default_factory=set)
    # HTTP-объекты, извлечённые из tcp_streams
    # ключ — (FlowKey запроса, FlowKey ответа) или одиночный FlowKey
    http_objects: list = field(default_factory=list)


def get_session_sni(
    key: FlowKey,
    flow: FlowStats,
    state: CaptureState,
) -> str | None:
    """
    SNI для flow. Сначала смотрим flow.sni (обратная совместимость),
    потом session_sni по SessionKey — так SNI виден обоим направлениям.

    Пример: ClientHello от клиента → SNI пишется в исходящий flow и в
    session_sni. Обратный flow (ответ сервера) видит SNI через session_sni.
    """
    if flow.sni:
        return flow.sni
    return state.session_sni.get(make_session_key(key))