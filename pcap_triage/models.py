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

# v0.9.0: карта тип finding → severity по умолчанию.
#
# Детектор может задать severity явно. Если оставил "medium" —
# применяется эта карта.
_SEVERITY_BY_TYPE: dict[str, str] = {
    "command_injection": "high",
    "brute_force": "high",
    "ftp_brute_force": "high",
    "ssh_brute_force": "high",
    "lateral_movement": "high",
    "ja3_malware": "high",
    "script_download": "high",

    "port_scan": "medium",
    "web_scanner": "medium",
    "vulnerable_path": "medium",
    "beaconing": "medium",
    "dns_tunneling": "medium",
    "suspicious_port": "medium",
    "cloud_tunnel": "medium",
    "sni_mismatch": "medium",
    "dga_domain": "medium",
    "large_transfer": "medium",
    "carved_file": "medium",

    "nxdomain_burst": "low",
    "typosquatting": "low",
    "ip_check_service": "low",
}


def _first_from_list(v):
    """Первый элемент списка/кортежа или None."""
    if isinstance(v, (list, tuple)) and v:
        return v[0]
    return None


def _first_ip_from_aggregated(v):
    """
    Первый IP из агрегированного списка top_src_ips:
        [{"ip": "192.168.1.12", "count": 1}, ...]
    """
    if isinstance(v, (list, tuple)) and v:
        first = v[0]
        if isinstance(first, dict):
            return first.get("ip")
        if isinstance(first, str):
            return first
    return None


@dataclass
class Finding:
    """
    Универсальный контракт находки.

    Top-level поля (src_ip, dst_ip, dst_port, severity, first_seen,
    last_seen, mitre_techniques) — то, чем пользуются кросс-детекторные
    потребители: contradictions/facts.py, aggregators/entities.py,
    reporters. Всё остальное (специфика конкретного детектора) —
    в evidence.

        v0.9.0: нормализация встроена в __post_init__. Детекторы могут
    писать src_ip / dst_ip / dst_port либо напрямую, либо в evidence
    (в том числе агрегированные top_src_ips / dst_ips / dst_ports).
    На выходе конструктора top-level поля всегда заполнены.
    """
    type: str
    value: str
    confidence: float

    # Универсальные поля (v0.8.0). None — детектор не задал,
    # читатель падает на evidence как fallback.
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    severity: str = "medium"   # critical | high | medium | low | info

    first_seen: float | None = None
    last_seen: float | None = None

    # MITRE. Один источник правды — tuple техник. mitre_id ниже —
    # производное (первая техника), чтобы JSON-reporter и
    # markdown-reporter не тащили весь список в заголовке.
    mitre_techniques: tuple[str, ...] = ()

    # Специфика детектора. Никаких гарантий по ключам — каждый
    # детектор пишет что хочет.
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        v0.9.0: поднять top-level поля из evidence.

        Порядок:
          1. Одиночные ключи (src_ip / dst_ip / dst_port) — приоритет.
          2. Агрегированные (top_src_ips / dst_ips / dst_ports) — fallback.
          3. severity — из _SEVERITY_BY_TYPE, если осталось "medium".
        """
        ev = self.evidence or {}
        if self.src_ip is None:
            self.src_ip = (
                ev.get("src_ip")
                or _first_ip_from_aggregated(ev.get("top_src_ips"))
            )
        if self.dst_ip is None:
            self.dst_ip = (
                ev.get("dst_ip") or _first_from_list(ev.get("dst_ips"))
            )
        if self.dst_port is None:
            self.dst_port = (
                ev.get("dst_port") or _first_from_list(ev.get("dst_ports"))
            )
        if self.severity == "medium" and self.type in _SEVERITY_BY_TYPE:
            self.severity = _SEVERITY_BY_TYPE[self.type]

    @property
    def mitre_id(self) -> str | None:
        """Основная (первая) техника или None, если техник нет."""
        return self.mitre_techniques[0] if self.mitre_techniques else None

    def to_dict(self) -> dict:
        # asdict не подхватывает property — добавляем mitre_id вручную.
        d = asdict(self)
        d["mitre_id"] = self.mitre_id
        return d


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

    # DNS-ответы: name → {IP}, IP → {name}. Нужно для правил
    # sni_without_dns / direct_ip_no_dns: связывают домен, который
    # клиент резолвил, с IP, куда он ходил. set, не list — при
    # повторных ответах дублей быть не должно.
    dns_answers_by_name: dict[str, set[str]] = field(default_factory=dict)
    dns_answers_by_ip: dict[str, set[str]] = field(default_factory=dict)

    # v0.9.0: timestamps каждого NXDOMAIN по src_ip.
    # Нужно nxdomain_burst для скользящего окна. Раньше
    # dns_nxdomain_by_src считал за весь файл — на FIN-2015 давало
    # 93 findings, из которых большинство — размазанные по часу
    # опечатки. Здесь храним ts, окно считаем в детекторе.
    dns_nxdomain_ts_by_src: dict[str, list[float]] = field(
        default_factory=dict,
    )

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

    # IP → {MAC: [first_ts, last_ts, count]}
    # Отдельно от host_identities: там только последний MAC (для отчёта),
    # здесь — все, что видели (для правила mac_ip_conflict). Потеря истории
    # = потеря ARP-spoof: финальное значение не покажет атаку.
    # Формат [first, last, count] — list, а не tuple, потому что count
    # инкрементируется in-place на каждом ARP-пакете.
    arp_macs: dict[str, dict[str, list]] = field(default_factory=dict)
    # TCP reassembly: склеенные потоки по FlowKey
    tcp_streams: dict[FlowKey, bytes] = field(default_factory=dict)
    carved_files: list = field(default_factory=list)
    tcp_streams_truncated: set[FlowKey] = field(default_factory=set)
    # HTTP-объекты, извлечённые из tcp_streams
    # ключ — (FlowKey запроса, FlowKey ответа) или одиночный FlowKey
    http_objects: list = field(default_factory=list)

    # X.509 сертификаты из TLS-хендшейков.
    # list[tuple[FlowKey, Certificate]] — как carved_files,
    # чтобы не плодить импорт-цикл models ↔ x509_cert.
    tls_certs: list = field(default_factory=list)

    # v0.9.0: SSH баннеры (RFC 4253).
    # server: (ip, port) -> software version, напр. "OpenSSH_8.2p1"
    # client: ip -> набор software-версий, от которых приходили баннеры
    ssh_server_versions: dict[tuple[str, int], str] = field(
        default_factory=dict,
    )
    ssh_client_versions: dict[str, set[str]] = field(
        default_factory=dict,
    )

    # v0.9.0: счётчик попыток SSH-подключений.
    # Ключ — (src_ip, dst_ip, dst_port). Инкремент при каждом
    # клиентском баннере (RFC 4253: один баннер на соединение).
    # Нужно детектору ssh_brute_force.
    ssh_client_attempts: dict[tuple[str, str, int], int] = field(
        default_factory=dict,
    )

    # v0.9.0: SMTP.
    #   helo_by_src   — последний EHLO/HELO-домен клиента
    #   from_by_src   — все MAIL FROM адреса от клиента
    #   rcpt_by_src   — все RCPT TO адреса от клиента
    #   mailer_by_src — X-Mailer / User-Agent из DATA
    smtp_helo_by_src: dict[str, str] = field(default_factory=dict)
    smtp_from_by_src: dict[str, set[str]] = field(default_factory=dict)
    smtp_rcpt_by_src: dict[str, set[str]] = field(default_factory=dict)
    smtp_mailer_by_src: dict[str, set[str]] = field(default_factory=dict)


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