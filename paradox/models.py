from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, NamedTuple

from paradox.taxonomy import SEVERITY_BY_TYPE as _SEVERITY_BY_TYPE


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

# v0.9.0: карта тип finding → severity по умолчанию живёт в
# paradox/taxonomy.py. Здесь оставлен алиас для обратной совместимости.
#
# Детектор может задать severity явно (включая "medium" для типа, у
# которого в карте стоит "high"). Если severity не задана вовсе —
# применяется эта карта, затем "medium".


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
    # None — детектор не задал, severity берётся из карты по типу.
    # Явно заданное значение (в т.ч. "medium") не переопределяется.
    severity: str | None = None

    first_seen: float | None = None
    last_seen: float | None = None

    # MITRE. Один источник правды — tuple техник. mitre_id ниже —
    # производное (первая техника), чтобы JSON-reporter и
    # markdown-reporter не тащили весь список в заголовке.
    mitre_techniques: tuple[str, ...] = ()

    # Специфика детектора. Никаких гарантий по ключам — каждый
    # детектор пишет что хочет.
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence_reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """
        v0.9.0: поднять top-level поля из evidence.

        Порядок:
          1. Одиночные ключи (src_ip / dst_ip / dst_port) — приоритет.
          2. Агрегированные (top_src_ips / dst_ips / dst_ports) — fallback.
          3. severity — из _SEVERITY_BY_TYPE, если детектор её не задал.
        """
        ev = self.evidence or {}
        if self.src_ip is None:
            self.src_ip = (
                ev.get("src_ip")
                or _first_ip_from_aggregated(ev.get("top_src_ips"))
                or _first_ip_from_aggregated(ev.get("src_ips"))
            )
        if self.dst_ip is None:
            self.dst_ip = (
                ev.get("dst_ip")
                or _first_ip_from_aggregated(ev.get("dst_ips"))
                or _first_ip_from_aggregated(ev.get("top_dst_ips"))
            )
        if self.dst_port is None:
            self.dst_port = (
                ev.get("dst_port") or _first_from_list(ev.get("dst_ports"))
            )
        if self.severity is None:
            self.severity = _SEVERITY_BY_TYPE.get(self.type, "medium")
        if not self.confidence_reasons and self.evidence:
            from paradox.detectors.explainer import build_reasons
            self.confidence_reasons = build_reasons(self.evidence)

    @property
    def mitre_id(self) -> str | None:
        """Основная (первая) техника или None, если техник нет."""
        return self.mitre_techniques[0] if self.mitre_techniques else None

    def to_dict(self) -> dict:
        # asdict не подхватывает property — добавляем mitre_id вручную.
        d = asdict(self)
        d["mitre_id"] = self.mitre_id
        return d


class FlowKey(NamedTuple):
    """
    Направленный 5-tuple. Направление НЕ нормализуется:
    A→B и B→A — два разных ключа.

    Для двунаправленной агрегации использовать make_session_key.

    NamedTuple, а не dataclass: ключ хэшируется и сравнивается на
    каждом пакете (627k на эталонном захвате), а tuple-хэш и tuple-eq
    выполняются в C. На профиле это ~2.5 млн сравнений и ~0.8 с.
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

    # v1.3.1: timestamps DNS-запросов по имени домена.
    # Нужно dga/cloud_tunnel/typosquatting для first_seen/last_seen
    # в Finding — иначе timeline их пропускает.
    # Аналог dns_nxdomain_ts_by_src, но по имени, а не по src.
    dns_query_ts_by_name: dict[str, list[float]] = field(
        default_factory=dict,
    )

    # v1.3.x: timestamps DNS-запросов по src_ip.
    # Нужно nxdomain_burst для windowed ratio-знаменателя: доля
    # NXDOMAIN в том же окне, а не за весь захват.
    dns_query_ts_by_src: dict[str, list[float]] = field(
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

    # IPv6 NDP (RFC 4861): аналог ARP для IPv6.
    #   ndp_total      — сколько NDP-пакетов разобрано
    #   ndp_neighbors  — IPv6 → MAC из NA/NS
    #   ndp_routers    — IPv6-адреса, приславшие Router Advertisement
    ndp_total: int = 0
    ndp_neighbors: dict[str, str] = field(default_factory=dict)
    ndp_routers: set[str] = field(default_factory=set)

    # TCP reassembly: склеенные потоки по FlowKey
    tcp_streams: dict[FlowKey, bytes] = field(default_factory=dict)
    # Сколько потоков было собрано до освобождения сырых байтов:
    # после post-extract state.tcp_streams очищается, чтобы не держать
    # до 200 МБ в памяти.
    tcp_streams_total: int = 0
    tcp_streams_truncated: set[FlowKey] = field(default_factory=set)
    carved_files: list = field(default_factory=list)
    # HTTP-объекты, извлечённые из tcp_streams
    # ключ — (FlowKey запроса, FlowKey ответа) или одиночный FlowKey
    http_objects: list = field(default_factory=list)

    # X.509 сертификаты из TLS-хендшейков.
    # list[tuple[FlowKey, Certificate]] — как carved_files,
    # чтобы не плодить импорт-цикл models ↔ x509_cert.
    tls_certs: list = field(default_factory=list)
    # Сертификаты, которые нашли в потоке, но не смогли разобрать как
    # DER. Счётчик виден в summary: молчаливый ноль маскирует битые
    # хендшейки и ошибки парсера.
    tls_cert_parse_errors: int = 0

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

    # v1.6: SMB2 (порт 445, NetBIOS-рамка). Собирается post-extract
    # из state.tcp_streams; нужен для AD-детекторов (перебор share,
    # доступ к SYSVOL, копирование по SMB).
    smb2_messages: int = 0
    smb2_parse_errors: int = 0
    smb2_commands: Counter = field(default_factory=Counter)
    smb2_dialects: Counter = field(default_factory=Counter)
    # Ключи — (client_ip, server_ip, share) и (client, server, path).
    smb2_shares: Counter = field(default_factory=Counter)
    smb2_paths: Counter = field(default_factory=Counter)
    smb2_status_errors: Counter = field(default_factory=Counter)
    smb2_read_bytes: int = 0
    smb2_write_bytes: int = 0

    # v1.6: LDAP (389 и Global Catalog 3268). Bind/search нужны
    # Kerberoasting/ADRecon/DCSync-эвристикам.
    ldap_messages: int = 0
    ldap_parse_errors: int = 0
    ldap_bind_dns: Counter = field(default_factory=Counter)
    ldap_search_bases: Counter = field(default_factory=Counter)
    ldap_filters: Counter = field(default_factory=Counter)
    ldap_attributes: Counter = field(default_factory=Counter)
    ldap_result_codes: Counter = field(default_factory=Counter)
    # По клиенту: сколько поисков и какие «чувствительные» атрибуты
    # просили. Нужно ad_recon (перечисление каталога).
    ldap_searches_by_src: Counter = field(default_factory=Counter)
    ldap_root_dse_by_src: Counter = field(default_factory=Counter)
    ldap_sensitive_attrs_by_src: dict[str, set[str]] = field(
        default_factory=dict,
    )

    # v1.6: Kerberos TGS-запросы к сервисам — Kerberoasting.
    # Ключи: (client_ip, kdc_ip, spn) и (client_ip, kdc_ip, etype).
    kerberos_tgs_requests: Counter = field(default_factory=Counter)
    kerberos_etypes: Counter = field(default_factory=Counter)

    # v1.6: DCE/RPC для DCSync. Собирается post-extract из
    # tcp_streams: BIND-ы по интерфейсам (UUID+версия), вызовы в
    # контексте DRSUAPI, naming context из тел DsGetNCChanges.
    # Ключи: (client, server, uuid, version) и
    # (client, server, dst_port, opnum), (client, server, nc).
    dcerpc_binds: Counter = field(default_factory=Counter)
    dcerpc_drsuapi_calls: Counter = field(default_factory=Counter)
    dcerpc_naming_contexts: Counter = field(default_factory=Counter)

    # v1.6: HTTP/2 (h2c и h2 поверх TLS с SSLKEYLOGFILE). Объекты
    # добавляются в http_objects, здесь — только счётчики, чтобы
    # отчёт показывал, сколько соединений реально разобрано, а
    # сколько TLS-потоков осталось закрытыми.
    h2_connections: int = 0
    h2_streams: int = 0
    h2_frames: int = 0
    h2_parse_errors: int = 0
    tls_decrypted_streams: int = 0
    tls_decrypted_records: int = 0
    tls_decrypt_errors: int = 0
    tls_streams_without_keylog: int = 0
    # HTTP/1.1-объекты из расшифрованного TLS: HTTPObjectExtractor их
    # не видел, потому что поток был зашифрован.
    tls_http1_objects: int = 0


def dns_sources_by_name(state: CaptureState) -> dict[str, list[str]]:
    """Обратный индекс: qname → список src_ip, которые его спрашивали."""
    out: dict[str, list[str]] = {}
    for src_ip, bucket in state.dns_queries_by_src.items():
        for name in bucket:
            out.setdefault(name, []).append(src_ip)
    return out


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
