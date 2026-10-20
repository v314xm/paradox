Архитектура Paradox
Модель
Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются через
структуры данных.

text
PCAP
│
▼
RawPcapReader / PcapReader (по magic bytes)
│
▼
parse_packet (struct) → PacketRecord
│
▼
Extractors (9) + TCPReassembler (on the fly)
├── flow, dns, tls, http, host_identity, arp_history, nbns,
    kerberos, tls_cert (post-extract)
│
▼
CaptureState (flows, dns, host_identities, arp_macs, tcp_streams)
│
▼
Post-extract (после чтения всех пакетов)
├── TCPReassembler.finalize_all → tcp_streams
├── HTTPObjectExtractor.run_post_extract → http_objects
├── TlsCertificateExtractor.run_post_extract → tls_certs
└── carve_files → carved_files
│
▼
Detectors (19) → Findings
│
▼
ContradictionDetector (слой 4.5)
├── facts.py — извлечение фактов
├── rules/ — 13 правил
└── Contradictions
│
▼
Timeline / kill-chain (слой 4.6)
├── timeline.py — build_timeline, summarize_by_phase
└── TimelineEvents (findings + contradictions по фазам атаки)
│
▼
build_entities → Entities (internal / external, роли + pivot)
│
▼
Reporters → JSON + Markdown + flow report
Принципы
Разделение extract / detect / contradict / aggregate / report.
Никакой слой не делает работу другого.

Данные текут в одном направлении.
Никаких обратных связей, никакого общего мутабельного
состояния между слоями.

Каждый слой — реестр плагинов.
Новый экстрактор, детектор или правило contradictions — это
новый файл, а не правка существующего кода.

Finding — на сущность, не на инцидент.
Один finding = одна логическая находка, а не строка на каждый
flow или пакет.

Contradiction — надстройка над findings.
Правила contradictions не находят атаки — они ищут
несогласованности между слоями данных (DNS vs SNI, MAC vs IP,
роли vs поведение). Не дублируют детекторы.

Пороги и списки — в Config.
Никаких магических чисел в коде детекторов и правил. Все
пороги — поля Config, валидация в _validate().

FP-фильтр важнее recall.
100 findings, из которых 80 ложных, хуже, чем 20 findings,
из которых 5 ложных. Приоритет — точность.

Оффлайн-режим.
Никаких внешних API на пути основного прогона. Enrichment —
отдельный слой, по флагу --enrich.

Слой 1. Парсинг (parsers.py)
Собственный парсер пакетов через struct.unpack. Без scapy dissect.

Почему не scapy: на 334 МБ pcap профилирование показало, что
74% времени уходило на построение дерева слоёв scapy
(Packet.dissect). Мы используем 6-10 полей из каждого пакета,
а scapy строит полную объектную модель.

Решение: parse_packet(raw_bytes, ts) -> PacketRecord.

PacketRecord содержит:

мета: ts, length, raw (сырые байты)

L2: eth_src, eth_dst, ethertype, vlan_id

L3: src_ip, dst_ip, ip_proto, ip_id, ip_frag_offset, ip_mf

L4: proto, src_port, dst_port

TCP: tcp_seq, tcp_ack, tcp_flags

ARP: arp_op, arp_sender_mac/ip, arp_target_mac/ip

payload (L4-payload, не парсится)

Скорость: ~25 МБ/с против 0.6 МБ/с через scapy. 39x.

Fallback: если magic bytes не classic pcap (D4 C3 B2 A1) —
используется scapy PcapReader для pcapng.

Слой 2. Экстракторы (extractors/)
Реестр независимых экстракторов. Единственное место, где живут
scapy (для сложных payload) и ручные парсеры.

Порядок важен: FlowExtractor идёт первым. Остальные
экстракторы, пишущие в FlowStats, ищут существующий flow по
FlowKey и падают явно, если его нет.

Реализованы (11 + post-extract)
Экстрактор	Источник	Что пишет
flow.py	IP/TCP/UDP заголовки	state.flows[FlowKey] → FlowStats
dns.py	UDP/53 payload	state.dns_queries, dns_nxdomain_by_src
tls.py	TCP payload (ClientHello)	flow.sni, flow.ja3, flow.ja3s, state.session_sni
http.py	TCP payload (HTTP-запрос)	flow.http_host/uri/method/ua
host_identity.py	ARP	state.host_identities[ip].mac, mac_history
arp_history.py	ARP	state.arp_macs[ip][mac] = [first, last, count]
nbns.py	UDP/137	state.host_identities[ip].hostnames
kerberos.py	UDP/88, TCP/88	state.host_identities[ip].username/realm
| tls_cert.py | TCP stream (TLS Certificate handshake) | state.tls_certs: list[(FlowKey, Certificate)] — CN, SAN, issuer, validity, self_signed |

Почему два ARP-экстрактора:

host_identity.py — последний MAC на IP, для отчёта сущностей.

arp_history.py — полная история MAC на IP, для правила
mac_ip_conflict. Финальное значение не покажет ARP-spoof:
если хост отвечал двумя MAC, host_identities.mac сохранит
только последний.

Post-extract (после чтения всех пакетов)
reassembler.py — TCPReassembler, склейка TCP-сегментов
по sequence numbers с обработкой out-of-order и retransmit.
Лимиты: 1 МБ per-flow, 200 МБ total. Заполняет
state.tcp_streams и state.tcp_streams_truncated.
Вызывается до экстракторов в цикле чтения (feed по каждому
пакету), финализируется после.

http_object.py — HTTPObjectExtractor. Из tcp_streams
собирает полные HTTP запросы/ответы (Content-Length, chunked).
Заполняет state.http_objects. Двухпроходный парсинг: pass 1 —
requests (собираем URI), pass 2 — responses (URI пробрасывается
из парного request по нормализованному pair-key).
Не process(record, state) — метод run_post_extract(state, config).

tls_cert.py — TlsCertificateExtractor. Из tcp_streams
извлекает X.509 Certificate из TLS-хендшейка. Работает на
TLS 1.2 (в 1.3 сертификат зашифрован). Внутри:

  - x509_der.py — минимальный DER TLV-парсер (~250 LOC);
  - x509_cert.py — извлечение CN, issuer, validity,
    self_signed, SAN (DNS + IP) из DER-структуры;
  - tls_cert.py — парсер Certificate handshake (определяет
    границы сертификата в TCP-потоке).

Не process(record, state) — метод run_post_extract(state, config).
Заполняет state.tls_certs.

file_carve.py — метаданные payload'ов (sha256, размер,
MIME, первые 64 байта). Тело не пишется на диск по умолчанию.
Флаг file_carve_write_body позволяет сохранить как
<sha256>.bin. Функция carve_files(state, config, output_dir=None) -> list
возвращает список, присваивание делает pipeline.py.

Изоляция ошибок: падение одного экстрактора не роняет проход.
Ошибки считаются в state.extractor_errors[имя]. Ошибки
пост-обработки (http_object, file_carve) пишутся в тот же
счётчик.

Известное ограничение: TLS ClientHello и Kerberos-сообщения
могут быть фрагментированы. С v0.6.0 работает TCP reassembly —
проблема частично решена, но TLS/JA3 из tls.py всё ещё читается
из первого сегмента.

Слой 3. CaptureState (models.py)
Нормализованное представление захвата. Никакого scapy внутри.

python
@dataclass
class CaptureState:
       # DNS
    dns_queries: Counter           # qname → count
    dns_nxdomain: Counter
    dns_nxdomain_by_src: Counter
    dns_queries_by_src: dict[str, Counter]

    # DNS-ответы: name → {IP}, IP → {name}.
    # Нужно для правил sni_without_dns / direct_ip_no_dns /
    # dns_answer_mismatch — связывают домен, который клиент
    # резолвил, с IP, куда он ходил.
    dns_answers_by_name: dict[str, set[str]]
    dns_answers_by_ip: dict[str, set[str]]

    # flows
    flows: dict[FlowKey, FlowStats]
    session_sni: dict[SessionKey, str]

    # identity
    host_identities: dict[str, HostIdentity]
    arp_macs: dict[str, dict[str, list]]  # ip → {mac → [first, last, count]}

       # TCP reassembly
    tcp_streams: dict[FlowKey, bytes]
    tcp_streams_truncated: set[FlowKey]
    http_objects: list
    carved_files: list

    # X.509 сертификаты из TLS-хендшейков.
    # list[tuple[FlowKey, Certificate]] — как carved_files,
    # чтобы не плодить импорт-цикл models ↔ x509_cert.
    tls_certs: list

   

    # meta
    packet_count: int
    first_ts: float | None
    last_ts: float | None
    extractor_errors: Counter
FlowStats
Точка сборки контекста сессии:

базовая телеметрия: packets, bytes_sent, first_ts,
last_ts, initiated_by_src

(v0.7.0+: поле timestamps удалено — занимало до 160 МБ
на 4.7 ГБ pcap, использовалось только в старых версиях
beaconing. Список timestamps растёт неограниченно и
не нужен: beaconing работает по first_ts / last_ts.)

протокол-специфичные поля: sni, ja3, ja3s, http_host,
http_uri, http_method, http_user_agent

FlowKey
Направленный 5-tuple (proto, src_ip, dst_ip, src_port,
dst_port). A→B и B→A — разные ключи.

SessionKey + make_session_key() — нормализованный ключ
(направление схлопывается). Используется в session_sni и
reverse_asymmetry.

HostIdentity
Профиль хоста:

ip

mac (из ARP)

hostnames (из NBNS / Kerberos cname с $)

username (из Kerberos cname без $)

realm (из Kerberos crealm, FQDN предпочтительнее)

Слой 4. Детекторы (detectors/)
Чистые функции над CaptureState. Возвращают list[Finding].
Никакого scapy. Детекторы независимы, но фильтруют findings
друг друга (см. «Cross-detector связи»).

Контракт
python
class LocalDetector(Protocol):
    name: str
    def run(self, state: CaptureState, config: Config) -> list[Finding]: ...
Реализованы (19)
Детектор	Источник данных	Логика
dga	dns_queries	Энтропия label > порога, игнор дефисов, allowlist
suspicious_port	flows	Порт из списка, dst_ip внешний, агрегация по (dst_ip, dst_port)
port_scan	flows	Один src → много dst на один dst_port, тонкие цели
nxdomain_burst	dns_nxdomain_by_src	Count > порога с одного IP
cloud_tunnel	dns_queries	Суффиксы trycloudflare/ngrok/serveo/…
ip_check_service	dns_queries + flow.sni + flow.http_host + flow.dst_ip	4 источника, каноническое имя сервиса
typosquatting	dns_queries	SLD-only, contains + Levenshtein
sni_mismatch	flows.sni × dns_queries	SNI не в DNS, allowlist по суффиксу
ja3_malware	flows.ja3	Malware-JA3 из config.ja3_known_malware
brute_force	flows	HTTP: много коротких flows к одной (src, dst, port)
ftp_brute_force	flows	FTP: много flows с уникальными src_ports к (dst, 21)
beaconing	flows.timestamps	Периодичность (jitter < 0.1) + multi-tenant filter
dns_tunneling	dns_queries_by_src	Длинные уникальные поддомены под одним base
lateral_movement	flows	Internal→internal на 445/135/139/3389/5985/5986 + UA/URI-маркеры
large_transfer	flows	Пара прямого+обратного > 100 МБ (с exclude)
vulnerable_path	flows.http_uri	Подстроки в URI + web_scanner агрегация
command_injection	http_objects + flows	RCE в URI и POST body (io.popen, system(), subprocess…)
Служебный модуль mitre_map.py
MITRE_MAP: dict[str, tuple[str, ...]] — type → техники.
get_techniques(finding_type) — lookup.

Приоритет: instance-level Finding.mitre_techniques (если
детектор заполнил сам — например large_transfer по direction)
перебивает type-map. Заполнение происходит в pipeline.py:_detect:

python
for f in findings:
    if not f.mitre_techniques:
        f.mitre_techniques = get_techniques(f.type)
Cross-detector связи
Детекторы независимы, но фильтруют findings друг друга:

port_scan → suspicious_port. SuspiciousPortDetector
собирает scan_pairs: set[(src_ip, dst_port)] — пары, где один
src стучится к ≥ 10 разным dst. Если все src в finding'е —
сканеры на этом порту, finding пропускается.

vulnerable_path → web_scanner. Для пар (src_ip, dst_ip)
с ≥ 10 разными URI генерируется один web_scanner finding
вместо N individual.

ftp_brute_force ↔ brute_force. Взаимно исключающие:
brute_force пропускает port 21, ftp_brute_force работает
только на 21.

command_injection — агрегация. ≥ 5 hit'ов с одного
(src_ip, dst_ip) → один finding с count вместо N individual.

beaconing × large_transfer. Beaconing требует малый
размер flow (< 5 КБ), large_transfer — большой (> 100 МБ).
Не пересекаются.

Порядок регистрации в DETECTORS не важен: каждый детектор сам
собирает счётчики из state.flows.

Таблица FP-фильтров
Фильтр	Значение	Что отсеивает
port_scan_excluded_ports	{80, 443}	Браузер = скан на веб-портах
port_scan_max_flows_per_dst	3	Браузер с параллельными соединениями
port_scan_min_distinct_dsts	10	Одиночные соединения
web_scanner_min_distinct_paths	10	Одиночные обращения к уязвимым путям
brute_force_skip_tls_ports	{443, 8443}	HTTPS-браузер к CDN
brute_force_min_rate_flows_per_sec	0.01	Поллинг (Safe Browsing)
brute_force_max_avg_packets	20	FTP-сессии
ftp_brute_force_min_flows	20	Редкие FTP-подключения
beaconing_min_connections	20 (v0.7.0)	Единичные обращения
beaconing_max_jitter_ratio	0.1 (v0.7.0)	Нерегулярный трафик
beaconing_max_avg_bytes	5000	Загрузки, а не heartbeat
beaconing_payload_stddev_ratio_max	0.5	Переменный payload
beaconing_mail_polling_ports	{110, 143, 993, 995}	POP3/IMAP-поллинг — дизайн, не C2
dns_tunneling_min_qname_length	50	DGA-поддомены
dns_tunneling_min_long_qnames	20	Единичные длинные запросы
dns_tunneling_min_queries	50	Редкие запросы
lateral_movement_min_flows_port_only	5	Одиночный RDP к jump-host
large_transfer_min_bytes	100 MB	Обычные сессии
large_transfer_excluded_hosts	7 доменов	Windows Update, Apple CDN
typosquatting_levenshtein_threshold	2	Разные слова
dga_entropy_threshold	3.5	Человекочитаемые домены
Confidence для новых детекторов (0.5.0–0.7.0)
lateral_movement: 0.8 при UA/URI, 0.6 при «только порт»

large_transfer: 0.85

ftp_brute_force: 0.75 / 0.85 / 0.95 по объёму (20 / 50 / 100 flows)

beaconing: 0.6–0.85 линейно по jitter (0.2 → 0.05)

dns_tunneling: 0.7 / 0.9 по количеству длинных qname

ip_check_service: 0.7

command_injection: 0.9 (high-паттерн) / 0.6–0.7 (medium)

ja3_malware: 0.8–0.9 в зависимости от семейства

Слой 4.5. ContradictionDetector (contradictions/)
Новый слой в 0.7.0. Ищет не атаки, а несогласованности между
источниками данных: одно утверждение о мире подтверждается
одним источником и опровергается другим.

Модель данных (base.py)
python
@dataclass(frozen=True)
class Fact:
    source: str          # "dns" | "sni" | "http_host" | "ja3" | "arp" | "flow" | "finding"
    subject: str         # обычно IP
    predicate: str       # "victim_of" | "attacker_of" | "has_mac" |
                         # "sni" | "http_host" | "uses_ja3" | "uses_ua" |
                         # "session_asymmetry" | "protocol_on_port" |
                         # "direct_ip_connect" | "makes_dns_queries"
    value: str           # зависит от predicate; "" для ролевых фактов
    ts: float
    confidence: float
    evidence: dict

@dataclass
class Contradiction:
    rule: str
    subject: str
    facts: list[Fact]
    severity: str                # critical | high | medium | low | info
    confidence: float
    likely_causes: list[str]
    resolution_hint: str | None

    @property
    def priority(self) -> float:
        return SEVERITY_WEIGHT[self.severity] * self.confidence
Архитектура модуля
text
paradox/contradictions/
├── __init__.py            # экспорт run_all
├── base.py                # Fact, Contradiction, ContradictionRule, SEVERITY_WEIGHT
├── facts.py               # extract_*_facts для каждого типа источника
├── registry.py            # RULES, run_all()
└── rules/
    ├── b_mac_ip_conflict.py
    ├── c_sni_host_mismatch.py
    ├── d_ja3_ua_mismatch.py
    ├── e_reverse_asymmetry.py
    ├── e_victim_makes_attack.py
    ├── f_port_service_mismatch.py
    ├── g_direct_ip_no_dns.py
    ├── h_dns_answer_mismatch.py       # v0.7.0+: SNI vs резолвнутый IP
    ├── h_sni_without_dns.py           # v0.7.0+: SNI без DNS-ответа
    └── (tls_cert-правила)             # v0.7.0+: sni_cert_mismatch,
                                       # self_signed_cert, expired_cert
Функции извлечения фактов (facts.py) Замени её содержимое — старые 7 остаются, добавь 6 новых:
Правило	Severity base	
Источник фактов
victim_makes_attack	critical	findings (роли)
mac_ip_conflict	critical	state.arp_macs
sni_host_mismatch	high	flows (sni + http_host)
ja3_ua_mismatch	high	flows (ja3 + ua)
reverse_asymmetry	medium	flows (сессии)
port_service_mismatch	high	flows (protocol on port)
direct_ip_no_dns	medium	flows + dns_answers_by_ip
sni_without_dns	medium	flows (sni) + dns_answers_by_name
dns_answer_mismatch	medium	flows (sni) + dns_answers_by_name (CNAME-aware)
sni_cert_mismatch	medium	flows (sni) + state.tls_certs
self_signed_cert	medium	state.tls_certs
expired_cert	low	state.tls_certs
Функция	Что генерирует
extract_attack_facts(findings)	victim_of / attacker_of из findings
extract_arp_facts(state)	has_mac из state.arp_macs
extract_tls_host_facts(state, config)	sni / http_host из flows
extract_ja3_ua_facts(state, config)	uses_ja3 / uses_ua из flows
extract_asymmetry_facts(state, config)	session_asymmetry по сессиям
extract_protocol_on_port_facts(state, config)	protocol_on_port (tls/http)
extract_direct_ip_facts(state, config)	direct_ip_connect + makes_dns_queries
13 правил
Правило	Severity base	Источник фактов
victim_makes_attack	critical	findings (роли)
mac_ip_conflict	critical	state.arp_macs
sni_host_mismatch	high	flows (sni + http_host)
ja3_ua_mismatch	high	flows (ja3 + ua)
reverse_asymmetry	medium	flows (сессии)
port_service_mismatch	high	flows (protocol on port)
direct_ip_no_dns	medium	flows + dns_queries_by_src
Контракт правила
python
class ContradictionRule(Protocol):
    name: str
    severity_base: str
    def extract_facts(self, state, findings, config) -> list[Fact]: ...
    def find_contradictions(self, facts) -> list[Contradiction]: ...
Полярность findings
facts.py синхронизирован с entities.py (блок role_tags):

_ATTACK_TYPES: brute_force, ftp_brute_force, vulnerable_path,
command_injection, port_scan, web_scanner, lateral_movement.
→ src = attacker, dst = victim.

_VICTIM_SIGNAL_TYPES: beaconing, dns_tunneling,
script_download, nxdomain_burst, ja3_malware, sni_without_dns,
dga_domain, cloud_tunnel, ip_check_service, typosquatting,
suspicious_port. → src = victim, dst = C2.

large_transfer — по evidence.direction.

Если правишь полярность в одном месте — правь в обоих.

Почему после Detectors и до Aggregators
После detectors — потому что contradictions используют
findings как источник фактов.

До aggregators — потому что влияют на финальные роли хоста
(pivot — это не «жертва или атакующий», а «жертва + атакующий»).

Aggregation-tie-breaker
victim_makes_attack: одна Contradiction на subject. Из N
фактов выбирается самый уверенный, при равенстве — тот, у
которого непустой value (роль с адресатом важнее роли без него).

reverse_asymmetry: одна Contradiction на subject. Если
сессий ≥ 5 (bulk-паттерн), severity понижается до low,
conf × 0.7. Фикс FP на шлюзах/NAT — CyberCampTask 192.168.1.1
давал 9 «эксфильтраций» без агрегации.

Слой 4.6. Timeline / kill-chain (timeline.py)
Новый слой в v0.8.0. Собирает из findings и contradictions
хронологию событий и группирует по фазам kill-chain. Нового
анализа не делает — только упорядочивает уже найденное.

Модель данных (timeline.py)
python
@dataclass
class TimelineEvent:
    ts: float              # unix timestamp
    kind: str              # "finding" | "contradiction"
    type: str              # f.type / c.rule
    subject: str           # обычно IP
    severity: str
    confidence: float
    phase: str             # kill-chain фаза
    chain_order: int       # число для сортировки фаз
    description: str
    mitre_id: str | None
    ref_id: int            # индекс в исходном списке

Фазы kill-chain
Численный порядок:

recon          10   port_scan, web_scanner
initial_access 20   vulnerable_path, brute_force, ftp_brute_force,
                    typosquatting, mac_ip_conflict
execution      30   command_injection, script_download, carved_file
persistence    40   (зарезервировано)
lateral_movement 50 lateral_movement, victim_makes_attack
c2             60   beaconing, dns_tunneling, dga_domain, cloud_tunnel,
                    ja3_malware, ip_check_service, sni_without_dns,
                    sni_mismatch, suspicious_port, nxdomain_burst,
                    sni_host_mismatch, ja3_ua_mismatch,
                    port_service_mismatch, direct_ip_no_dns,
                    sni_cert_mismatch, self_signed_cert, expired_cert,
                    dns_answer_mismatch
exfiltration   70   large_transfer, reverse_asymmetry
impact         80   (зарезервировано)
other         999   всё, что не заведено

ts события: для finding — first_seen; для contradiction —
max(facts.ts) (момент, когда все подтверждающие факты уже
произошли).

Сортировка: ts → chain_order → subject → type → kind.
Детерминированно: одинаковый вход → побитово одинаковый список.

Функции
build_timeline(findings, contradictions=None) -> list[TimelineEvent]
summarize_by_phase(events) -> list[dict]
    Группировка по phase, отсортированная по chain_order:
    [{"phase": ..., "chain_order": ..., "count": ..., "events": [...]}, ...]

Интеграция
pipeline.run_pipeline строит timeline после contradictions и до
reporters. Возвращает ключ "timeline" в dict (плоский список).
Markdown-репортёр группирует по фазам в секции «Timeline»,
JSON — плоский список + по фазам (через summarize_by_phase в
потребителе).

Слой 5. Агрегаторы (aggregators/)
Превращают flow'ы, findings и contradictions в сущности (хосты).

entities.py
python
def build_entities(
    state, findings, config, contradictions=None
) -> Entities
Возвращает Entities(internal=[Entity], external=[Entity]).

contradictions — опционально. Нужен для роли pivot.

Entity
Один IP. Содержит:

ip, is_internal

roles: list[str]

first_seen, last_seen

flows_out/in, bytes_out/in

unique_dsts/srcs

sni_domains, dns_names

findings_indices

mac, hostname, username, realm

Роли
Роль	Когда
internal / external	Всегда
domain_controller	Много flows на порты 88/389/445 от разных внутренних src
attacker_candidate	attacker_tag из findings
victim_candidate	victim_tag из findings
c2_candidate	External с findings
gateway_candidate	Internal, много flows и уникальных dst
pivot	Rule victim_makes_attack сработало на IP
Роль pivot
Ставится поверх victim_candidate, если для IP есть
contradiction с rule == "victim_makes_attack". Не заменяет
роль, а дополняет:

victim_candidate — «этот хост надо спасать»;

pivot — «этот хост уже скомпрометирован и атакует дальше».

build_entities принимает contradictions через duck-typing
(getattr(c, "rule"), getattr(c, "subject")) — модуль
contradictions не импортируется в entities.py, чтобы не
плодить циклы.

Семантика тегов
Finding → IP → тег. Теги взаимоисключающие:

Finding	src → tag	dst → tag
brute_force	attacker_tag	victim_tag
ftp_brute_force	attacker_tag	victim_tag
vulnerable_path	attacker_tag	victim_tag
web_scanner	attacker_tag	victim_tag
port_scan	attacker_tag	(не выделяется)
lateral_movement	attacker_tag	victim_tag
beaconing	victim_tag	attacker_tag
script_download	victim_tag (инверсия)	attacker_tag
suspicious_port	victim_tag	attacker_tag
large_transfer	—	—
large_transfer не помечает роли. Статистический сигнал —
не роль: шлюз, качающий 2 ГБ обновлений, не victim. Роль
определяется через gateway_candidate или не ставится.

Слой 6. Reporters (reporters/)
JSON (json_reporter.py)
Структурированный отчёт. Схема: schema_version: "0.3.0".

Ключи:

provenance — tool_version, pcap_path, pcap_sha256

summary — пакеты, flows, findings, contradictions, направление

entities — internal, external

findings — список с mitre_techniques

contradictions — список (rule, subject, severity, confidence,
priority, likely_causes, resolution_hint, facts)

flows — top_by_bytes, top_by_packets

http — методы, hosts, URIs, UA

http_objects — полные HTTP-запросы/ответы

carved_files — метаданные payload'ов + MITRE-сводка

dns — top-by-count, nxdomain

Summary (полный список):

python
"summary": {
    "packets": int,
    "unique_dns_queries": int,
    "nxdomain_count": int,
    "flows": int,
    "findings": int,
    "contradictions": int,
    "extractor_errors": dict,
    "tcp_streams": int,
    "tcp_streams_truncated": int,
    "http_objects": int,
    "carved_files": int,
    "uploaded_bytes": int,
    "downloaded_bytes": int,
    "internal_bytes": int,
    "external_bytes": int,
}
MITRE-сводка кладётся в carved_files.mitre (необычное
место, но так в коде): total_techniques + by_technique.

Детерминизм: всё сортировано. Один pcap + config → побитово
одинаковый JSON.

Markdown (markdown_reporter.py)
Секции:

Header: файл, sha256, инструмент

TL;DR — цепочка findings в порядке kill-chain, PIVOT первым

Timeline — хронология findings

Carved Files — метаданные payload'ов

Сводка — пакеты, flows, contradictions

Сущности: internal (MAC, hostname, username, realm, pivot)

Findings: таблица + instance-level MITRE

Противоречия — секция с фактами и hint

HTTP: hosts, URIs, user-agents (_fmt_host → IP-литералы
помечаются как unknown host)

IOC: домены, IP, порты

Топ-10 flows

Kill-chain ordering:

python
_CHAIN_ORDER = {
    "pivot":              5,
    "web_scanner":       10,
    "port_scan":         20,
    "vulnerable_path":   30,
    "command_injection": 40,
    "brute_force":       50,
    "ftp_brute_force":   55,
    "script_download":   60,
    "carved_file":       65,
    "suspicious_port":   70,
    "ja3_malware":       75,
    "beaconing":         80,
    # ...
    "lateral_movement": 100,
    "large_transfer":   110,
}
TL;DR строится через _chain_for(findings) — уникальные типы
в порядке цепочки, не в порядке confidence. Это отражает
реальную последовательность атаки: pivot → сканирование →
эксплуатация → закрепление → C2 → эксфильтрация.

Flow report (flow_report.py)
conn.log-стиль: src, src_port, dst_ip, dst_port, proto, bytes, packets, duration, sni.

4 функции: build_flow_report (top_by_bytes, top_by_packets),
build_dns_report, build_http_report, build_http_object_report.

Слой 7. Pipeline (pipeline.py)
python
def run_pipeline(pcap_path: Path, config: Config) -> dict:
    state = CaptureState()

    _extract(pcap_path, state, config)
    findings = _detect(state, config)

       # Contradictions — между detectors и build_entities.
    # После detectors: используют findings.
    # До entities: влияют на роли (pivot).
    contradictions = run_contradictions(state, findings, config)

    # v0.8.0: timeline / kill-chain reconstruction.
    # Собираем события из findings + contradictions. Делается
    # ДО reporters: они читают готовый список.
    timeline_events = build_timeline(findings, contradictions)

    flow_report = build_flow_report(state, config, ...)

    dns_report = build_dns_report(state, ...)
    http_report = build_http_report(state, ...)
    http_objects_report = build_http_object_report(state, ...)
    carved_report = {...}
    entities = build_entities(state, findings, config,
                              contradictions=contradictions)
    direction_summary = _summarize_direction(state, config)

    return {
        "schema_version": "0.3.0",
        "provenance": {...},
        "summary": {...},
        "entities": {...},
        "dns": dns_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
    }
Ключевые точки:

_extract читает pcap, кормит TCPReassembler по пакету,
вызывает экстракторы, финализирует reassembly, строит
HTTPObject, делает FileCarve.

_detect вызывает все детекторы, потом заполняет MITRE.

run_contradictions — точка интеграции contradictions.

build_entities принимает contradictions опционально.

_summarize_direction считает uploaded / downloaded / internal /
external байты.

Реестры
python
EXTRACTORS = [
    FlowExtractor(),               # ДОЛЖЕН быть первым
    DNSExtractor(),
    TLSExtractor(),
    HTTPExtractor(),
    HostIdentityExtractor(),
    ARPMacHistoryExtractor(),      # 0.7.0: история MAC для mac_ip_conflict
    NBNSExtractor(),
     KerberosExtractor(),
    # tls_cert — не в EXTRACTORS: работает post-extract на готовых
    # TCP-потоках, вызывается из _extract отдельно.
]

]

DETECTORS = [
    DGADetector(),
    PortScanDetector(),
    SuspiciousPortDetector(),
    NXDOMAINBurstDetector(),
    CloudTunnelDetector(),
    IPCheckServiceDetector(),
    TyposquattingDetector(),
    SNIMismatchDetector(),
    JA3MalwareDetector(),
    BruteForceDetector(),
    FTPBruteForceDetector(),
    BeaconingDetector(),
    DNSTunnelingDetector(),
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
    CommandInjectionDetector(),
]

RULES = [
    VictimMakesAttackRule(),
    MacIpConflictRule(),
    SniHostMismatchRule(),
    Ja3UaMismatchRule(),
    ReverseAsymmetryRule(),
    PortServiceMismatchRule(),
    DirectIpNoDnsRule(),
    SniWithoutDnsRule(),           # v0.7.0+
    DnsAnswerMismatchRule(),       # v0.7.0+
    SniCertMismatchRule(),         # v0.7.0+
    SelfSignedCertRule(),          # v0.7.0+
    ExpiredCertRule(),             # v0.7.0+
]
]
Известная ошибка: если случайно поместить детектор в
EXTRACTORS или задублировать в DETECTORS — получишь либо
ошибки per-packet, либо дубликаты findings. Проверяй список
после правок.

Post-extract (после реестров, в _extract): TCPReassembler,
HTTPObjectExtractor, carve_files. Не экстракторы в общем
смысле — работают не на пакетах, а на готовых потоках.

Расширение
Новый экстрактор
Файл extractors/<name>.py. Класс с атрибутами name, layer,
методом process(record, state).

Регистрация в EXTRACTORS.

Тесты.

Новый детектор
Файл detectors/<name>.py. Класс с атрибутом name, методом
run(state, config) -> list[Finding].

Универсальные поля в evidence: src_ip, dst_ip, dst_port,
first_seen, last_seen.

Регистрация в DETECTORS (не забыть import).

Тесты — tests/test_<name>.py.

Новое правило contradictions
Файл contradictions/rules/<буква>_<name>.py.

Класс с name, severity_base, методами
extract_facts(state, findings, config) и
find_contradictions(facts).

Функция извлечения фактов в facts.py (если новый источник).

Регистрация в RULES.

Тесты — tests/test_<name>.py.

Новый reporter
Файл reporters/<name>_reporter.py.

Функция, принимающая dict от run_pipeline.

Вызов из pipeline.py + добавление в возвращаемый dict +
вызов из cli.py.

Finding
Универсальный контракт находки. Top-level поля — то, чем
пользуются кросс-детекторные потребители: contradictions/facts.py,
aggregators/entities.py, reporters. Всё остальное (специфика
конкретного детектора) — в evidence.

python
@dataclass
class Finding:
    type: str
    value: str
    confidence: float

    # Универсальные поля (v0.8.0)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    severity: str = "medium"   # critical | high | medium | low | info

    first_seen: float | None = None
    last_seen: float | None = None
    mitre_techniques: tuple[str, ...] = ()

    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def mitre_id(self) -> str | None:
        return self.mitre_techniques[0] if self.mitre_techniques else None

Мост совместимости v0.8.0 — pipeline._normalize_finding.
После _detect и MITRE-обогащения pipeline проходит по всем
findings и вытаскивает top-level поля из evidence:
  src_ip / dst_ip / dst_port   — fallback на evidence-ключи
                                 (в т.ч. агрегированные
                                 top_src_ips / dst_ips / dst_ports
                                 для vulnerable_path и script_download)
  severity                     — из _SEVERITY_BY_TYPE: dict по типу
                                 (временный, уйдёт в v0.9)

Читатели (facts.py, entities.py) в переходный период используют
fallback: `src = f.src_ip or ev.get("src_ip")`. Уйдёт в v0.9,
когда детекторы начнут заполнять контракт сами.

MITRE заполняется в pipeline._detect после всех детекторов:
если instance-level mitre_techniques пуст — берём из
detectors/mitre_map.py::get_techniques(f.type). В v0.8.0
покрытие MITRE_MAP доведено до 100% типов findings (добавлены
command_injection, beaconing, dns_tunneling, ja3_malware,
sni_mismatch, cloud_tunnel).

Известные долги (0.8.0)
_normalize_finding в pipeline — временный мост v0.8.0. Вытаскивает
top-level поля Finding из evidence. Уйдёт в v0.9, когда детекторы
начнут заполнять контракт сами и дубли в evidence уберутся.
Пока работают оба механизма параллельно.

_SEVERITY_BY_TYPE в pipeline — временная карта тип→severity.
Уйдёт вместе с _normalize_finding.

vulnerable_path / script_download пишут findings в агрегированном
виде (top_src_ips / dst_ips / dst_ports — списки, не одиночные
поля). _normalize_finding это нормализует, но правильнее —
чтобы детекторы писали src_ip / dst_ip в self явно на этапе
агрегации. TODO v0.9.

TLS 1.3 Certificate зашифрован. Правила sni_cert_mismatch /
self_signed_cert / expired_cert работают только на TLS 1.2
(и на pcap до 2018). Обходной путь — keylog, пока не сделан.

JA3-хеши браузеров не в config. Все неизвестные → family=normal.
Правило ja3_ua_mismatch ловит только tool/malware.

IPv6 не поддержан в парсере.

nxdomain_burst считает за весь файл — не по окну. 93
findings на FIN-2015, часть могут быть FP.

beaconing чувствителен к jitter — медленные C2 (> 1 часа)
не ловятся без windowing.

Двухуровневые TLD (co.uk, com.au) не поддержаны в SLD.
Влияет на sni_host_mismatch, dns_answer_mismatch, typosquatting.

Внутренний C2 (internal → internal зашифрованный) не
детектируется без HTTP/2 framing.


История версий (архитектурно значимые)
0.1.x
Raw parser + 39x ускорение.

Flow, DNS экстракторы. 6 детекторов.

0.2.x
TLS, HTTP экстракторы.

SNI mismatch, brute_force, vulnerable_path.

Entities с ролями.

0.3.x
HostIdentity (ARP), NBNS, Kerberos.

MTA-задание 5/5 (IP, MAC, hostname, username, realm).

0.4.0
PortScanDetector — 11-й детектор.

Typosquatting SLD-only — переписан.

VulnerablePathDetector — агрегация + web_scanner.

Массовая FP-чистка. 5872 → 343 findings.

0.5.x
LateralMovementDetector — WinRM/PsExec/SMB/RDP между
внутренними хостами.

LargeTransferDetector — пары flow > 100 МБ + exclude.

FTPBruteForceDetector — отдельно от HTTP-brute_force.

IPCheckServiceDetector расширен — 4 источника матчинга.

13 детекторов. CyberCampTask: 6 findings, 0 FP.

0.6.0
TCP Reassembly — TCPReassembler + state.tcp_streams.

HTTPObjectExtractor — полные HTTP-запросы/ответы.

FileCarve — метаданные payload'ов.

JA3/JA3S fingerprinting — из TLS ClientHello/ServerHello.

CommandInjectionDetector — RCE в URI и body.

BeaconingDetector — периодические heartbeat.

DNSTunnelingDetector — длинные уникальные поддомены.

Enrichment (--enrich) — Shodan InternetDB, AbuseIPDB,
SQLite-кэш.

19 детекторов, 244 теста.

0.7.0
ContradictionDetector — новый слой анализа.

paradox/contradictions/ — base, facts, registry, rules.

13 правил: victim_makes_attack, mac_ip_conflict,
sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry,
port_service_mismatch, direct_ip_no_dns.

Факты: attack, arp, tls_host, ja3_ua, asymmetry,
protocol_on_port, direct_ip.

Роль pivot в entities (поверх victim_candidate).

Секция «Противоречия» в markdown_reporter + TL;DR с PIVOT.

ARPMacHistoryExtractor — история MAC на IP.

LargeTransfer direction — inbound/outbound/internal/external +
bytes_in/bytes_out + instance-level mitre_techniques.

TL;DR в порядке kill-chain — _CHAIN_ORDER + _chain_for().

_fmt_host — IP-литералы в HTTP Host помечаются как
(unknown host).

Beaconing переработан — пороги 20/600/0.1, multi-tenant filter,
mail polling filter, payload stddev, allowlist SNI/Host.

CLI -o корректно работает с директориями.

Схема JSON: 0.2.0 → 0.3.0 (top-level contradictions).

570 теста. FIN-2015: 386 findings, 11 contradictions.
CyberCampTask: 7 findings, 2 contradictions.

0.7.0+ (backend-сессия: DNS + TLS)
DNS-ответы:
- парсер A/AAAA/CNAME в extractors/dns.py
- dns_answers_by_name / dns_answers_by_ip в CaptureState
- CNAME-цепочки склеиваются (www.foo.com → cdn.foo.com → 1.2.3.4)
- direct_ip_no_dns переделан: per-IP фильтр через
  dns_answers_by_ip вместо «клиент вообще делал DNS-запросы»
- новое правило sni_without_dns (SNI без DNS-ответа, medium)
- новое правило dns_answer_mismatch (CNAME-aware, medium)
- SNIMismatchDetector расширен: сравнение с dns_answers_by_name
- allowlist CDN + twitter — FP на FIN-2015 срезаны

TLS-сертификаты:
- paradox/x509_der.py — минимальный DER TLV-парсер (~250 LOC)
- paradox/x509_cert.py — извлечение CN/issuer/validity/SAN
- paradox/tls_cert.py — парсер Certificate handshake из TCP-потока
- paradox/extractors/tls_cert.py — post-extract экстрактор
- state.tls_certs: list[tuple[FlowKey, Certificate]]
- 3 новых правила: sni_cert_mismatch (medium),
  self_signed_cert (medium), expired_cert (low)

Убрано мёртвое FlowStats.timestamps — ~160 МБ экономии
на 4.7 ГБ pcap (использовалось только в старом beaconing).

Тесты: 302 → 570 passed (+78), 25 → 33 файла тестов.

Проверено:
- FIN-2015: 58 pcap, 9.5M пакетов, 0 ошибок
- CyberCampTask: 7 findings / 2 contradictions (baseline)
- sni_without_dns findings: 73 → 0 (allowlist CDN/brands)
- direct_ip_no_dns: ожило на FIN-2015 (192.168.0.54)
- tls_certs: 2 сертификата извлечено на тестовом pcap

0.8.0
Универсальный контракт Finding:
- top-level поля src_ip / dst_ip / dst_port / severity
- property mitre_id (первая техника из mitre_techniques)
- to_dict() добавляет mitre_id в сериализацию
- pipeline._normalize_finding — мост из evidence в top-level
- _SEVERITY_BY_TYPE — временная карта тип→severity
- fallback в читателях: src = f.src_ip or ev.get("src_ip")
- нормализация агрегированных ключей top_src_ips / dst_ips /
  dst_ports (vulnerable_path, script_download)

MITRE_MAP: 100% покрытие типов findings. Добавлены:
command_injection (T1190, T1059), beaconing (T1071.001),
dns_tunneling (T1071.004), ja3_malware (T1071.001),
sni_mismatch (T1071.001), cloud_tunnel (T1572).

Timeline / kill-chain reconstruction:
- paradox/timeline.py — новый модуль
- TimelineEvent, build_timeline, summarize_by_phase
- фазы recon / initial_access / execution / persistence /
  lateral_movement / c2 / exfiltration / impact / other
- интеграция в pipeline (ключ "timeline") и markdown
  (секция "Timeline" с группировкой по фазам)
- 32 теста в tests/test_timeline.py

Читатели переключены на контракт с fallback:
- contradictions/facts.py::extract_attack_facts
- aggregators/entities.py::_ips_from_finding

Тесты: 380 → 570 passed (+32).

0.9.0 (текущая)
Новые экстракторы (3):
- dhcp.py — UDP 67/68. IP↔MAC↔hostname из BOOTP/DHCP.
- ssh_banner.py — TCP 22/2222/2022. SSH-баннер (RFC 4253):
  server/client software versions.
- smtp.py — TCP 25/587. EHLO/HELO, MAIL FROM, RCPT TO,
  X-Mailer/User-Agent.

Новые детекторы (2):
- ssh_brute_force — 20+ SSH-баннеров с одного src к одной
  паре (dst_ip, dst_port). T1110.001 + T1021.004.
- smtp_spam — 50+ уникальных RCPT TO с одного src.
  T1583.002, phase impact.

nxdomain_burst: скользящее окно (60s) + ratio-фильтр (min 0.2).
93 → ~20-30 на FIN-2015.

CarvedFile в timeline: payload как событие execution (T1105).

Двухуровневые TLD (domain_utils.py): co.uk, com.au, co.jp и др.
28 тестов.

Снятие моста v0.8.0:
- Finding.__post_init__ — нормализация в одну точку.
- _SEVERITY_BY_TYPE переехал в models.
- fallback `or ev.get(...)` в читателях убран.

Тесты: 412 → 570.

Что дальше
0.9.0 — новые экстракторы и снятие моста:

Новые экстракторы:
- SMB2, DHCP, SSH-баннер, SMTP.
- HTTP/2 framing (HPACK для headers).
- IPv6 в парсере.

Снятие моста v0.8.0:
- детекторы пишут src_ip / dst_ip / dst_port напрямую,
  дубли в evidence убираются.
- удаление _normalize_finding и _SEVERITY_BY_TYPE.
- удаление fallback `f.src_ip or ev.get("src_ip")` в читателях.
- vulnerable_path / script_download пишут одиночные поля
  на этапе агрегации.

1.0.0 — стабильный API:

STIX 2.1 экспорт IOC.

REST API + Web UI.

Плагины (пользовательские правила contradictions).