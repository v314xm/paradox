# Архитектура Paradox v1.2.0

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются через
структуры данных.
PCAP
│
▼
RawPcapReader / PcapReader (по magic bytes)
│
▼
parse_packet (struct.unpack) → PacketRecord
│
▼
Extractors (12) + TCPReassembler (feed по пакету)
│
▼
CaptureState (flows, dns, answers, host_identities, arp_macs,
tcp_streams, http_objects, tls_certs, carved_files,
ssh_, smtp_, ndp_*)
│
▼
Post-extract (после чтения всех пакетов)
├── TCPReassembler.finalize_all → tcp_streams
├── HTTPObjectExtractor.run_post_extract → http_objects
├── TlsCertificateExtractor.run_post_extract → tls_certs
└── carve_files → carved_files
│
▼
Detectors (20) → Findings
│
▼
ContradictionDetector (12 правил)
│
▼
Timeline (kill-chain reconstruction)
│
▼
build_entities (роли + pivot)
│
▼
build_attack_graph (пути атаки: entry → pivot → impact)
│
▼
Reporters: JSON + Markdown + Flow report + IOC + Attack Graph

text

## Принципы

1. **Разделение слоёв.** extract / detect / contradict / timeline /
   aggregate / graph / report. Никакой слой не делает работу другого.
2. **Данные текут в одном направлении.** Никаких обратных связей.
3. **Каждый слой — реестр плагинов.** Новый экстрактор, детектор,
   правило — это новый файл + регистрация, не правка существующего.
4. **Finding — на сущность, не на инцидент.** Один finding = одна
   логическая находка.
5. **Contradiction — надстройка над findings.** Правила не находят
   атаки, а ищут несогласованности между источниками (DNS vs SNI,
   MAC vs IP, роли vs поведение).
6. **Пороги — в Config.** Никаких магических чисел в детекторах.
7. **FP-фильтр важнее recall.** 100 findings из 80 ложных хуже, чем
   20 из 5 ложных.
8. **Оффлайн по умолчанию.** Enrichment — отдельный слой, по флагу
   `--enrich`.
9. **Multi-pcap — расширение, не переписывание.** `run_multi_pipeline`
   — append-only, `run_pipeline` не тронут.

## Слой 1. Парсинг (`parsers.py`, `parsers_ipv6.py`)

Собственный парсер через `struct.unpack`. Без scapy dissect.
39x быстрее.

**IPv4:** Ethernet, 802.1Q VLAN, IPv4 (фрагментация), TCP, UDP,
ICMP, ARP.

**IPv6:** заголовок, extension chain (HopByHop, Routing, Fragment,
ESP, Auth, DestOptions, Mobility), извлечение портов. Мета в
`PacketRecord.ipv6_meta`.

**`parse_packet(raw, ts) -> PacketRecord`** — все L2-L4 поля +
payload (не парсится).

## Слой 2. Экстракторы (`extractors/`) — 12

Contract: `Extractor` Protocol — `name`, `layer`, `process(record, state)`.

`FlowExtractor` **обязательно первый** — остальные ищут существующий
flow по `FlowKey` и падают явно, если его нет.

| Экстрактор | Источник | Что пишет |
|---|---|---|
| flow | IP/TCP/UDP | `state.flows` |
| dns | UDP/53 | `dns_queries`, `dns_nxdomain*`, `dns_answers_by_name/ip` |
| tls | ClientHello | `flow.sni/ja3/ja3s`, `session_sni` |
| http | HTTP-запрос | `flow.http_*` |
| host_identity | ARP | `host_identities[ip].mac` |
| arp_history | ARP | `arp_macs[ip][mac]` |
| dhcp | UDP 67/68 | MAC + hostname |
| ssh_banner | TCP 22 | `ssh_server_versions`, `ssh_client_attempts` |
| smtp | TCP 25/587 | `smtp_helo/from/rcpt/mailer` |
| nbns | UDP/137 | `hostnames` |
| kerberos | UDP/TCP 88 | `username`, `realm`, `hostnames` |
| ndp | ICMPv6 | `ndp_neighbors`, `ndp_routers` |

**Post-extract (не в EXTRACTORS):**
- `TCPReassembler` — склейка TCP, лимиты 1 МБ/flow, 200 МБ total
  (освобождается при finalize в v1.1)
- `HTTPObjectExtractor.run_post_extract()` — полные HTTP-запросы/ответы
- `TlsCertificateExtractor.run_post_extract()` — X.509 из TLS
- `carve_files()` — метаданные payload'ов (sha256, MIME, magic)

Изоляция ошибок: падение одного экстрактора не роняет проход,
счётчик в `state.extractor_errors[name]`.

## Слой 3. CaptureState (`models.py`)

Нормализованное представление захвата. Никакого scapy внутри.

**DNS:** `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`,
`dns_queries_by_src`, `dns_answers_by_name`, `dns_answers_by_ip`,
`dns_nxdomain_ts_by_src`.

**Flows:** `flows[FlowKey] → FlowStats`, `session_sni[SessionKey]`.

**Identity:** `host_identities`, `arp_macs`.

**TCP:** `tcp_streams`, `tcp_streams_truncated`, `http_objects`,
`carved_files`, `tls_certs`.

**SSH/SMTP/NDP (v0.9+):** `ssh_server_versions`,
`ssh_client_versions`, `ssh_client_attempts`, `smtp_*`, `ndp_*`.

**Meta:** `packet_count`, `first_ts`, `last_ts`, `extractor_errors`.

### FlowKey vs SessionKey

`FlowKey` — направленный 5-tuple. A→B и B→A разные ключи.

`SessionKey` + `make_session_key()` — нормализованный двунаправленный
ключ. Используется в `session_sni` и `reverse_asymmetry`.

## Слой 4. Детекторы (`detectors/`) — 20

Чистые функции над `CaptureState`. `run(state, config) -> list[Finding]`.

| Детектор | Логика |
|---|---|
| dga | энтропия label |
| suspicious_port | external dst, порт из списка |
| port_scan | 1 src → много dst на 1 порт |
| nxdomain_burst | скользящее окно 60s + ratio |
| cloud_tunnel | суффиксы ngrok/trycloudflare/… |
| ip_check_service | 4 источника (DNS/SNI/Host/direct) |
| typosquatting | SLD contains + levenshtein |
| sni_mismatch | SNI без DNS-ответа |
| ja3_malware | из `ja3_known_malware` |
| brute_force | HTTP-перебор |
| ftp_brute_force | 20+ flows на 21 |
| ssh_brute_force | 20+ SSH-баннеров |
| smtp_spam | 50+ RCPT TO |
| beaconing | jitter + multi-tenant + payload stddev |
| dns_tunneling | длинные поддомены |
| lateral_movement | internal→internal на 445/3389/… |
| large_transfer | 100MB в flow (или паре) |
| vulnerable_path | wp-login/.env + web_scanner |
| command_injection | RCE в URI/body |
| yara | YARA на carved_files |

**MITRE:** instance-level `Finding.mitre_techniques` приоритетнее
type-map в `detectors/mitre_map.py`.

## Слой 4.5. ContradictionDetector (`contradictions/`) — 12 правил

Ищет не атаки, а **несогласованности между источниками**: одно
утверждение о мире подтверждается одним источником и опровергается
другим.

**`Fact`** (frozen): `source`, `subject`, `predicate`, `value`,
`ts`, `confidence`, `evidence`.

**`Contradiction`:** `rule`, `subject`, `facts`, `severity`,
`confidence`, `likely_causes`, `resolution_hint`,
`priority = severity_weight × confidence`.

**12 правил:**
- `victim_makes_attack` (critical) — pivot
- `mac_ip_conflict` (critical) — ARP-spoof
- `sni_host_mismatch` (high) — domain fronting
- `ja3_ua_mismatch` (high) — мимикрия
- `port_service_mismatch` (high) — туннель
- `reverse_asymmetry` (medium) — эксфильтрация
- `direct_ip_no_dns` (medium) — hardcoded IP
- `sni_without_dns` (medium) — SNI без резолва
- `dns_answer_mismatch` (medium) — CNAME-aware
- `sni_cert_mismatch` (medium) — CN/SAN ≠ SNI
- `self_signed_cert` (medium) — issuer == subject
- `expired_cert` (low) — not_after < ts

**Полярность findings** синхронизирована с `entities.py` — при
правке менять в обоих местах.

**Место в pipeline:** после detectors (нужны findings), до
entities (влияют на pivot).

## Слой 4.6. Timeline (`timeline.py`)

Kill-chain reconstruction из findings + contradictions +
carved_files. Нового анализа не делает — упорядочивает.

**`TimelineEvent`:** `ts`, `kind`, `type`, `subject`, `severity`,
`confidence`, `phase`, `chain_order`, `description`, `mitre_id`.

**Фазы:** recon(10) → initial_access(20) → execution(30) →
persistence(40) → lateral_movement(50) → c2(60) → exfiltration(70)
→ impact(80) → other(999).

**Сортировка:** `ts → chain_order → subject → type → kind`.
Детерминированно.

## Слой 5. Агрегаторы (`aggregators/entities.py`)

Один IP = одна `Entity`. Вместо N flow-строк — M сущностей.

**Роли:** `internal`/`external` (всегда), `domain_controller`,
`attacker_candidate`, `victim_candidate`, `c2_candidate`,
`gateway_candidate`, `pivot` (поверх `victim_candidate`).

`contradictions` принимаются через duck-typing
(`getattr(c, "rule")`) — без импорта, чтобы не плодить циклы.

## Слой 5.5. Attack Graph (`analyzers/attack_graph.py`) — v1.2.0

Directed graph атаки: узлы = IP, рёбра = findings с (src, dst),
пути = BFS от entry к impact.

**Entry:** внутренние `victim_candidate` или external→internal
с initial_access.

**Impact:** `c2_candidate`/`attacker_candidate` или impact-phase.

**Pivot:** из `victim_makes_attack`.

**Multi-pcap** (`multi_pcap.py`): `merge_capture_states([s1, s2, …])`
— слияние N `CaptureState`. Вызывается из `run_multi_pipeline`
(append-only в `pipeline.py`, `run_pipeline` не тронут).

## Слой 6. Reporters (`reporters/`)

**JSON** (`json_reporter.py`): схема `0.3.0`. Все секции
отсортированы — детерминизм. Ключи: `provenance`, `summary`,
`entities`, `findings`, `contradictions`, `attack_graph`,
`timeline`, `flows`, `http`, `http_objects`, `carved_files`,
`dns`, `absence`, `ioc_files`.

**Markdown** (`markdown_reporter.py`): 11 секций, TL;DR в порядке
kill-chain (не confidence). PIVOT первым.

**Flow report** (`flow_report.py`): conn.log-стиль.

**IOC reporter** (`ioc_reporter.py`, v1.0.0): `iocs.txt`,
`iocs.csv`, `iocs.json`, `suricata.rules` (SID 9000000+),
`queries.txt` (KQL + Splunk).

## Реестры

```python
EXTRACTORS = [FlowExtractor(), ..., NDPExtractor()]  # 12, flow первым
DETECTORS  = [...20...]                               # порядок не важен
RULES      = [...12...]                               # порядок не важен
Post-extract (не экстракторы): TCPReassembler,
HTTPObjectExtractor, TlsCertificateExtractor, carve_files — работают
на готовых потоках, вызываются из _extract.

Расширение
Новый экстрактор: файл extractors/<name>.py + класс с
name, layer, process(record, state) + регистрация в
EXTRACTORS + тесты.

Новый детектор: файл detectors/<name>.py + класс с
name, run(state, config) -> list[Finding] + регистрация в
DETECTORS + тесты. Заполнять top-level src_ip/dst_ip/
dst_port (не только в evidence).

Новое правило: файл contradictions/rules/<буква>_<name>.py +
класс с name, severity_base, extract_facts, find_contradictions

extract_*_facts в facts.py (если новый источник) + регистрация
в RULES + тесты.

Новый reporter: файл reporters/<name>_reporter.py + функция
(report_dict) -> ... + вызов из pipeline.py + добавление в
возвращаемый dict + вызов из cli.py.

Ключевой контракт: Finding
python
@dataclass
class Finding:
    type: str
    value: str
    confidence: float

    # Универсальные поля — их читают facts.py, entities.py,
    # reporters, attack_graph, timeline
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    severity: str = "medium"

    first_seen: float | None = None
    last_seen: float | None = None
    mitre_techniques: tuple[str, ...] = ()

    evidence: dict[str, Any] = field(default_factory=dict)
__post_init__ нормализует top-level поля из evidence:

src_ip ← evidence.src_ip → top_src_ips → src_ips

dst_ip ← evidence.dst_ip → dst_ips → top_dst_ips

dst_port ← evidence.dst_port → dst_ports

severity ← _SEVERITY_BY_TYPE[type] если осталось "medium"

Детектор должен заполнять top-level src_ip/dst_ip
напрямую, чтобы не полагаться на fallback. Fallback существует для
совместимости.

confidence_reasons автоматически заполняется через
detectors/explainer.py::build_reasons(evidence).

GUI (paradox_gui/)
Отдельный пакет, ядро не трогает — работает через
run_pipeline/run_multi_pipeline в QThread.

8 вкладок: Прогон, История, Обогащение, Настройки, IPv6,
Таймлайн, Экспорт, Сравнение.

Workers (QThread): AnalysisWorker (принимает str | list[str]),
EnrichmentWorker, QuickCheckWorker.

Диалоги: Attack Graph (с Time Machine + PNG/DOT/GraphML),
Graph связей, Contradiction, Finding, Carved files, Host story,
What-If.

Ключевое: GUI не модифицирует ядро. Все изменения через
Config + monkey-patch DETECTORS/RULES в воркере с откатом в
finally.

Известные ограничения v1.2.0
TLS 1.3 Certificate зашифрован — правила на сертификатах только
для TLS 1.2.

JA3 браузеров не в config — ja3_ua_mismatch работает только на
tool/malware.

beaconing не ловит медленный C2 (интервал > часа) — нужен
windowing.

Внутренний C2 (internal→internal зашифрованный) вне зоны
видимости.

IPv6 в ioc_reporter не тестируется.

NDPExtractor без layer = 0 — нарушает Protocol.

test_multi_pcap.py — 0 тестов.

История версий (архитектурно значимые)
См. CHANGELOG.md. Ключевые точки:

v0.4.0 — mass FP-чистка, port_scan, 5872 → 343 findings.

v0.6.0 — TCP reassembly, HTTPObject, FileCarve, JA3, enrichment.

v0.7.0 — ContradictionDetector, pivot, 12 правил.

v0.8.0 — Timeline / kill-chain, универсальный контракт Finding.

v0.9.0 — DNS-ответы, X.509, IPv6, DHCP/SSH/SMTP/NDP/YARA.

v1.0.0 — стабилизация, 942 теста.

v1.1.0 — severity guards, evidence fallbacks, IPv6 IOC.

v1.2.0 — Attack Graph, Multi-pcap, Splash, Logo, Diff.

Связанные документы
README.md — обзор, quick start, метрики.

MODULES.md — описание каждого файла: что делает, классы,
функции, связи.

CHANGELOG.md — история версий с деталями.

TODO.md — что дальше.
