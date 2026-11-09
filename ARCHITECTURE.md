# Архитектура Paradox v1.5.1

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются через
структуры данных.

```text
PCAP
│
▼
RawPcapReader; pcapng отвергается с подсказкой editcap
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
├── TLSExtractor.run_post_extract → sni/ja3/ja3s из склеенных потоков
└── carve_files → carved_files
   (после этого tcp_streams освобождаются)
│
▼
Detectors (24) → Findings
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
Reporters: JSON + Markdown + Flow report + IOC + HTML + STIX
```

## Принципы

1. **Разделение слоёв.** extract / detect / contradict / timeline /
   aggregate / graph / report. Никакой слой не делает работу другого.
2. **Данные текут в одном направлении.** Никаких обратных связей.
3. **Каждый слой — реестр плагинов.** Новый экстрактор, детектор,
   правило — это новый файл + регистрация, не правка существующего.
   Пользовательские детекторы подключаются из `~/.paradox/plugins`
   без изменения кода.
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
10. **Отчёт не должен быть опасным файлом.** Тела, на которых
    сработали детекторы, хранятся в base64: цельных сигнатур
    веб-шеллов в JSON нет.

## Слой 1. Парсинг (`parsers.py`, `parsers_ipv6.py`)

Собственный парсер через `struct.unpack`. Без scapy dissect.

**IPv4:** Ethernet, 802.1Q VLAN, IPv4 (фрагментация), TCP, UDP,
ICMP, ARP.

**IPv6:** заголовок, extension chain (HopByHop, Routing, Fragment,
ESP, Auth, DestOptions, Mobility), извлечение портов. Мета в
`PacketRecord.ipv6_meta`.

**`parse_packet(raw, ts) -> PacketRecord`** — все L2-L4 поля +
payload (не парсится).

## Слой 2. Экстракторы (`extractors/`) — 12

Contract: `Extractor` Protocol — `name`, `layer`, `process(record, state)`.
У всех 12 экстракторов `layer = 0`.

`FlowExtractor` **обязательно первый** — остальные ищут существующий
flow по `FlowKey` и падают явно, если его нет.

| Экстрактор | Источник | Что пишет |
|---|---|---|
| flow | IP/TCP/UDP | `state.flows` |
| dns | UDP/53 | `dns_queries`, `dns_nxdomain*`, `dns_answers_by_name/ip` |
| tls | ClientHello | `flow.sni/ja3/ja3s`, `session_sni` |
| http | HTTP-запрос | `flow.http_*` |
| host_identity | ARP | `host_identities[ip].mac` |
| arp_mac_history | ARP | `arp_macs[ip][mac]` |
| dhcp | UDP 67/68 | MAC + hostname |
| ssh_banner | TCP 22 | `ssh_server_versions`, `ssh_client_attempts` |
| smtp | TCP 25/587 | `smtp_helo/from/rcpt/mailer` |
| nbns | UDP/137 | `hostnames` |
| kerberos | UDP/TCP 88 | `username`, `realm`, `hostnames` |
| ndp | ICMPv6 | `ndp_neighbors`, `ndp_routers` |

**Post-extract (не в EXTRACTORS):**
- `TCPReassembler` — склейка TCP, лимиты 1 МБ/flow, 200 МБ total;
  потоки сверх лимита помечаются truncated
- `HTTPObjectExtractor.run_post_extract()` — все HTTP-сообщения
  потока (keep-alive, pipelining)
- `TlsCertificateExtractor.run_post_extract()` — X.509 из TLS
- `TLSExtractor.run_post_extract()` — SNI/JA3 из склеенных потоков:
  ClientHello больше одного сегмента потоковый экстрактор не видит
- `carve_files()` — метаданные payload'ов (sha256, MIME, magic)

После post-extract `state.tcp_streams` освобождаются: сырые байты
потоков больше не нужны и держали бы до 200 МБ до конца прогона.

Изоляция ошибок: падение одного экстрактора не роняет проход,
счётчик в `state.extractor_errors[name]`.

## Слой 3. CaptureState (`models.py`)

Нормализованное представление захвата. Никакого scapy внутри.

**DNS:** `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`,
`dns_queries_by_src`, `dns_answers_by_name`, `dns_answers_by_ip`,
`dns_nxdomain_ts_by_src`, `dns_query_ts_by_name`, `dns_query_ts_by_src`.

**Flows:** `flows[FlowKey] → FlowStats`, `session_sni[SessionKey]`.

**Identity:** `host_identities`, `arp_macs`.

**TCP:** `tcp_streams`, `tcp_streams_total`, `tcp_streams_truncated`,
`http_objects`, `carved_files`, `tls_certs`.

**SSH/SMTP/NDP:** `ssh_server_versions`, `ssh_client_versions`,
`ssh_client_attempts`, `smtp_*`, `ndp_*`.

**Meta:** `packet_count`, `first_ts`, `last_ts`, `extractor_errors`.

### FlowKey vs SessionKey

`FlowKey` — направленный 5-tuple. A→B и B→A разные ключи.

`SessionKey` + `make_session_key()` — нормализованный двунаправленный
ключ. Используется в `session_sni` и `reverse_asymmetry`.

## Слой 4. Детекторы (`detectors/`) — 24

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
| ja3s_malware | серверный JA3S из `ja3s_known_malware` |
| brute_force | HTTP-перебор |
| ftp_brute_force | 20+ flows на 21 |
| ssh_brute_force | 20+ SSH-баннеров |
| smtp_spam | 50+ RCPT TO |
| beaconing | jitter + multi-tenant + payload stddev (+ slow-режим) |
| dns_tunneling | длинные поддомены |
| lateral_movement | internal→internal на 445/3389/… |
| large_transfer | 100MB в flow (или паре) |
| vulnerable_path | wp-login/.env + web_scanner |
| command_injection | RCE в URI/body |
| http_binary_upload | серия бинарных POST на внешний хост |
| php_payload | `<?php` в ответе (`php_download`) или в загрузке (`webshell_upload`) |
| webshell_markers | маркеры шеллов PHP/ASP/JSP + семейства (WSO/b374k/c99/r57) |
| yara | YARA на carved_files (опционально) |

**`_http_body.py`** — общее для `command_injection`, `php_payload` и
`http_binary_upload`: распаковка gzip/deflate (в т.ч. по magic
`1f 8b` без `content-encoding`), критерий текстовости,
`body_for_scan()`. Лимит `http_body_max_decoded_bytes` = 8 МБ.

**Slow-режим beaconing (v1.4):** отдельный набор порогов
`beaconing_slow_*` (3 соединения, ≥ 3600 с, jitter < 0.15,
rate < 0.2/min) для C2 со sleep больше часа; в evidence пишется
`mode="slow"`. Плотный beacon по-прежнему идёт по fast-пути.

**`ja3s_malware` (v1.4):** `Config.ja3s_known_malware` по умолчанию
пуст — детектор молчит, пока пользователь не добавит проверенные
хеши; `flow.ja3s` при этом виден в flow-отчёте для ручного разбора.

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
правке менять в обоих местах (в TODO.md — вынос в `taxonomy.py`).

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

## Слой 5.5. Attack Graph (`analyzers/attack_graph.py`)

Directed graph атаки: узлы = IP, рёбра = findings с (src, dst),
пути = BFS от entry к impact. Падение сборки графа не валит прогон:
в отчёте остаётся пустой граф.

**Entry:** внутренние `victim_candidate` или external→internal
с initial_access.

**Impact:** `c2_candidate`/`attacker_candidate` или impact-phase.

**Pivot:** из `victim_makes_attack`.

**Multi-pcap** (`multi_pcap.py`): `merge_capture_states([s1, s2, …])`
— слияние N `CaptureState`. Вызывается из `run_multi_pipeline`
(append-only в `pipeline.py`, `run_pipeline` не тронут). Байты TCP
одного 5-tuple из разных файлов не склеиваются: коллизия считается
в `extractor_errors["multi_pcap_stream_conflict"]`.

## Слой 6. Reporters (`reporters/`)

**JSON** (`json_reporter.py`): `write_json` сортирует ключи —
детерминизм. Схема `schema_version = "0.3.0"`. Ключи: `provenance`,
`summary`, `entities`, `findings`, `contradictions`, `attack_graph`,
`timeline`, `flows`, `http`, `http_objects`, `carved_files`, `dns`,
`ndp`, `absence`, `ioc_files`.

**Markdown** (`markdown_reporter.py`): TL;DR в порядке kill-chain
(не confidence), PIVOT первым; секции TL;DR, таймлайн, carved,
сводка (в т.ч. `summary.protocols.by_l4`/`by_l7`), противоречия,
findings, сущности, HTTP, IOC, топ-10 flows.

**Flow report** (`flow_report.py`): conn.log-стиль
(`build_flow_report`, `build_dns_report`, `build_http_report`,
`build_http_object_report`) — вызывается внутри pipeline.

**IOC reporter** (`ioc_reporter.py`): `iocs.txt`, `iocs.csv`,
`iocs.json`, `suricata.rules` (SID 9000000+), `queries.txt`
(KQL + Splunk). Пишется из pipeline при `ioc_export_enabled`.

**HTML** (`html_reporter.py`, v1.5.0): самодостаточный файл со
встроенным CSS — сводка, протоколы, findings по severity,
противоречия с фактами, таймлайн, IOC; печать в PDF из браузера.
Все значения экранируются, evidence обрезается. CLI: `--html`.

**STIX** (`stix_reporter.py`, v1.5.0): STIX 2.1 bundle,
детерминированные UUIDv5, внешние IP из findings и домены;
внутренние IP не экспортируются. CLI: `--stix`.

JSON/Markdown/HTML/STIX пишутся из CLI или GUI: сам `run_pipeline`
возвращает dict, файлы на диск не кладёт (кроме IOC и carved).

## Выдержки тел (`payload_excerpt.py`, v1.5.0)

`command_injection`, `php_payload` и `webshell_markers` кладут в
`finding.evidence.payload_samples` выдержку тела, на котором
сработали. Схема записи: `direction`, `method`, `host`, `uri`,
`content_type`, `status_code`, `size`, `sha256`, `truncated`,
`is_text`, `text_b64`.

Тело берётся после снятия content-encoding — ровно то, что видел
детектор; лимит `payload_excerpt_bytes` (64 КБ). В base64 — чтобы
антивирус не ловил цельные сигнатуры шеллов в JSON-отчёте. GUI
декодирует выдержку в памяти (вкладка «Код инжекта» и окно
`Ctrl+Shift+P`), цепочка URL → Base64 → Gzip/Deflate.

## Плагины детекторов (`detector_plugins.py`, v1.5.0)

Каталог `~/.paradox/plugins/*.py` (`Config.plugins_dir`). Плагин
экспортирует `DETECTORS = [MyDetector()]` или `DETECTOR = MyDetector`.
Требования те же: `name: str` и `run(state, config) -> list[Finding]`.

Включается флагом `--plugins` или `Config(plugins_enabled=True)`;
по умолчанию выключено — это исполнение чужого Python-кода.
Ошибка загрузки или совпадение имени с встроенным детектором не
валят прогон: проблема попадает в `summary.extractor_errors`
(ключ `plugin`), упавший `run()` — под `detector:<name>`.

## Реестры

```python
EXTRACTORS = [FlowExtractor(), ..., NDPExtractor()]  # 12, flow первым
DETECTORS  = [...24...]                              # порядок не важен
RULES      = [...12...]                              # порядок не важен
```

Post-extract (не экстракторы): TCPReassembler,
HTTPObjectExtractor, TlsCertificateExtractor,
TLSExtractor.run_post_extract, carve_files — работают
на готовых потоках, вызываются из _extract.

Плагины: load_detector_plugins() — только при plugins_enabled.

### Расширение

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
(report_dict) -> ... + вызов из cli.py / GUI (внутри pipeline
пишутся только flow-отчёты и IOC).

Свой детектор без правки репозитория: .py в ~/.paradox/plugins
с DETECTORS/DETECTOR + Config(plugins_enabled=True).

Ключевой контракт: Finding

```python
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
```

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

9 вкладок: Прогон, История, Код инжекта, Обогащение, Настройки,
IPv6, Таймлайн, Экспорт, Сравнение. `views/roadmap_view.py`
существует, но к вкладкам не подключён (судьба — в TODO.md).

Настройки: 13 секций (Общие, Пороги, Детекторы, Противоречия,
Allowlist, DGA, Brute force, Сеть, Отчёты, Плагины, YARA,
Threat Intel, Производительность).

Workers (QThread): AnalysisWorker (принимает str | list[str],
отмена через requestInterruption), EnrichmentWorker,
QuickCheckWorker.

Диалоги: Attack Graph (с Time Machine + PNG/DOT/GraphML),
Graph связей, Contradiction, Finding, Carved files, Host story,
What-If.

Ключевое: GUI не модифицирует ядро. Отключение детекторов и
правил — параметры `detectors`/`rules` у run_pipeline
(v1.4: без monkey-patch глобальных DETECTORS/RULES, поэтому два
воркера не мешают друг другу).

i18n (v1.5.0): все пользовательские строки — через
`paradox_gui.i18n.tr()`; словари `_ru.py` и `_en.py` с плоскими
dot-ключами, fallback текущий → en → ru → сам ключ; язык
переключается в настройках (RU по умолчанию).
Множественное число/склонения не поддержаны: подстановка —
только `str.format`.

«Код инжекта» (v1.5.0): вкладка и отдельное окно без parent
(`Ctrl+Shift+P`). Показывают `evidence.payload_samples`, а не тела
из pcap. Предпросмотр — статический: санитизированная разметка по
белому списку тегов, без `script`/`style`/`iframe`/`form`/`img`,
ссылок и внешних запросов; серверный код шелла не исполняется.

Известные ограничения v1.5.1
Только то, что верно сейчас; план — в TODO.md.

TLS 1.3 Certificate зашифрован — правила на сертификатах
(sni_cert_mismatch, self_signed_cert, expired_cert) работают
только для TLS 1.2.

JA3 браузеров нет в config — ja3_ua_mismatch работает только на
tool/malware (в ja3_known_tools три инструмента, не браузеры).

ja3s_known_malware по умолчанию пуст — ja3s_malware молчит, пока
хеши не добавлены вручную.

Slow-режим beaconing требует минимум 3 соединений и ≥ 1 часа —
в коротком захвате медленный C2 не виден.

Внутренний C2 (internal→internal зашифрованный) вне зоны
видимости.

HTTP/2 не разбирается: http_object.py и _http_body.py работают с
HTTP/1.x; h2-фреймы и HPACK не поддержаны.

brotli и zstd не распаковываются (нужны внешние зависимости):
тела с таким сжатием не сканируются, поддержаны gzip/deflate.

Потоки сверх бюджета reassembly (200 МБ) помечаются truncated и
теряются; их число видно в summary.tcp_streams_truncated.

Плагины — произвольный Python с правами пользователя; по
умолчанию выключены (plugins_enabled=False).

IPv6 в ioc_reporter не покрыт тестами — тесты IOC только на
IPv4-адресах.

sni_mismatch шумит на CDN (73 FP на FIN-2015): нужен
context-aware allowlist.

tests/test_multi_pcap.py — ручной скрипт под skip, не pytest;
слияние покрыто tests/test_multi_pcap_merge.py (21 тест).

CI-workflow в репозитории нет: прогон тестов локальный.

История версий (архитектурно значимые)
См. CHANGELOG.md. Ключевые точки:

v0.4.0 — mass FP-чистка, port_scan, 5872 → 343 findings.

v0.6.0 — TCP reassembly, HTTPObject, FileCarve, JA3, enrichment.

v0.7.0 — ContradictionDetector, pivot, 12 правил.

v0.8.0 — Timeline / kill-chain, универсальный контракт Finding.

v0.9.0 — DNS-ответы, X.509, IPv6, DHCP/SSH/SMTP/NDP/YARA.

v1.0.0 — стабилизация, 925 тестов.

v1.1.0 — severity guards, evidence fallbacks, IPv6 IOC.

v1.2.0 — Attack Graph, Multi-pcap, Splash, Logo, Diff; 942 теста
в 110 файлах.

v1.4.0 — http_binary_upload, php_payload, распаковка HTTP-тел,
slow-beaconing, summary.protocols.by_l4/by_l7, детекторы и
правила параметром (без monkey-patch), keep-alive fix.

v1.5.0 — webshell_markers (24-й детектор), выдержки тел
payload_samples, html_reporter, stix_reporter, плагины детекторов,
RU/EN i18n, вкладка «Код инжекта».

Связанные документы
README.md — обзор, quick start, метрики.

MODULES.md — описание каждого файла: что делает, классы,
функции, связи.

CHANGELOG.md — история версий с деталями.

TODO.md — что дальше (единственный роадмап).
