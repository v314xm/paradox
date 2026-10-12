# Архитектура pcap-triage

## Модель

Конвейер преобразований. Каждый слой решает одну задачу и передаёт
результат следующему. Слои не знают друг о друге, общаются через
структуры данных.

```
PCAP
  │
  ▼
RawPcapReader / PcapReader (по magic bytes)
  │
  ▼
parse_packet (struct) → PacketRecord
  │
  ▼
Extractors (Flow, DNS, TLS, HTTP, HostIdentity, NBNS, Kerberos)
  │
  ▼
CaptureState (flows, dns, host_identities)
  │
  ▼
Detectors (13) → Findings
  │
  ▼
build_entities → Entities (internal / external)
  │
  ▼
Reporters → JSON + Markdown
```

## Принципы

1. **Разделение extract / detect / aggregate / report.**
   Никакой слой не делает работу другого.

2. **Данные текут в одном направлении.**
   Никаких обратных связей, никакого общего мутабельного
   состояния между слоями.

3. **Каждый слой — реестр плагинов.**
   Новый экстрактор или детектор — это новый файл, а не правка
   существующего кода.

4. **Finding — на сущность, не на инцидент.**
   Один finding = одна логическая находка, а не одна строка
   на каждый flow или пакет.

5. **Пороги и списки — в `Config`.**
   Никаких магических чисел в коде детекторов.

6. **FP-фильтр важнее recall.**
   Инструмент для триажа — 100 findings из которых 80 ложных хуже,
   чем 20 findings из которых 5 ложных. После 0.4.0 приоритет
   смещён в сторону точности.

## Слой 1. Парсинг (`parsers.py`)

Собственный парсер пакетов через `struct.unpack`. Без scapy dissect.

**Почему не scapy:** на 334 МБ pcap профилирование показало, что
74% времени уходило на построение дерева слоёв scapy (`Packet.dissect`).
Мы используем 6-10 полей из каждого пакета, а scapy строит полную
объектную модель.

**Решение:** `parse_packet(raw_bytes, ts) -> PacketRecord`.

`PacketRecord` содержит:
- мета: `ts`, `length`, `raw` (сырые байты)
- L2: `eth_src`, `eth_dst`, `ethertype`, `vlan_id`
- L3: `src_ip`, `dst_ip`, `ip_proto`, `ip_id`, `ip_frag_offset`, `ip_mf`
- L4: `proto`, `src_port`, `dst_port`
- TCP: `tcp_seq`, `tcp_ack`, `tcp_flags`
- ARP: `arp_op`, `arp_sender_mac/ip`, `arp_target_mac/ip`
- `payload` (L4-payload, не парсится)

**Скорость:** ~25 МБ/с против 0.6 МБ/с через scapy. **39x**.

**Fallback:** если magic bytes не classic pcap (`D4 C3 B2 A1`) —
используется scapy `PcapReader` для pcapng. Медленнее, но читается.

## Слой 2. Экстракторы (`extractors/`)

Реестр независимых экстракторов. Единственное место, где живут
scapy (для сложных payload) и ручные парсеры.

**Порядок важен:** `FlowExtractor` идёт **первым**. Остальные
экстракторы, пишущие в `FlowStats`, ищут существующий flow по
`FlowKey` и **падают явно**, если его нет. Это ловит ошибку
порядка регистрации сразу.

### Реализованы (L0)

| Экстрактор | Источник | Что пишет |
|---|---|---|
| `flow.py` | IP/TCP/UDP заголовки | `state.flows[FlowKey] → FlowStats` |
| `dns.py` | UDP/53 payload | `state.dns_queries`, `dns_nxdomain_by_src` |
| `host_identity.py` | ARP | `state.host_identities[ip].mac` |
| `nbns.py` | UDP/137 | `state.host_identities[ip].hostnames` |
| `kerberos.py` | UDP/88, TCP/88 | `state.host_identities[ip].username/realm` |
| `tls.py` | TCP payload (ClientHello) | `flow.sni` |
| `http.py` | TCP payload (HTTP-запрос) | `flow.http_host/uri/method/ua` |

**Изоляция ошибок:** падение одного экстрактора не роняет проход.
Ошибки считаются в `state.extractor_errors[имя]`. Если в отчёте
видно большое число ошибок одного экстрактора — это баг регистрации
(например, детектор попал в `EXTRACTORS`), а не проблема данных.

**Известное ограничение:** TLS ClientHello и Kerberos-сообщения
могут быть фрагментированы через несколько TCP-сегментов.
Полная сборка требует `StreamReassembler` — не реализован.

## Слой 3. CaptureState (`models.py`)

Нормализованное представление захвата. Никакого scapy внутри.

```python
@dataclass
class CaptureState:
    # DNS
    dns_queries: Counter           # qname → count
    dns_nxdomain: Counter          # qname → count
    dns_nxdomain_by_src: Counter   # src_ip → count
    dns_queries_by_src: dict[str, Counter]

    # flows
    flows: dict[FlowKey, FlowStats]

    # identity
    host_identities: dict[str, HostIdentity]

    # meta
    packet_count: int
    first_ts: float | None
    last_ts: float | None
    extractor_errors: Counter
```

### FlowStats

Точка сборки контекста сессии:
- базовая телеметрия: `packets`, `bytes_sent`, `first_ts`, `last_ts`,
  `timestamps` (для будущего beaconing), `initiated_by_src`
- протокол-специфичные поля: `sni`, `ja3`, `http_host`, `http_uri`,
  `http_method`, `http_user_agent`

### FlowKey

Направленный 5-tuple. A→B и B→A — **разные ключи**.

### HostIdentity

Профиль хоста:
- `ip`
- `mac` (из ARP)
- `hostnames` (из NBNS / Kerberos cname с `$`)
- `username` (из Kerberos cname без `$`)
- `realm` (из Kerberos crealm, FQDN предпочтительнее)

## Слой 4. Детекторы (`detectors/`)

Чистые функции над `CaptureState`. Возвращают `list[Finding]`.
Никакого scapy.

### Контракт

```python
class LocalDetector(Protocol):
    name: str
    def run(self, state: CaptureState, config: Config) -> list[Finding]: ...
```

### Реализованы (13)

| Детектор | Источник данных | Логика |
|---|---|---|
| `dga` | `dns_queries` | Энтропия label > порога, игнор дефисов, allowlist |
| `suspicious_port` | `flows` | Порт из списка, dst_ip внешний, агрегация по (dst_ip, dst_port) |
| `port_scan` | `flows` | Один src → много dst на один dst_port, тонкие цели |
| `nxdomain_burst` | `dns_nxdomain_by_src` | Count > порога с одного IP |
| `cloud_tunnel` | `dns_queries` | Суффиксы trycloudflare/ngrok/serveo |
| `ip_check_service` | `dns_queries` + `flow.sni` + `flow.http_host` + `flow.dst_ip` | 4 источника матчинга, каноническое имя сервиса |
| `typosquatting` | `dns_queries` | SLD-only, contains + Levenshtein к списку брендов |
| `sni_mismatch` | `flows.sni` × `dns_queries` | SNI не в DNS, allowlist по суффиксу |
| `brute_force` | `flows` | HTTP: много коротких flows к одному (src, dst, port) |
| `ftp_brute_force` | `flows` | FTP: много flows с уникальными src_ports к (dst, 21) |
| `lateral_movement` | `flows` | Internal→internal на 445/135/139/3389/5985/5986 + UA/URI-маркеры |
| `large_transfer` | `flows` | Пара прямого+обратного flow > 100 МБ |
| `vulnerable_path` | `flows.http_uri` | Подстроки в URI + web_scanner агрегация |

### Cross-detector связи

Детекторы независимы, но три **фильтруют findings друг друга**:

- **`port_scan` → `suspicious_port`.** `SuspiciousPortDetector`
  собирает `scan_pairs: set[(src_ip, dst_port)]` — пары, где один
  src стучится к ≥ `port_scan_min_distinct_dsts` разным dst. Если
  все src в finding'е — сканеры на этом порту, finding пропускается.
- **`vulnerable_path` → `web_scanner`.** Для пар `(src_ip, dst_ip)`
  с ≥ `web_scanner_min_distinct_paths` разными URI генерируется
  один `web_scanner` finding вместо N individual.
- **`brute_force` → `ftp_brute_force`.** Взаимно исключающие:
  `brute_force` работает с avg_packets ≤ 20 (HTTP), `ftp_brute_force`
  — специально для FTP (пакеты на порядок больше).

Порядок регистрации в `DETECTORS` для фильтров не важен: каждый
детектор сам собирает нужные счётчики из `state.flows`, а не из
findings другого детектора.

### Таблица FP-фильтров (0.4.0 + 0.5.0)

| Фильтр | Значение | Что отсеивает |
|---|---|---|
| `port_scan_excluded_ports` | `{80, 443}` | Браузер = скан на веб-портах |
| `port_scan_max_flows_per_dst` | 3 | Браузер с параллельными соединениями |
| `port_scan_min_distinct_dsts` | 10 | Одиночные соединения |
| `web_scanner_min_distinct_paths` | 10 | Одиночные обращения к уязвимым путям |
| `brute_force_skip_tls_ports` | `{443, 8443}` | HTTPS-браузер к CDN |
| `brute_force_min_rate_flows_per_sec` | 0.01 | Поллинг (Safe Browsing) |
| `brute_force_max_avg_packets` | 20 | FTP-сессии (см. `ftp_brute_force`) |
| `ftp_brute_force_min_flows` | 20 | Редкие FTP-подключения |
| `ftp_brute_force_min_unique_src_ports` | 20 | Переиспользование сокетов |
| `lateral_movement_min_flows_port_only` | 5 | Одиночный RDP/WinRM к jump-host |
| `large_transfer_min_bytes` | 100 MB | Обычные сессии |
| `typosquatting_levenshtein_threshold` | 2 | Разные слова (behance/binance) |
| `dga_entropy_threshold` | 3.5 | Человекочитаемые домены |

### Confidence для новых детекторов (0.5.0)

- `lateral_movement`: 0.8 при UA/URI, 0.6 при «только порт»
- `large_transfer`: 0.85
- `ftp_brute_force`: 0.75 / 0.85 / 0.95 по объёму (20 / 50 / 100 flows)
- `ip_check_service`: 0.7

## Слой 5. Агрегаторы (`aggregators/`)

Превращают flow'ы и findings в сущности (хосты). Вместо 500 строк
flows — 20-50 сущностей с ролями.

### `entities.py`

```python
def build_entities(state, findings, config) -> Entities
```

Возвращает `Entities(internal=[Entity], external=[Entity])`.

### Entity

Один IP. Содержит:
- `ip`, `is_internal`
- `roles: list[str]`
- `first_seen`, `last_seen`
- `flows_out/in`, `bytes_out/in`
- `unique_dsts/srcs`
- `sni_domains`, `dns_names`
- `findings_indices`
- `mac`, `hostname`, `username`, `realm`
- `service_flows_in`, `service_unique_srcs`

### Роли

| Роль | Когда |
|---|---|
| `internal` / `external` | Всегда |
| `domain_controller` | Много flows на порты 88/389/445 от разных внутренних src |
| `attacker_candidate` | `attacker_tag` из findings |
| `victim_candidate` | `victim_tag` из findings |
| `c2_candidate` | External с findings |
| `gateway_candidate` | Внутренний, много flows и уникальных dst |

### Семантика тегов

Finding → IP → тег. Теги взаимоисключающие:

| Finding | src → tag | dst → tag |
|---|---|---|
| `brute_force` | `attacker_tag` | `victim_tag` |
| `ftp_brute_force` | `attacker_tag` | `victim_tag` |
| `vulnerable_path` | `attacker_tag` | `victim_tag` |
| `web_scanner` | `attacker_tag` | `victim_tag` |
| `port_scan` | `attacker_tag` | (не выделяется) |
| `lateral_movement` | `attacker_tag` | `victim_tag` |
| `script_download` | `victim_tag` (**инверсия**) | `attacker_tag` |

## Слой 6. Reporters (`reporters/`)

Превращают findings + entities в артефакты.

### JSON (`json_reporter.py`)

Структурированный отчёт. Ключи:
- `schema_version`
- `provenance` — `tool_version`, `pcap_path`, `pcap_sha256`
- `summary` — пакеты, flows, findings, uploaded/downloaded
- `entities` — internal, external
- `findings` — список
- `flows` — top_by_bytes, top_by_packets
- `http` — методы, hosts, URIs, UA
- `dns` — top-by-count, nxdomain

**Детерминизм:** всё сортировано. Один pcap + config → побитово
одинаковый JSON.

### Markdown (`markdown_reporter.py`)

Человекочитаемый отчёт. Секции:
- Header: файл, sha256, инструмент
- Сводка: пакеты, flows, направление трафика
- Сущности: internal (с MAC, hostname, username, realm)
- Findings: таблица
- HTTP: hosts, URIs, user-agents
- IOC: домены, IP, порты
- Топ-10 flows

### Flow report (`flow_report.py`)

conn.log-стиль: `src, src_port, dst_ip, dst_port, proto, bytes, packets,
duration, sni`.

## Слой 7. Pipeline (`pipeline.py`)

```python
def run_pipeline(pcap_path, config):
    state = CaptureState()
    _extract(pcap_path, state)
    findings = _detect(state, config)
    entities = build_entities(...)
    return {...}
```

## Реестры

```python
EXTRACTORS = [
    FlowExtractor(),           # ДОЛЖЕН быть первым
    DNSExtractor(),
    TLSExtractor(),
    HTTPExtractor(),
    HostIdentityExtractor(),
    NBNSExtractor(),
    KerberosExtractor(),
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
    BruteForceDetector(),
    FTPBruteForceDetector(),
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
]
```

**Известная ошибка:** если случайно поместить детектор в `EXTRACTORS`,
он будет вызываться per-packet с сигнатурой `process(record, state)`,
которой у него нет. Исключение поймается в `_extract`, но
`state.extractor_errors[name]` будет равен числу пакетов. Признак —
аномально большое число ошибок одного "экстрактора" в summary.

## Расширение

### Новый экстрактор

1. Файл `extractors/<name>.py`. Класс с атрибутами `name`, `layer`,
   методом `process(record, state)`.
2. Регистрация в `EXTRACTORS`.
3. Тесты.

### Новый детектор

1. Файл `detectors/<name>.py`. Класс с атрибутом `name`, методом
   `run(state, config) -> list[Finding]`.
2. Регистрация в `DETECTORS`.
3. Тесты в `tests/test_detectors.py`. FP-регрессия —
   в `tests/test_regressions.py`.

### Новый reporter

1. Файл `reporters/<name>_reporter.py`.
2. Функция, принимающая `dict` от `run_pipeline`.
3. Вызов из `cli.py`.

## Известные долги

- **Timestamps в FlowStats** растут неограниченно. На 334 МБ — 106 МБ
  RAM, не критично, но Welford нужен для гигабайтных файлов.
- **FlowKey не нормализует направление** (SessionKey есть, но
  FlowStats не использует).
- **IPv6 не поддержан** в парсере.
- **TCP reassembly отсутствует** — Kerberos и большие HTTP
  разбираются частично (только первый TCP-сегмент).
- **JA3/JA3S отсутствует.**
- **`nxdomain_burst` считает за весь файл** — должен быть по окну.
  93 findings на FIN-2015, часть могут быть FP от distributed
  resolvers.
- **`sni_without_dns` может давать FP** на CDN, где DNS-запрос был
  в другом файле захвата. 73 findings на FIN-2015.
- **Двухуровневые TLD** (co.uk, com.au) не поддержаны в SLD-извлечении
  `typosquatting`. Решение — public suffix list.
- **Внутренний C2** (`internal → internal` зашифрованный POST)
  не детектируется. Требует HTTPObjectExtractor + эвристики
  beaconing. Видно на CyberCampTask: 10.0.1.247 принял
  зашифрованный PNG от `watch_movie.ps1`.
- **HTTPObjectExtractor отсутствует** — тело HTTP запросов и
  ответов не разбирается. Блокирует FileCarve, экспорт файлов,
  анализ POST body.
- **Threat Intel отсутствует** — нет VT/AbuseIPDB enrichment.
- **Correlator / Timeline отсутствуют** — нет сквозной хронологии
  инцидента.

## История версий (архитектурно значимые)

### 0.1.x
- Raw parser + 39x ускорение.
- Flow, DNS экстракторы.
- 6 детекторов.

### 0.2.x
- TLS, HTTP экстракторы.
- SNI mismatch, brute_force, vulnerable_path.
- Entities с ролями.

### 0.3.x
- HostIdentity (ARP), NBNS, Kerberos.
- MTA-задание 5/5.

### 0.4.0
- **PortScanDetector** — 11-й детектор.
- **Typosquatting SLD-only** — переписан.
- **VulnerablePathDetector** — агрегация + web_scanner.
- **BruteForceDetector** — TLS/login-hint фильтры.
- Массовая FP-чистка. 5872 → 343 findings на FIN-2015.
- 127 тестов.

### 0.5.0
- **LateralMovementDetector** — WinRM/PsExec/SMB/RDP между
  внутренними хостами.
- **LargeTransferDetector** — пары flow > 100 МБ.
- **FTPBruteForceDetector** — отдельно от HTTP-brute_force.
- **IPCheckServiceDetector расширен** — 4 источника матчинга
  (DNS+SNI+HTTP Host+direct IP), канонические имена сервисов.
- 13 детекторов.
- **CyberCampTask: 6 findings, 0 FP** — покрыто 4 из 5 гэпов
  ручного анализа.
- 145 тестов.

## Что дальше

- HTTPObjectExtractor + FileCarve (для внутреннего C2).
- Threat Intel (VT + SQLite-кэш, rate limit).
- FlowAggregator + BeaconingDetector.
- Windowing в CaptureState (fix nxdomain_burst).
- StreamReassembler (TCP reassembly).
- Correlator (entity scoring, timeline).
- Streamlit / FastAPI обёртка.