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
Detectors (10) → Findings
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

**Формат:** `pcap_triage/pipeline.py:_extract()` — определяет
по первым 4 байтам.

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
Ошибки считаются в `state.extractor_errors[имя]`.

**Известное ограничение:** TLS ClientHello и Kerberos-сообщения
могут быть фрагментированы через несколько TCP-сегментов.
Полная сборка требует `StreamReassembler` — не реализован. Для
большинства триаж-задач хватает того, что помещается в первый
сегмент (первые 1460 байт).

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

### Реализованы (10)

| Детектор | Источник данных | Логика |
|---|---|---|
| `dga` | `dns_queries` | Энтропия label > порога, игнор дефисов, allowlist |
| `suspicious_port` | `flows` | Порт из списка, dst_ip внешний, агрегация по (dst_ip, dst_port) |
| `nxdomain_burst` | `dns_nxdomain_by_src` | Count > порога с одного IP |
| `cloud_tunnel` | `dns_queries` | Суффиксы trycloudflare/ngrok/serveo |
| `ip_check_service` | `dns_queries` | Точные домены (ip-api.com и т.п.) |
| `typosquatting` | `dns_queries` | Contains + Levenshtein к списку брендов |
| `sni_mismatch` | `flows.sni` × `dns_queries` | SNI не в DNS, allowlist по суффиксу |
| `brute_force` | `flows` | Много коротких flows к одной паре (src, dst_ip, dst_port) |
| `vulnerable_path` | `flows.http_uri` | Подстроки в URI (wp-login, .env, /.git) |
| `script_download` | `flows.http_uri` | Расширения .ps1/.sh/.vbs/.jar |

### Принципы

- **Пороги и списки — в `Config`.** Никаких магических чисел в коде.
- **Агрегация по сущности.** 474 соединения к одному серверу → один
  finding, а не 474.
- **Cross-layer detectors** — самые ценные (`sni_mismatch` читает
  и `dns_queries`, и `flows.sni`).

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
- `roles: list[str]` — см. ниже
- `first_seen`, `last_seen`
- `flows_out/in`, `bytes_out/in`
- `unique_dsts/srcs`
- `sni_domains`, `dns_names`
- `findings_indices` — ссылки на findings
- `mac`, `hostname`, `username`, `realm`
- `service_flows_in`, `service_unique_srcs` — для DC-детекта

### Роли

| Роль | Когда |
|---|---|
| `internal` / `external` | Всегда |
| `domain_controller` | Много flows на порты 88/389/445 от разных внутренних src |
| `attacker_candidate` | `attacker_tag` из findings (brute_force src, vulnerable_path src) |
| `victim_candidate` | `victim_tag` из findings (brute_force dst, script_download src) |
| `c2_candidate` | External с findings |
| `gateway_candidate` | Внутренний, много flows и уникальных dst, не DC и не attacker |

### Семантика тегов

Finding → IP → тег. Теги взаимоисключающие:
- `brute_force`: src → `attacker_tag`, dst → `victim_tag`
- `vulnerable_path`: src → `attacker_tag` (сканер), dst → `victim_tag` (цель)
- `script_download`: src → `victim_tag` (**инверсия**, жертва качает),
  dst → `attacker_tag`

## Слой 6. Reporters (`reporters/`)

Превращают findings + entities в артефакты.

### JSON (`json_reporter.py`)

Структурированный отчёт. Ключи:
- `schema_version` — для совместимости
- `provenance` — `tool_version`, `pcap_path`, `pcap_sha256`
- `summary` — пакеты, flows, findings, uploaded/downloaded
- `entities` — internal, external
- `findings` — список
- `flows` — top_by_bytes, top_by_packets
- `http` — методы, hosts, URIs, UA
- `dns` — top-by-count, nxdomain

**Детерминизм:** всё сортировано (`sort_keys=True`, полный вторичный
ключ в сортировках). Один pcap + config → побитово одинаковый JSON.

### Markdown (`markdown_reporter.py`)

Человекочитаемый отчёт. Секции:
- Header: файл, sha256, инструмент
- Сводка: пакеты, flows, направление трафика
- Сущности: internal (с MAC, hostname, username, realm)
- Findings: таблица
- HTTP: hosts, URIs, user-agents
- IOC: домены, IP, порты
- Топ-10 flows

Цель — копировать в тикет без ручной переработки.

### Flow report (`flow_report.py`)

conn.log-стиль: `src, src_port, dst_ip, dst_port, proto, bytes, packets,
duration, sni`. Для ручного пивота в Wireshark.

## Слой 7. Pipeline (`pipeline.py`)

Склейка слоёв. Функция `run_pipeline(pcap_path, config) -> dict`.

```python
def run_pipeline(pcap_path, config):
    state = CaptureState()
    _extract(pcap_path, state)         # PCAP → CaptureState
    findings = _detect(state, config)  # CaptureState → Findings
    entities = build_entities(...)     # Findings + State → Entities
    return {...}                       # → dict для reporters
```

## Реестры

В `pipeline.py`:

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
    SuspiciousPortDetector(),
    NXDOMAINBurstDetector(),
    CloudTunnelDetector(),
    IPCheckServiceDetector(),
    TyposquattingDetector(),
    SNIMismatchDetector(),
    BruteForceDetector(),
    VulnerablePathDetector(),
]
```

Порядок детекторов не важен — они независимы.

## Расширение

### Новый экстрактор

1. Файл `extractors/<name>.py`. Класс с атрибутами `name`, `layer`,
   методом `process(record, state)`.
2. Регистрация в `EXTRACTORS` в `pipeline.py`.
3. Тесты.

### Новый детектор

1. Файл `detectors/<name>.py`. Класс с атрибутом `name`, методом
   `run(state, config) -> list[Finding]`.
2. Регистрация в `DETECTORS`.
3. Тесты в `tests/test_detectors.py`.

### Новый reporter

1. Файл `reporters/<name>_reporter.py`.
2. Функция, принимающая `dict` от `run_pipeline`.
3. Вызов из `cli.py`.

## Известные долги

- **Timestamps в FlowStats** растут неограниченно. На 334 МБ — 106 МБ
  RAM, не критично, но Welford нужен для гигабайтных файлов.
- **FlowKey не нормализует направление** (SessionKey есть, но
  FlowStats не использует).
- **IPv6 не поддержан** в парсере (только заглушка `proto="other"`).
- **TCP reassembly отсутствует** — Kerberos и большие HTTP
  разбираются частично (только первый TCP-сегмент).
- **JA3/JA3S отсутствует.**
- **`nxdomain_burst` считает за весь файл** — должен быть по окну.
- **`brute_force` даёт false positive** на Google Safe Browsing
  (Firefox качает много разных URI с одного IP) и на LDAP-порт 389.
- **Threat Intel отсутствует** — нет VT/AbuseIPDB enrichment.
- **Correlator / Timeline отсутствуют** — нет сквозной хронологии
  инцидента.

## Порядок внедрения (что сделано)

1. Raw parser + 39x ускорение — **сделано**
2. Flow, DNS, TLS (SNI), HTTP экстракторы — **сделано**
3. 10 детекторов — **сделано**
4. Entities с ролями — **сделано**
5. HostIdentity (ARP), NBNS, Kerberos — **сделано**
6. JSON + Markdown отчёты — **сделано**
7. MTA-задание 5/5 — **сделано**

## Что дальше

- Threat Intel (VT + SQLite-кэш, rate limit).
- FlowAggregator + BeaconingDetector.
- Windowing в CaptureState.
- StreamReassembler (TCP reassembly).
- HTTPObjectExtractor + FileCarve.
- Correlator (entity scoring, timeline).
- Streamlit / FastAPI обёртка.