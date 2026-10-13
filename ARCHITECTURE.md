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
Extractors (Flow, DNS, TLS, HTTP, HostIdentity, ARPMacHistory,
NBNS, Kerberos) + TCPReassembler
│
▼
CaptureState (flows, dns, host_identities, arp_macs, tcp_streams,
http_objects, carved_files)
│
▼
Detectors (17) → Findings
│
▼
ContradictionDetector
├── Fact extraction (facts.py)
├── ContradictionRules (7 правил)
└── Contradictions
│
▼
build_entities → Entities (internal / external, роли + pivot)
│
▼
Reporters → JSON + Markdown
```


## Принципы

1. **Разделение extract / detect / contradict / aggregate / report.**
   Никакой слой не делает работу другого.

2. **Данные текут в одном направлении.**
   Никаких обратных связей, никакого общего мутабельного
   состояния между слоями.

3. **Каждый слой — реестр плагинов.**
   Новый экстрактор, детектор или правило contradictions — это
   новый файл, а не правка существующего кода.

4. **Finding — на сущность, не на инцидент.**
   Один finding = одна логическая находка, а не строка на каждый
   flow или пакет.

5. **Contradiction — надстройка над findings.**
   Правила contradictions не находят атаки — они ищут
   несогласованности между слоями данных (DNS vs SNI, MAC vs IP,
   роли vs поведение). Не дублируют детекторы.

6. **Пороги и списки — в `Config`.**
   Никаких магических чисел в коде детекторов и правил.

7. **FP-фильтр важнее recall.**
   100 findings из которых 80 ложных хуже, чем 20 findings из
   которых 5 ложных. Приоритет — точность.

8. **Оффлайн-режим.**
   Никаких внешних API на пути основного прогона. Enrichment —
   отдельный слой, по флагу `--enrich`.

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
используется scapy `PcapReader` для pcapng.

## Слой 2. Экстракторы (`extractors/`)

Реестр независимых экстракторов. Единственное место, где живут
scapy (для сложных payload) и ручные парсеры.

**Порядок важен:** `FlowExtractor` идёт **первым**. Остальные
экстракторы, пишущие в `FlowStats`, ищут существующий flow по
`FlowKey` и **падают явно**, если его нет.

### Реализованы (8)

| Экстрактор | Источник | Что пишет |
|---|---|---|
| `flow.py` | IP/TCP/UDP заголовки | `state.flows[FlowKey] → FlowStats` |
| `dns.py` | UDP/53 payload | `state.dns_queries`, `dns_nxdomain_by_src` |
| `host_identity.py` | ARP | `state.host_identities[ip].mac`, `mac_history` |
| `arp_history.py` | ARP | `state.arp_macs[ip][mac] = [first, last, count]` |
| `nbns.py` | UDP/137 | `state.host_identities[ip].hostnames` |
| `kerberos.py` | UDP/88, TCP/88 | `state.host_identities[ip].username/realm` |
| `tls.py` | TCP payload (ClientHello) | `flow.sni`, `flow.ja3`, `flow.ja3s`, `state.session_sni` |
| `http.py` | TCP payload (HTTP-запрос) | `flow.http_host/uri/method/ua` |

**Почему два ARP-экстрактора:**
- `host_identity.py` — последний MAC на IP, для отчёта сущностей.
- `arp_history.py` — **полная** история MAC на IP, для правила
  `mac_ip_conflict`. Финальное значение не покажет ARP-spoof:
  если хост отвечал двумя MAC, `host_identities.mac` сохранит
  только последний.

### Post-extract (после чтения всех пакетов)

- **`reassembler.py`** — `TCPReassembler`, склейка TCP-сегментов
  по sequence numbers с обработкой out-of-order и retransmit.
  Лимиты: 1 МБ per-flow, 200 МБ total. Заполняет
  `state.tcp_streams`.
- **`http_object.py`** — `HTTPObjectExtractor`. Из `tcp_streams`
  собирает полные HTTP запросы/ответы (Content-Length, chunked).
  Заполняет `state.http_objects`. Двухпроходный парсинг: pass 1 —
  requests (собираем URI), pass 2 — responses (URI пробрасывается
  из парного request по нормализованному pair-key).
- **`file_carve.py`** — метаданные payload'ов (sha256, размер,
  MIME, первые 64 байта). Тело **не пишется** на диск по умолчанию.
  Флаг `file_carve_write_body` позволяет сохранить как
  `<sha256>.bin`.

**Изоляция ошибок:** падение одного экстрактора не роняет проход.
Ошибки считаются в `state.extractor_errors[имя]`.

## Слой 3. CaptureState (`models.py`)

Нормализованное представление захвата. Никакого scapy внутри.

```python
@dataclass
class CaptureState:
    # DNS
    dns_queries: Counter
    dns_nxdomain: Counter
    dns_nxdomain_by_src: Counter
    dns_queries_by_src: dict[str, Counter]

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

    # meta
    packet_count: int
    first_ts: float | None
    last_ts: float | None
    extractor_errors: Counter

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
используется scapy `PcapReader` для pcapng.

## Слой 2. Экстракторы (`extractors/`)

Реестр независимых экстракторов. Единственное место, где живут
scapy (для сложных payload) и ручные парсеры.

**Порядок важен:** `FlowExtractor` идёт **первым**. Остальные
экстракторы, пишущие в `FlowStats`, ищут существующий flow по
`FlowKey` и **падают явно**, если его нет.

### Реализованы (7)

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
(например, детектор попал в `EXTRACTORS`).

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
    dns_nxdomain: Counter
    dns_nxdomain_by_src: Counter
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

базовая телеметрия: packets, bytes_sent, first_ts, last_ts,
timestamps, initiated_by_src

протокол-специфичные поля: sni, http_host, http_uri,
http_method, http_user_agent, ja3, ja3s

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

### Реализованы (15)

| Детектор | Источник данных | Логика |
|---|---|---|
| `dga` | `dns_queries` | Энтропия label > порога, игнор дефисов, allowlist |
| `suspicious_port` | `flows` | Порт из списка, dst_ip внешний, агрегация по (dst_ip, dst_port) |
| `port_scan` | `flows` | Один src → много dst на один dst_port, тонкие цели |
| `nxdomain_burst` | `dns_nxdomain_by_src` | Count > порога с одного IP |
| `cloud_tunnel` | `dns_queries` | Суффиксы trycloudflare/ngrok/serveo |
| `ip_check_service` | `dns_queries` + `flow.sni` + `flow.http_host` + `flow.dst_ip` | 4 источника, каноническое имя сервиса |
| `typosquatting` | `dns_queries` | SLD-only, contains + Levenshtein |
| `sni_mismatch` | `flows.sni` × `dns_queries` | SNI не в DNS, allowlist по суффиксу |
| `brute_force` | `flows` | HTTP: много коротких flows к одной (src, dst, port) |
| `ftp_brute_force` | `flows` | FTP: много flows с уникальными src_ports к (dst, 21) |
| `beaconing` | `flows.timestamps` | Периодичность (jitter < 0.2) |
| `dns_tunneling` | `dns_queries_by_src` | Длинные уникальные поддомены под одним base |
| `lateral_movement` | `flows` | Internal→internal на 445/135/139/3389/5985/5986 + UA/URI-маркеры |
| `large_transfer` | `flows` | Пара прямого+обратного > 100 МБ (с exclude) |
| `vulnerable_path` | `flows.http_uri` | Подстроки в URI + web_scanner агрегация |
command_injection	http_objects + flows	RCE в URI и POST body (io.popen, system(), subprocess…)
ja3_malware	flows.ja3	TLS-фреймворки C2 из config.ja3_known_malware

### Cross-detector связи

Детекторы независимы, но **фильтруют findings друг друга**:

- **`port_scan` → `suspicious_port`.** SuspiciousPortDetector
  собирает `scan_pairs: set[(src_ip, dst_port)]` — пары, где один
  src стучится к ≥ 10 разным dst. Если все src в finding'е —
  сканеры на этом порту, finding пропускается.
- **`vulnerable_path` → `web_scanner`.** Для пар `(src_ip, dst_ip)`
  с ≥ 10 разными URI генерируется один `web_scanner` finding
  вместо N individual.
- **`ftp_brute_force` ↔ `brute_force`.** Взаимно исключающие:
  `brute_force` пропускает port 21 (обрабатывает FTPBruteForceDetector),
  `ftp_brute_force` работает только на port 21.
- **`beaconing` × `large_transfer`.** Beaconing требует малый размер
  flow (< 5 КБ), large_transfer — большой (> 100 МБ). Не пересекаются.

Порядок регистрации в `DETECTORS` не важен: каждый детектор сам
собирает счётчики из `state.flows`.
Детекторы независимы, но фильтруют findings друг друга:

port_scan → suspicious_port. SuspiciousPortDetector
собирает scan_pairs — пары, где один src стучится к ≥ 10
разным dst. Сканы не дублируются как suspicious_port.

vulnerable_path → web_scanner. Для пар (src_ip, dst_ip)
с ≥ 10 разными URI генерируется один web_scanner вместо N.

ftp_brute_force ↔ brute_force. Взаимно исключающие:
brute_force пропускает port 21, ftp_brute_force работает
только на 21.

command_injection — агрегация. ≥ 5 hit'ов с одного
(src_ip, dst_ip) → один finding с count вместо N individual.

large_transfer direction. Detector заполняет
evidence.direction (inbound/outbound/internal/external)
и evidence.bytes_in/bytes_out, а также mitre_techniques
на инстансе (T1041/T1105/T1071.001).


### Таблица FP-фильтров

| Фильтр | Значение | Что отсеивает |
|---|---|---|
| `port_scan_excluded_ports` | `{80, 443}` | Браузер = скан на веб-портах |
| `port_scan_max_flows_per_dst` | 3 | Браузер с параллельными соединениями |
| `port_scan_min_distinct_dsts` | 10 | Одиночные соединения |
| `web_scanner_min_distinct_paths` | 10 | Одиночные обращения к уязвимым путям |
| `brute_force_skip_tls_ports` | `{443, 8443}` | HTTPS-браузер к CDN |
| `brute_force_min_rate_flows_per_sec` | 0.01 | Поллинг (Safe Browsing) |
| `brute_force_max_avg_packets` | 20 | FTP-сессии |
| `ftp_brute_force_min_flows` | 20 | Редкие FTP-подключения |
| `beaconing_min_connections` | 10 | Единичные обращения |
| `beaconing_max_jitter_ratio` | 0.2 | Нерегулярный трафик |
| `beaconing_max_avg_bytes` | 5000 | Загрузки, а не heartbeat |
| `dns_tunneling_min_qname_length` | 50 | DGA-поддомены |
| `dns_tunneling_min_long_qnames` | 20 | Единичные длинные запросы |
| `dns_tunneling_min_queries` | 50 | Редкие запросы |
| `lateral_movement_min_flows_port_only` | 5 | Одиночный RDP к jump-host |
| `large_transfer_min_bytes` | 100 MB | Обычные сессии |
| `large_transfer_excluded_hosts` | 7 доменов | Windows Update, Apple CDN |
| `typosquatting_levenshtein_threshold` | 2 | Разные слова |
| `dga_entropy_threshold` | 3.5 | Человекочитаемые домены |

### Confidence для новых детекторов (0.5.0–0.6.0)

- `lateral_movement`: 0.8 при UA/URI, 0.6 при «только порт»
- `large_transfer`: 0.85
- `ftp_brute_force`: 0.75 / 0.85 / 0.95 по объёму (20 / 50 / 100 flows)
- `beaconing`: 0.6–0.85 линейно по jitter (0.2 → 0.05)
- `dns_tunneling`: 0.7 / 0.9 по количеству длинных qname
- `ip_check_service`: 0.7

## Слой 5. Агрегаторы (`aggregators/`)

Превращают flow'ы и findings в сущности (хосты).

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
| `beaconing` | `victim_tag` (жертва отстукивает) | `attacker_tag` |
| `script_download` | `victim_tag` (инверсия) | `attacker_tag` |

## Слой 6. Reporters (`reporters/`)

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

conn.log-стиль: `src, src_port, dst_ip, dst_port, proto, bytes,
packets, duration, sni`.

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
    BeaconingDetector(),
    DNSTunnelingDetector(),
    LateralMovementDetector(),
    LargeTransferDetector(),
    VulnerablePathDetector(),
]
```

**Известная ошибка:** если случайно поместить детектор в `EXTRACTORS`
или задублировать его в `DETECTORS` — получишь либо ошибки
per-packet, либо дубликаты findings. Проверяй список после правок.

## Расширение

### Новый экстрактор

1. Файл `extractors/<name>.py`. Класс с атрибутами `name`, `layer`,
   методом `process(record, state)`.
2. Регистрация в `EXTRACTORS`.
3. Тесты.

### Новый детектор

1. Файл `detectors/<name>.py`. Класс с атрибутом `name`, методом
   `run(state, config) -> list[Finding]`.
2. Регистрация в `DETECTORS` (не забыть `import`).
3. Тесты — желательно в отдельном файле `tests/test_<name>.py`.

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
  разбираются частично.
- **JA3/JA3S отсутствует.**
- **`nxdomain_burst` считает за весь файл** — должен быть по окну.
- **`sni_without_dns` может давать FP** на CDN, где DNS-запрос был
  в другом файле захвата.
- **Двухуровневые TLD** (co.uk, com.au) не поддержаны в SLD.
- **Внутренний C2** (internal → internal зашифрованный) не
  детектируется. Требует HTTPObjectExtractor.
- **`beaconing` чувствителен к jitter** — реальные C2 с jitter > 0.2
  не ловятся. Требует windowing.
- **HTTPObjectExtractor отсутствует** — тело HTTP запросов и
  ответов не разбирается.
- **Threat Intel отсутствует** — нет VT/AbuseIPDB enrichment.
- **Correlator / Timeline отсутствуют** — нет сквозной хронологии.

## История версий (архитектурно значимые)

### 0.1.x
- Raw parser + 39x ускорение.
- Flow, DNS экстракторы. 6 детекторов.

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
- Массовая FP-чистка. 5872 → 343 findings.

### 0.5.x
- **LateralMovementDetector** — WinRM/PsExec/SMB/RDP между
  внутренними хостами.
- **LargeTransferDetector** — пары flow > 100 МБ.
- **FTPBruteForceDetector** — отдельно от HTTP-brute_force.
- **IPCheckServiceDetector расширен** — 4 источника матчинга.
- **LargeTransfer exclude** — Windows Update, Apple CDN.
- 13 детекторов. CyberCampTask: 6 findings, 0 FP.

### 0.6.0
- **BeaconingDetector** — периодические C2 heartbeat.
- **DNSTunnelingDetector** — длинные уникальные поддомены.
- 15 детекторов, 165 тестов.

## Что дальше

- HTTPObjectExtractor + FileCarve (для внутреннего C2).
- ObfuscationDetector, WebShellDetector — на HTTP body.
- Threat Intel enrichment (VT + AbuseIPDB + Shodan + SQLite-кэш).
- FlowAggregator + Windowing (для медленных beaconing).
- StreamReassembler (TCP reassembly).
- Correlator (entity scoring, timeline).
- MITRE-маппинг + STIX 2.1 экспорт.
- REST API + Web UI.
- SMB2/DHCP/SSH/SMTP экстракторы, TLS cert parser + JA3.
- IPv6 поддержка.


Слой 4.5. ContradictionDetector (contradictions/)
Новый слой в 0.7.0. Ищет не атаки, а несогласованности
между источниками данных: одно утверждение о мире подтверждается
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
    value: str           # зависит от predicate; может быть "" для ролевых фактов
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
pcap_triage/contradictions/
├── __init__.py
├── base.py              # Fact, Contradiction, ContradictionRule, SEVERITY_WEIGHT
├── facts.py             # extract_*_facts для каждого типа источника
├── registry.py          # RULES, run_all()
└── rules/
    ├── b_mac_ip_conflict.py
    ├── c_sni_host_mismatch.py
    ├── d_ja3_ua_mismatch.py
    ├── e_victim_makes_attack.py
    ├── e_reverse_asymmetry.py
    ├── f_port_service_mismatch.py
    └── g_direct_ip_no_dns.py
Функции извлечения фактов (facts.py)
Функция	Что генерирует
extract_attack_facts(findings)	victim_of / attacker_of из findings
extract_arp_facts(state)	has_mac из state.arp_macs
extract_tls_host_facts(state, config)	sni / http_host из flows
extract_ja3_ua_facts(state, config)	uses_ja3 / uses_ua из flows
extract_asymmetry_facts(state, config)	session_asymmetry по сессиям
extract_protocol_on_port_facts(state, config)	protocol_on_port (tls/http)
extract_direct_ip_facts(state, config)	direct_ip_connect + makes_dns_queries
7 правил
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
victim_makes_attack: одна Contradiction на subject. Из N фактов
выбирается самый уверенный, при равенстве — тот, у которого
непустой value (роль с адресатом важнее роли без него).

reverse_asymmetry: одна Contradiction на subject. Если сессий
≥ 5 (bulk-паттерн), severity понижается до low, conf × 0.7.
Это фикс FP на шлюзах/NAT — CyberCampTask 192.168.1.1 давал
9 «эксфильтраций» без агрегации.

Слой 5. Агрегаторы (aggregators/)
Превращают flow'ы и findings в сущности (хосты).

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
pivot	Правило victim_makes_attack сработало на IP
Роль pivot
Ставится поверх victim_candidate, если для IP есть contradiction
с rule == "victim_makes_attack". Не заменяет роль, а дополняет:

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
large_transfer	—	—
suspicious_port	victim_tag	attacker_tag
large_transfer не помечает роли. Статистический сигнал —
не роль: шлюз, качающий 2 ГБ обновлений, не victim. Роль
определяется через gateway_candidate или не ставится.

Слой 6. Reporters (reporters/)
JSON (json_reporter.py)
Структурированный отчёт. Ключи:

schema_version — 0.3.0 (добавлен contradictions)

provenance — tool_version, pcap_path, pcap_sha256

summary — пакеты, flows, findings, contradictions,
uploaded/downloaded

entities — internal, external

findings — список с mitre_techniques

contradictions — список (rule, subject, severity, confidence,
priority, likely_causes, resolution_hint, facts)

flows — top_by_bytes, top_by_packets

http — методы, hosts, URIs, UA

dns — top-by-count, nxdomain

http_objects, carved_files

Детерминизм: всё сортировано. Один pcap + config → побитово
одинаковый JSON.

Markdown (markdown_reporter.py)
Секции:

Header: файл, sha256, инструмент

TL;DR — цепочка findings в порядке kill-chain
(_CHAIN_ORDER), PIVOT выделяется первым

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

Kill-chain ordering
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
    ...
    "lateral_movement": 100,
    "large_transfer":   110,
}
TL;DR строится через _chain_for(findings) — уникальные типы
в порядке цепочки, не в порядке confidence.

Flow report (flow_report.py)
conn.log-стиль: src, src_port, dst_ip, dst_port, proto, bytes, packets, duration, sni.

Слой 7. Pipeline (pipeline.py)
python
def run_pipeline(pcap_path, config):
    state = CaptureState()
    _extract(pcap_path, state, config)
    findings = _detect(state, config)
    contradictions = run_contradictions(state, findings, config)
    entities = build_entities(
        state, findings, config, contradictions=contradictions,
    )
    return {
        "schema_version": "0.3.0",
        "provenance": {...},
        "summary": {...},
        "entities": {...},
        "findings": [...],
        "contradictions": [...],
        ...
    }
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
]
Известная ошибка: если случайно поместить детектор в EXTRACTORS
или задублировать в DETECTORS — получишь либо ошибки per-packet,
либо дубликаты findings. Проверяй список после правок.

Расширение
Новый экстрактор
Файл extractors/<name>.py. Класс с name, layer,
методом process(record, state).

Регистрация в EXTRACTORS.

Тесты.

Новый детектор
Файл detectors/<name>.py. Класс с name, методом
run(state, config) -> list[Finding].

Универсальные поля в evidence: src_ip, dst_ip, dst_port.

Регистрация в DETECTORS.

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

Вызов из cli.py.

Известные долги (0.7.0)
Timestamps в FlowStats растут неограниченно. На 334 МБ —
106 МБ RAM, не критично, но Welford нужен для гигабайтных файлов.

DNS-ответы (A/AAAA/CNAME) не парсятся. Только запросы.
Блокирует точный direct_ip_no_dns и часть правил категории A.

TLS-сертификаты (CN, SAN) не парсятся. Блокирует
cert_cn_sni_mismatch, self_signed_on_external.

JA3-хеши браузеров не в config. Все неизвестные →
family=normal. Правило ja3_ua_mismatch ловит только tool/malware.

IPv6 не поддержан в парсере.

nxdomain_burst считает за весь файл — не по окну. 93
findings на FIN-2015, часть могут быть FP.

sni_without_dns — 73 findings на FIN-2015, CDN без DNS.

beaconing чувствителен к jitter — реальные C2 с jitter > 0.1
не ловятся. Требует windowing.

Двухуровневые TLD (co.uk, com.au) не поддержаны в SLD.

Внутренний C2 (internal → internal зашифрованный) не
детектируется без HTTP/2 framing.

Timeline / kill-chain отсутствуют — contradictions дают
точки, но не цепочки.

Универсальный контракт Finding не зафиксирован — часть
полей остаётся в evidence со своими именами.

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

MTA-задание 5/5.

0.4.0
PortScanDetector — 11-й детектор.

Typosquatting SLD-only — переписан.

VulnerablePathDetector — агрегация + web_scanner.

Массовая FP-чистка. 5872 → 343 findings.

0.5.x
LateralMovementDetector, LargeTransferDetector,
FTPBruteForceDetector.

IPCheckServiceDetector расширен — 4 источника матчинга.

LargeTransfer exclude — Windows Update, Apple CDN.

13 детекторов. CyberCampTask: 6 findings, 0 FP.

0.6.0
TCP Reassembly — TCPReassembler + state.tcp_streams.

HTTPObjectExtractor — полные HTTP-запросы/ответы.

FileCarve — метаданные payload'ов.

JA3/JA3S fingerprinting — из TLS ClientHello/ServerHello.

CommandInjectionDetector — RCE в URI и body.

BeaconingDetector — периодические heartbeat (multi-tenant
filter, allowlist, rate check).

DNSTunnelingDetector — длинные уникальные поддомены.

Enrichment (--enrich) — Shodan InternetDB, AbuseIPDB,
SQLite-кэш.

17 детекторов, 244 теста.

0.7.0
ContradictionDetector — новый слой анализа.

pcap_triage/contradictions/ — base, facts, registry, rules.

7 правил: victim_makes_attack, mac_ip_conflict,
sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry,
port_service_mismatch, direct_ip_no_dns.

Факты: attack, arp, tls_host, ja3_ua, asymmetry,
protocol_on_port, direct_ip.

Роль pivot в entities (поверх victim_candidate).

Секция «Противоречия» в markdown_reporter + TL;DR с PIVOT.

ARPMacHistoryExtractor — история MAC на IP для mac_ip_conflict.

LargeTransfer direction — inbound/outbound/internal/external

bytes_in/bytes_out + instance-level mitre_techniques.

TL;DR в порядке kill-chain — _CHAIN_ORDER + _chain_for().

_fmt_host — IP-литералы в HTTP Host помечаются как
(unknown host).

CLI -o корректно работает с директориями.

Схема JSON: 0.2.0 → 0.3.0 (top-level contradictions).

302 теста. FIN-2015: 386 findings, 11 contradictions.
CyberCampTask: 7 findings, 2 contradictions.

Что дальше
0.8.0 — расширение видимости:

DNS-ответы (A/AAAA/CNAME) — оживит sni_host_mismatch через
DNS, точный direct_ip_no_dns, sni_dns_different_ip.

TLS-сертификаты (CN, SAN) — cert_cn_sni_mismatch,
self_signed_on_external.

Универсальный контракт Finding — top-level поля.

Timeline / kill-chain reconstruction.

0.9.0 — новые экстракторы:

SMB2, DHCP, SSH-баннер.

HTTP/2 framing (HPACK для headers).

IPv6 в парсере.

1.0.0 — стабильный API:

STIX 2.1 экспорт IOC.

REST API + Web UI.

Плагины (пользовательские правила contradictions).

text

---

Файл готов к вставке. Замени содержимое `ARCHITECTURE.md` целиком. Ключевые добавления:

- **Слой 4.5 ContradictionDetector** — новая секция между детекторами и агрегаторами (модель данных, 7 правил, полярность, порядок в pipeline).
- **Слой 2** — 7 → 8 экстракторов (`arp_history.py`), post-extract (reassembler, http_object, file_carve).
- **Слой 3** — `arp_macs`, `tcp_streams`, `http_objects`, `carved_files`.
- **Слой 4** — 15 → 17 детекторов (`command_injection`, `ja3_malware`), direction в `large_transfer`, универсальные evidence-поля.
- **Слой 5** — роль `pivot`, убрано «large_transfer → victim_tag».
- **Слой 6** — TL;DR kill-chain, `_fmt_host`, instance-level MITRE, секция «Противоречия».
- **Реестры** — актуализированы.
- **Известные долги** — убраны сделанные (TCP reassembly, HTTPObject, JA3, Threat Intel), оставлены актуальные.
- **История** — добавлен 0.7.0.