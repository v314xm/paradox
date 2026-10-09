# Справочник модулей

Описание каждого файла в проекте: что делает, ключевые классы и
функции, связи с другими модулями.

## Корень пакета `pcap_triage/`

### `__init__.py`

Версия пакета.

```python
__version__ = "0.4.0"
```

### `__main__.py`

Точка входа для `python -m pcap_triage`.

```python
from pcap_triage.cli import main
if __name__ == "__main__":
    main()
```

### `cli.py`

CLI-обёртка. Парсинг аргументов, интерактивный ввод пути, вызов
`run_pipeline`, запись отчётов.

**Функции:**
- `_ask_pcap_path() -> Path` — интерактивный ввод пути с валидацией
- `main()` — точка входа, парсит аргументы, вызывает pipeline

**Связи:** `config.py`, `pipeline.py`, `reporters/json_reporter.py`.

### `config.py`

Все настройки и пороги в одном месте. Датакласс `Config`.

**Секции:**
- **DGA:** `dga_entropy_threshold: 3.5`, `dga_min_label_length: 12`,
  `dga_allowlist` (CDN, cloud, Azure, Google, cloud tunnels,
  Stack Exchange, Live Messenger, blogs)
- **Suspicious ports:** 21, 22, 23, 4444, 1337, 31337, 8080, 8443, 12132
- **Private networks:** префиксы для определения internal
- **Port scan:** `port_scan_min_distinct_dsts: 10`,
  `port_scan_max_flows_per_dst: 3`,
  `port_scan_excluded_ports: {80, 443}` (браузер неотличим от скана)
- **NXDOMAIN burst:** `nxdomain_burst_threshold: 5`
- **Cloud tunnels:** суффиксы trycloudflare/ngrok/serveo
- **IP check services:** точные домены ip-api.com/ifconfig.me
- **Typosquatting:** `protected_brands` (18 брендов),
  `legitimate_brand_domains` (~50 доменов),
  `typosquatting_levenshtein_threshold: 2`
- **SNI mismatch:** `sni_mismatch_min_flows: 1`,
  `sni_mismatch_allowlist` (DoH, OCSP, smartscreen)
- **Entities:** `entities_top_n: 50`, `gateway_min_flows: 50`,
  `gateway_min_unique_dsts: 10`
- **Domain controller:** `dc_service_ports` (88, 389, 445, 3268, 636),
  `dc_min_service_flows: 20`, `dc_min_unique_srcs: 1`
- **Brute force:** `brute_force_min_flows: 20`,
  `brute_force_max_avg_packets: 20`,
  `brute_force_min_unique_src_ports: 10`,
  `brute_force_uri_ratio_threshold: 0.3`,
  `brute_force_min_rate_flows_per_sec: 0.01`,
  `brute_force_skip_tls_ports: {443, 8443}`,
  `login_endpoint_hints` (login/admin/wp-login/…)
- **Vulnerable paths:** `vulnerable_paths` (wp-login, .env, /.git),
  `suspicious_download_extensions` (.ps1, .sh, .vbs, .exe, .dll)
- **Web scanner:** `web_scanner_min_distinct_paths: 10`
- **Flow report:** `flow_report_top_n: 500`

**Связи:** передаётся во все слои (extractors, detectors, aggregators).

### `models.py`

Контракты данных. Определяет все структуры, которыми обмениваются
слои.

**Датаклассы:**
- `Finding` — результат работы детектора
  (`type`, `value`, `confidence`, `evidence`, `first_seen`,
  `last_seen`)
- `FlowKey` — направленный 5-tuple (`proto`, `src_ip`, `dst_ip`,
  `src_port`, `dst_port`)
- `SessionKey` + `make_session_key()` — нормализованный ключ
  (для будущего использования, пока не активен)
- `FlowStats` — состояние flow (`packets`, `bytes_sent`, `timestamps`,
  `initiated_by_src`, `sni`, `http_host`, `http_uri`, `http_method`,
  `http_user_agent`)
- `HostIdentity` — профиль хоста (`ip`, `mac`, `hostnames`,
  `username`, `realm`)
- `CaptureState` — корневая структура (`dns_queries`, `flows`,
  `host_identities`, `packet_count`, `extractor_errors`)

**Связи:** импортируется везде.

### `parsers.py`

Быстрый парсер сырых пакетов через `struct.unpack`. Без scapy dissect.

**Функции:**
- `parse_packet(raw: bytes, ts: float) -> PacketRecord` — разбор
  Ethernet/VLAN/IPv4/TCP/UDP/ICMP/ARP

**Датакласс:**
- `PacketRecord` — нормализованный пакет (L2-L4 поля + `payload`)

**Константы:** `ETHERNET_HEADER_LEN`, `ETHERTYPE_IPV4`,
`ETHERTYPE_ARP`, `ETHERTYPE_VLAN`, `PROTO_TCP`, `PROTO_UDP`,
`PROTO_ICMP`.

**Не поддержано:** IPv6, QinQ, non-Ethernet link types.

### `pipeline.py`

Склейка слоёв. Главная функция `run_pipeline()`.

**Функции:**
- `sha256_file(path)` — хэш pcap для provenance
- `_extract(pcap_path, state)` — читает pcap, вызывает экстракторы.
  Автоопределение classic pcap / pcapng по magic bytes.
- `_detect(state, config)` — запускает все детекторы
- `_summarize_direction(state, config)` — считает uploaded/downloaded
- `run_pipeline(pcap_path, config) -> dict` — общая точка входа

**Реестры:**
- `EXTRACTORS` — список экстракторов (FlowExtractor первым)
- `DETECTORS` — список детекторов (порядок не важен)

**Связи:** `parsers.py`, `extractors/*`, `detectors/*`,
`aggregators/entities.py`, `reporters/flow_report.py`.

### `net_utils.py`

Утилиты для классификации IP и направления трафика.

**Функции:**
- `is_internal_ip(ip, config) -> bool` — проверка приватного IP
- `classify_direction(src_ip, dst_ip, config) -> str` —
  `"outbound"` (internal → external), `"inbound"` (external → internal),
  `"internal"` (оба internal), `"external"` (оба external)

**Связи:** используется в `aggregators/entities.py`,
`pipeline.py:_summarize_direction`.

### `tls_parse.py`

Парсер TLS ClientHello. Извлекает SNI.

**Функции:**
- `extract_sni(payload: bytes) -> str | None` — разбор записи
  TLS handshake, поиск extension `server_name`
- `_find_sni_extension(...)`, `_parse_server_name(...)` — внутренние

**Константы:** `TLS_CONTENT_HANDSHAKE`, `TLS_HANDSHAKE_CLIENT_HELLO`,
`TLS_EXTENSION_SERVER_NAME`.

**Ограничения:** работает на одном TCP-сегменте. Не поддерживает
TLS 1.3 ECH, фрагментированные ClientHello.

### `http_parse.py`

Парсер HTTP-запросов из TCP-payload.

**Функции:**
- `parse_request(payload) -> dict | None` — разбор первой строки
  (method, URI, версия), заголовков (Host, User-Agent)

**Константы:** `HTTP_METHODS` (GET, POST, PUT, DELETE, ...).

**Не поддержано:** HTTP/2, chunked-тела, multipart.

### `nbns_parse.py`

Парсер NBNS (NetBIOS Name Service). Извлекает имя хоста.

**Функции:**
- `decode_nbns_name(encoded: bytes) -> (str, int) | None` — декодирует
  32-байтовое NetBIOS-имя в (name, suffix)
- `parse_nbns(payload) -> NBNSName | None` — разбор пакета UDP/137
- `_read_question`, `_read_answer`, `_read_name` — внутренние

**Датакласс:** `NBNSName(name, suffix, name_type)`.

**Формат:** RFC 1002. Имя кодируется попарно: `0x41 0x41` → `A`.
Суффикс определяет тип ресурса: `0x00` (workstation),
`0x20` (server), `0x1C` (DC), `0x03` (messenger).

### `kerberos_parse.py`

Минимальный ASN.1 DER парсер для Kerberos.

**Функции:**
- `parse_kerberos(payload) -> KerberosInfo | None` — разбор AS-REQ,
  AS-REP, TGS-REQ, TGS-REP, AP-REQ
- `_read_tlv(data, pos, strict)` — читает TLV (tag, length, value)
- `_parse_kerberos_sequence(content)` — верхний SEQUENCE
- `_handle_context_field`, `_handle_body_field` — обработка
  `[context N]`
- `_parse_principal_name`, `_extract_first_string` — PrincipalName

**Датакласс:** `KerberosInfo(msg_type, cname, crealm, sname, realm)`.

**Формат:** RFC 4120. Поддерживает lenient-режим для фрагментированных
TCP-сообщений — читает что есть, не падает.

## Слой экстракторов `pcap_triage/extractors/`

### `base.py`

Protocol-контракт экстрактора.

```python
class Extractor(Protocol):
    name: str
    layer: int
    def process(self, pkt, state: CaptureState) -> None: ...
```

### `flow.py`

Базовый экстрактор. Создаёт `FlowStats` для каждого 5-tuple.

**Порядок:** **должен идти первым** — все остальные экстракторы ищут
существующий flow по `FlowKey`.

**Что пишет:** `state.flows[key]` — packets, bytes_sent, timestamps,
initiated_by_src (по первому SYN без ACK).

### `dns.py`

DNS-экстрактор. Работает на UDP/53.

**Что пишет:**
- `state.dns_queries[qname]`
- `state.dns_nxdomain[qname]` (rcode=3)
- `state.dns_nxdomain_by_src[src_ip]`
- `state.dns_queries_by_src[client_ip][qname]`

Использует scapy для парсинга DNS-payload (только для порта 53).

**Strict decode:** qname декодируется через `decode("ascii")`, при
ошибке запрос отбрасывается. Без этого битые qname дают DGA-FP.

### `tls.py`

TLS-экстрактор. Извлекает SNI из ClientHello.

**Что пишет:** `flow.sni` (в существующий FlowStats).

**Ограничение:** ClientHello должен уместиться в один TCP-сегмент.
Работает на нестандартных портах (8443, 4443, 9443).

**Падает явно**, если FlowStats не найден — это ловит ошибку
порядка регистрации.

### `http.py`

HTTP-экстрактор. Извлекает Host, URI, Method, User-Agent из
HTTP-запросов.

**Что пишет:** `flow.http_host`, `flow.http_uri`, `flow.http_method`,
`flow.http_user_agent`.

**Только запросы**, не ответы.

### `host_identity.py`

Извлекает MAC из ARP. Только ARP, без fallback из Ethernet.

**Что пишет:** `state.host_identities[ip].mac`.

**Почему без fallback:** в routed-сетях `eth_src` — MAC шлюза,
а не хоста. Fallback приводил к тому, что один MAC шлюза записывался
на десятки IP.

### `nbns.py`

Извлекает hostname из NBNS-пакетов.

**Что пишет:** `state.host_identities[src_ip].hostnames.add(name)`.

**Фильтр по суффиксам:** только `0x00` (workstation) и `0x20` (server).

### `kerberos.py`

Извлекает username, realm, sname из Kerberos.

**Что пишет:**
- `state.host_identities[client_ip].username` — cname без `$`
- `state.host_identities[client_ip].hostnames.add(...)` — cname с `$`
- `state.host_identities[client_ip].realm` — crealm/realm
  (FQDN предпочтительнее короткого NetBIOS)

**Обрабатывает оба направления:** запросы клиента (dst_port=88) и
ответы KDC (src_port=88).

## Слой детекторов `pcap_triage/detectors/`

### `base.py`

Protocol-контракт детектора.

```python
class LocalDetector(Protocol):
    name: str
    def run(self, state, config) -> list[Finding]: ...
```

### `dga.py`

DGA-детектор по энтропии label.

**Логика:**
- Длина label ≥ `dga_min_label_length`
- Энтропия Шеннона > `dga_entropy_threshold`
- Игнор дефисов (признак человекочитаемого домена)
- Allowlist через `endswith` (CDN, cloud, Azure, Google,
  Stack Exchange, Live Messenger, blogs)

**Класс:** `DGADetector`. Функция `shannon_entropy(s)`.

### `suspicious_port.py`

Соединения к внешним адресам на подозрительные порты.

**Логика:**
- Порт в `config.suspicious_ports`
- `dst_ip` **не** приватный
- Агрегация по `(dst_ip, dst_port)` — один finding на пару
- **Фильтр `port_scan`:** если все src в finding'е — сканеры
  (у каждого ≥ `port_scan_min_distinct_dsts` разных dst на этот порт),
  finding пропускается — его покрывает `PortScanDetector`.

### `port_scan.py`

Горизонтальное сканирование: один src_ip, много dst_ip, один dst_port.

**Логика:**
- Группировка flows по `(src_ip, dst_port)`
- Порты 80/443 исключены (`port_scan_excluded_ports`) — браузер
  неотличим от скана
- Порог: ≥ `port_scan_min_distinct_dsts` (10) разных dst_ip
- Дополнительно: доля «тонких» целей (≤ `port_scan_max_flows_per_dst`
  flow'ов) должна быть ≥ 0.7 — иначе это браузер с параллельными
  соединениями

**Отличие от `suspicious_port`:**
- `suspicious_port` → finding per `(dst_ip, dst_port)`, много findings
- `port_scan` → finding per `(src_ip, dst_port)`, один finding

**Отличие от `brute_force`:**
- `brute_force` → много flow'ов к ОДНОМУ dst_ip
- `port_scan` → по 1-2 flow к КАЖДОМУ из многих dst_ip

**Класс:** `PortScanDetector`.

### `nxdomain_burst.py`

Много NXDOMAIN с одного IP.

**Логика:** `dns_nxdomain_by_src[src_ip] >= threshold`.

**Известный долг:** считает за весь файл, не по окну. Windowing — в
TODO (см. CHANGELOG).

### `cloud_tunnel.py`

Домены на cloud tunnel сервисах.

**Логика:** суффикс из `config.cloud_tunnel_domains` (endswith с
проверкой на точку).

### `ip_check_service.py`

Обращения к ip-api.com, ifconfig.me и т.п.

**Логика:** точное совпадение имени домена с `config.ip_check_services`.

### `typosquatting.py`

Подделки под известные бренды.

**Логика (v0.4.0):**
- Матчинг идёт **только по SLD** (registered domain, второй уровень
  справа). Поддомены игнорируются: `googleads.g.doubleclick.net` →
  SLD `doubleclick`, не `google`.
- **contains:** бренд — подстрока в SLD, но **не** в начале (sub-brand
  `microsoftstore`) и не в конце с очень коротким префиксом
  (tracking `s-microsoft`)
- **levenshtein:** SLD близок к бренду, при условии:
  - длина ≥ 5 (`app` не считается)
  - не короче бренда на 2+
  - первый и последний символ совпадают (`appier` vs `apple` — разные
    концы, не считается)
  - расстояние ≤ threshold и ≤ 25% длины (`behance` vs `binance` — 2/7
    = 0.29 > 0.25, не считается)
- Allowlist `legitimate_brand_domains` через `endswith`

**Функции:**
- `_registered_label(domain)` — SLD
- `_check_squat(sld, brand, lev_threshold)` — основная проверка
- `levenshtein(a, b)` — классический редакторский distance

**Класс:** `TyposquattingDetector`.

### `sni_mismatch.py`

SNI без DNS-запроса.

**Логика:**
- `flow.sni` не в `dns_queries`
- Не в `sni_mismatch_allowlist` (проверка по суффиксу)

**Агрегация по SNI.**

### `brute_force.py`

Перебор паролей к одной паре.

**Логика (v0.4.0):**
- Много flows к одной `(src_ip, dst_ip, dst_port)`
- Средний размер flow маленький (`max_avg_packets`)
- Много уникальных src_ports
- **Ratio URI:** если много разных URI → браузер, не подбор
- **Rate:** слишком редко (< 0.01 flow/s) → поллинг, не подбор
- **Skip TLS:** порты 443/8443 пропускаются — массовые TCP-соединения
  туда = браузер к CDN
- **Login hint:** если HTTP-трафик и ни один URI не содержит
  login/admin/wp-login → это браузер, не подбор

**Известное ограничение:** SSH/FTP/RDP-подбор не оставляет URI —
фильтр login-hint там не применяется (нет URI). Rate-фильтр
работает.

### `vulnerable_path.py`

Обращения к уязвимым путям в HTTP + скачивание опасных файлов +
детекция web-сканеров.

**Логика (v0.4.0):**
- Нормализация URI: `urlsplit(uri).path`, percent-decode, lowercase.
  `/WP-LOGIN.PHP?nonce=123` и `/wp-login.php?nonce=456` попадают в
  один bucket.
- **vulnerable_path:** URI содержит `config.vulnerable_paths`
- **script_download:** URI заканчивается на
  `config.suspicious_download_extensions`
- **Combo-сигнал:** `/wp-content/uploads/shell.php` даст оба finding
- **Две стратегии агрегации:**
  - individual — если у пары `(src, dst)` < `web_scanner_min_distinct_paths`
    разных URI
  - web_scanner — если ≥ порога. Один finding с `top_paths`,
    `distinct_paths`, `total_requests`. Individual findings для этой
    пары не генерируются.

### `web_scanner` (не отдельный файл)

Тип finding, генерируется `VulnerablePathDetector`. Агрегация
горизонтального перебора URI от одного `(src, dst)`. Confidence 0.9.

## Слой агрегаторов `pcap_triage/aggregators/`

### `entities.py`

Строит сущности из flow'ов и findings.

**Функции:**
- `build_entities(state, findings, config) -> Entities` — основная
- `_ips_from_finding(f)` — извлечь IP + сторону (src/dst) из finding
- `_is_special_ip(ip)` — multicast, broadcast, loopback
- `_touch_times(entity, ts)` — обновить first_seen/last_seen

**Датаклассы:**
- `Entity` — один IP с ролями, статистикой, профилем
- `Entities(internal, external)`

**Роли** (см. `ARCHITECTURE.md`).

## Слой reporters `pcap_triage/reporters/`

### `json_reporter.py`

JSON-отчёт.

**Функции:**
- `write_json(report, path)` — сортированный `json.dump`
- `write_markdown(report, path)` — обёртка для markdown_reporter

### `markdown_reporter.py`

Markdown-отчёт для тикета.

**Функции:**
- `render_markdown(report) -> str` — общий рендер
- `_render_entities(entities)` — секция сущностей
- `_render_http(http)` — секция HTTP
- `_extract_iocs(findings)` — извлечь IOC из findings
- `_fmt_bytes(n)`, `_fmt_duration(s)`, `_short(s, n)` — утилиты

### `flow_report.py`

conn.log-стиль.

**Функции:**
- `build_flow_report(state, config, top_n) -> dict` — top_by_bytes,
  top_by_packets
- `build_dns_report(state, top_n) -> dict`
- `build_http_report(state, top_n) -> dict`

## Тесты `tests/`

10 файлов, 127 тестов. См. таблицу в `README.md`.

**Ключевые файлы:**
- `test_detectors.py` — базовое поведение детекторов
- `test_regressions.py` — FP-регрессии из FIRST-2015.
  Каждый тест привязан к конкретному домену/сценарию, который был FP,
  и к фиксу, который его закрыл. Если регрессия вернётся — тест
  упадёт.

## Известные проблемы в структуре

1. **`extractors/extractors.py`** — дубликат `extractors/http.py`.
   Удалить.
2. **`diag_nbns.py`, `diag_kerberos.py`** — одноразовые диагностические
   скрипты. Не входят в пакет, лежат в корне. Можно удалить или
   вынести в `tools/`.
3. **`nxdomain_burst` windowing** — считает за весь файл. Требует
   правки `CaptureState` (time-bucketed counts).
4. **`vulnerable_path` и `script_download`** — остаются ~96 findings
   в батче FIN-2015. Это остатки сканеров после web_scanner
   агрегации, не FP. Дальнейшее сокращение требует анализа
   домен-специфичных паттернов.