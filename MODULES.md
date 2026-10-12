# Справочник модулей

Описание каждого файла в проекте: что делает, ключевые классы и
функции, связи с другими модулями.

## Корень пакета `pcap_triage/`

### `__init__.py`

Версия пакета.

```python
__version__ = "0.6.0"
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
- **Suspicious ports:** 22, 23, 4444, 1337, 31337, 8080, 8443, 12132
  (порт 21 убран — его обрабатывает FTPBruteForceDetector)
- **Private networks:** префиксы для определения internal
- **Port scan:** `port_scan_min_distinct_dsts: 10`,
  `port_scan_max_flows_per_dst: 3`,
  `port_scan_excluded_ports: {80, 443}`
- **Large transfer:** `large_transfer_min_bytes: 100 MB`,
  `large_transfer_include_reverse: True`,
  `large_transfer_excluded_hosts` (Windows Update, Apple CDN),
  `large_transfer_excluded_user_agents` (Microsoft BITS,
  Microsoft-CryptoAPI, Microsoft-Delivery-Optimization)
- **Lateral movement:** `lateral_movement_ports` (445, 135, 139,
  3389, 5985, 5986), `lateral_movement_min_flows_port_only: 5`,
  `lateral_movement_ua_markers` (WinRM, PsExec, Impacket, …),
  `lateral_movement_uri_markers` (/wsman, /cimv2),
  `lateral_movement_admin_srcs` (пусто по умолчанию)
- **FTP brute force:** `ftp_brute_force_min_flows: 20`,
  `ftp_brute_force_min_unique_src_ports: 20`
- **Beaconing:** `beaconing_min_connections: 10`,
  `beaconing_min_duration_sec: 300`,
  `beaconing_max_jitter_ratio: 0.2`,
  `beaconing_max_avg_bytes: 5000`
- **DNS tunneling:** `dns_tunneling_min_qname_length: 50`,
  `dns_tunneling_min_long_qnames: 20`,
  `dns_tunneling_min_queries: 50`,
  `dns_tunneling_allowlist` (DoH-сервисы: dns.google,
  cloudflare-dns.com, mozilla.cloudflare-dns.com)
- **NXDOMAIN burst:** `nxdomain_burst_threshold: 5`
- **Cloud tunnels:** суффиксы trycloudflare/ngrok/serveo
- **IP check services:** `ip_check_services` (домены) +
  `ip_check_service_ips: Mapping[str, str]` (IP → каноническое имя)
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
  `login_endpoint_hints`
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
- `DETECTORS` — список детекторов (порядок не важен, но все
  зарегистрированы один раз)

**Связи:** `parsers.py`, `extractors/*`, `detectors/*`,
`aggregators/entities.py`, `reporters/flow_report.py`.

### `net_utils.py`

Утилиты для классификации IP и направления трафика.

**Функции:**
- `is_internal_ip(ip, config) -> bool` — проверка приватного IP
- `classify_direction(src_ip, dst_ip, config) -> str` —
  `"outbound"`, `"inbound"`, `"internal"`, `"external"`

**Связи:** используется в `aggregators/entities.py`,
`pipeline.py:_summarize_direction`, `detectors/large_transfer.py`.

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

**Падает явно**, если FlowStats не найден.

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
- Игнор дефисов
- Allowlist через `endswith`

**Класс:** `DGADetector`. Функция `shannon_entropy(s)`.

### `suspicious_port.py`

Соединения к внешним адресам на подозрительные порты.

**Логика:**
- Порт в `config.suspicious_ports`
- `dst_ip` **не** приватный
- Агрегация по `(dst_ip, dst_port)` — один finding на пару
- **Фильтр `port_scan`:** если все src в finding'е — сканеры,
  finding пропускается.

### `port_scan.py`

Горизонтальное сканирование: один src_ip, много dst_ip, один dst_port.

**Логика:**
- Группировка flows по `(src_ip, dst_port)`
- Порты 80/443 исключены
- Порог: ≥ 10 разных dst_ip
- Доля «тонких» целей (≤ 3 flow'ов) должна быть ≥ 0.7

**Класс:** `PortScanDetector`.

### `nxdomain_burst.py`

Много NXDOMAIN с одного IP.

**Логика:** `dns_nxdomain_by_src[src_ip] >= threshold`.

**Известный долг:** считает за весь файл, не по окну.

### `cloud_tunnel.py`

Домены на cloud tunnel сервисах.

**Логика:** суффикс из `config.cloud_tunnel_domains`.

### `ip_check_service.py`

Обращения к сервисам проверки внешнего IP (ip-api.com, ifconfig.me).

**Логика (v0.5.0):**
- **DNS:** `state.dns_queries` содержит домен сервиса
- **SNI:** `flow.sni` содержит домен сервиса
- **HTTP Host:** `flow.http_host` содержит домен сервиса
- **Direct IP:** `flow.dst_ip` в `config.ip_check_service_ips`
  (mapping IP → каноническое имя сервиса)

Все источники дают **одинаковое value** — findings сливаются в один.
Evidence содержит `sources` — список совпавших источников.

### `typosquatting.py`

Подделки под известные бренды.

**Логика (v0.4.0+):**
- Матчинг только по SLD (registered domain)
- **contains:** бренд — подстрока в SLD, но не в начале и не в конце
  с коротким префиксом
- **levenshtein:** SLD близок к бренду, при условиях: длина ≥ 5,
  не короче бренда на 2+, первый и последний символ совпадают,
  distance / max_len ≤ 0.25
- Allowlist `legitimate_brand_domains`

**Функции:**
- `_registered_label(domain)` — SLD
- `_check_squat(sld, brand, lev_threshold)` — основная проверка
- `levenshtein(a, b)` — редакторский distance

### `sni_mismatch.py`

SNI без DNS-запроса.

**Логика:**
- `flow.sni` не в `dns_queries`
- Не в `sni_mismatch_allowlist`

**Агрегация по SNI.**

### `brute_force.py`

HTTP-перебор паролей к одному endpoint.

**Логика (v0.4.0):**
- Много flows к одной `(src_ip, dst_ip, dst_port)`
- Средний размер flow маленький
- Много уникальных src_ports
- **Ratio URI:** много разных URI → браузер
- **Rate:** слишком редко (< 0.01 flow/s) → поллинг
- **Skip TLS:** порты 443/8443 пропускаются
- **Login hint:** HTTP без login-endpoint → браузер
- **Skip port 21:** FTP обрабатывает FTPBruteForceDetector

### `ftp_brute_force.py`

Словарный подбор паролей к FTP-серверу.

**Логика:**
- Группировка flows по `(src_ip, dst_ip, dst_port=21)`
- Порог `flow_count >= 20`
- Порог `unique_src_ports >= 20`
- Каждая попытка = новое TCP-соединение = новый src_port

**Confidence:**
- 0.95 при flow_count ≥ 100
- 0.85 при flow_count ≥ 50
- 0.75 иначе

**Отличие от HTTP-brute_force:** FTP-сессия = 1185 пакетов,
рубится `brute_force_max_avg_packets: 20`. Отдельный детектор
с отдельными порогами.

**Класс:** `FTPBruteForceDetector`.

### `beaconing.py`

Периодические обращения к C2 (heartbeat).

**Логика (v0.6.0):**
- Группировка flows по `(src_ip, dst_ip, dst_port)` — src_port
  игнорируется, потому что каждый beacon = новое TCP-соединение
- N ≥ `beaconing_min_connections` (10)
- Длительность ≥ `beaconing_min_duration_sec` (300)
- jitter = stddev(intervals) / mean(intervals) < `beaconing_max_jitter_ratio` (0.2)
- Средний размер flow < `beaconing_max_avg_bytes` (5000)

**Confidence:** 0.85 при jitter 0.05, 0.6 при jitter = max_jitter_ratio.

**Отличие от brute_force:** brute_force — много flows ЗА КОРОТКОЕ
ВРЕМЯ. Beaconing — много flows с РАВНЫМИ ИНТЕРВАЛАМИ на длинном
горизонте.

**Класс:** `BeaconingDetector`.

### `dns_tunneling.py`

DNS-туннелирование (exfiltration через DNS).

**Логика (v0.6.0):**
- Группировка по `(src_ip, base_domain)` — где base_domain = последние
  2 уровня (attacker.com)
- `total_queries >= dns_tunneling_min_queries` (50)
- `long_qnames_count >= dns_tunneling_min_long_qnames` (20) —
  qname длиной ≥ 50 символов
- Allowlist `dns_tunneling_allowlist` (DoH)

**Confidence:** 0.9 при long_count ≥ 2×min_long, 0.7 иначе.

**Отличие от DGA:** DGA — короткие поддомены (10-15 символов).
Tunneling — длинные (>50). Требуем min_qname_length, чтобы DGA
не сработал как tunneling.

**Класс:** `DNSTunnelingDetector`.

### `lateral_movement.py`

Признаки перемещения по внутренней сети.

**Логика (v0.5.0):**
- Внутренний → внутренний трафик на порты удалённого управления
  (445, 135, 139, 3389, 5985, 5986)
- **UA-маркер** (WinRM, PsExec, Impacket, wmiexec, evil-winrm) —
  confidence 0.8
- **URI-маркер** (/wsman, /cimv2, /root/cimv2, /wmi) — 0.8
- **Только порт** — confidence 0.6, но требует ≥ 5 flows.
  Одиночный RDP-сеанс к jump-host — норма.

**Allowlist:** `lateral_movement_admin_srcs`.

**Класс:** `LateralMovementDetector`.

### `large_transfer.py`

Аномально большой объём в одном flow.

**Логика:**
- Один FlowKey или пара (прямой + обратный) с суммой байт >
  `large_transfer_min_bytes` (100 МБ)
- `large_transfer_include_reverse=True` — суммирует оба направления
- **Exclude:** хосты из `large_transfer_excluded_hosts`
  (Windows Update, Apple CDN) и UA из
  `large_transfer_excluded_user_agents` (Microsoft BITS)
- Агрегация по нормализованной паре `frozenset({src, dst})`

**Confidence:** 0.85.

**Класс:** `LargeTransferDetector`.

### `vulnerable_path.py`

Обращения к уязвимым путям в HTTP + скачивание опасных файлов +
детекция web-сканеров.

**Логика (v0.4.0+):**
- Нормализация URI: `urlsplit(uri).path`, percent-decode, lowercase
- **vulnerable_path:** URI содержит `config.vulnerable_paths`
- **script_download:** URI заканчивается на
  `config.suspicious_download_extensions`
- **Две стратегии:** individual (для одиночных) и web_scanner
  (для ≥ 10 разных URI от одного (src, dst))

## Слой агрегаторов `pcap_triage/aggregators/`

### `entities.py`

Строит сущности из flow'ов и findings.

**Функции:**
- `build_entities(state, findings, config) -> Entities` — основная
- `_ips_from_finding(f)` — извлечь IP + сторону из finding
- `_is_special_ip(ip)` — multicast, broadcast, loopback
- `_touch_times(entity, ts)` — обновить first_seen/last_seen

**Датаклассы:**
- `Entity` — один IP с ролями, статистикой, профилем
- `Entities(internal, external)`

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

12 файлов, 165 тестов. См. таблицу в `README.md`.

**Ключевые файлы:**
- `test_detectors.py` — базовое поведение старых 9 детекторов
- `test_regressions.py` — FP-регрессии из FIRST-2015 и CyberCampTask
- `test_beaconing.py` — BeaconingDetector (10 тестов)
- `test_dns_tunneling.py` — DNSTunnelingDetector (9 тестов)

## Известные проблемы в структуре

1. **`extractors/extractors.py`** — дубликат `extractors/http.py`.
   Удалить.
2. **`diag_nbns.py`, `diag_kerberos.py`** — одноразовые диагностические
   скрипты. Вынести в `tools/` или удалить.
3. **`nxdomain_burst` windowing** — считает за весь файл. Требует
   правки `CaptureState` (time-bucketed counts).
4. **`vulnerable_path` и `script_download`** — остаются ~96 findings
   в батче FIN-2015. Остатки сканеров после web_scanner агрегации.
5. **`beaconing` требует windowing** для ловли медленных C2
   (интервал больше часа). Сейчас работает только на heartbeat
   в пределах одной сессии захвата.