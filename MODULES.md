# Справочник модулей

Описание каждого файла в проекте: что делает, ключевые классы и
функции, связи с другими модулями.

## Корень пакета `pcap_triage/`

### `__init__.py`

Версия пакета.

```python
__version__ = "0.1.0"
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
- **DGA:** `dga_entropy_threshold`, `dga_min_label_length`,
  `dga_allowlist` (CDN, cloud, Azure, Google, cloud tunnels)
- **Suspicious ports:** список портов 21, 22, 4444, 1337, 31337, 8080,
  8443, 12132
- **Private networks:** префиксы для определения internal
- **NXDOMAIN burst:** `nxdomain_burst_threshold: 5`
- **Cloud tunnels:** суффиксы trycloudflare/ngrok/serveo
- **IP check services:** точные домены ip-api.com/ifconfig.me
- **Typosquatting:** `protected_brands` (microsoft, google, …),
  `legitimate_brand_domains`, `typosquatting_levenshtein_threshold: 2`
- **SNI mismatch:** `sni_mismatch_min_flows: 1`,
  `sni_mismatch_allowlist` (DoH, OCSP, smartscreen)
- **Entities:** `entities_top_n: 50`, `gateway_min_flows: 50`,
  `gateway_min_unique_dsts: 10`
- **Domain controller:** `dc_service_ports` (88, 389, 445, 3268, 636),
  `dc_min_service_flows: 20`, `dc_min_unique_srcs: 1`
- **Vulnerable paths:** `vulnerable_paths` (wp-login, .env, /.git),
  `suspicious_download_extensions` (.ps1, .sh, .vbs, .jar)
- **Flow report:** `flow_report_top_n: 100`

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

### `extractors.py` (дубликат)

Старая версия `HTTPExtractor`. Не используется. **Удалить.**

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
- Allowlist через `endswith`

**Класс:** `DGADetector`. Функция `shannon_entropy(s)`.

### `suspicious_port.py`

Соединения к внешним адресам на подозрительные порты.

**Логика:**
- Порт в `config.suspicious_ports`
- `dst_ip` **не** приватный
- Агрегация по `(dst_ip, dst_port)` — один finding на пару

### `nxdomain_burst.py`

Много NXDOMAIN с одного IP.

**Логика:** `dns_nxdomain_by_src[src_ip] >= threshold`.

**Известный долг:** считает за весь файл, не по окну.

### `cloud_tunnel.py`

Домены на cloud tunnel сервисах.

**Логика:** суффикс из `config.cloud_tunnel_domains` (endswith с
проверкой на точку).

### `ip_check_service.py`

Обращения к ip-api.com, ifconfig.me и т.п.

**Логика:** точное совпадение имени домена с `config.ip_check_services`.

### `typosquatting.py`

Подделки под известные бренды.

**Логика:**
- `contains`: бренд как часть label (`event-datamicrosoft.live`)
- `levenshtein`: label близок к бренду (`micr0soft`)
- Allowlist `legitimate_brand_domains`

**Функция:** `levenshtein(a, b) -> int` — классический
редакторский distance.

### `sni_mismatch.py`

SNI без DNS-запроса.

**Логика:**
- `flow.sni` не в `dns_queries`
- Не в `sni_mismatch_allowlist` (проверка по суффиксу)

**Агрегация по SNI.**

### `brute_force.py`

Перебор паролей к одной паре.

**Логика:**
- Много flows к одной `(src_ip, dst_ip, dst_port)`
- Средний размер flow маленький
- Много уникальных src_ports

**Известный долг:** false positive на Google Safe Browsing,
LDAP-порт 389.

### `vulnerable_path.py`

Обращения к уязвимым путям в HTTP.

**Логика:**
- URI содержит подстроку из `config.vulnerable_paths`
  (wp-login, .env, /.git)
- ИЛИ URI заканчивается на расширение из
  `config.suspicious_download_extensions` (.ps1, .sh, .vbs)

**Два типа finding:** `vulnerable_path` и `script_download`.

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

9 файлов, 106 тестов. См. таблицу в `README.md`.

## Известные проблемы в структуре

1. **`extractors/extractors.py`** — дубликат `extractors/http.py`.
   Удалить.
2. **`diag_nbns.py`, `diag_kerberos.py`** — одноразовые диагностические
   скрипты. Не входят в пакет, лежат в корне. Можно удалить или
   вынести в `tools/`.