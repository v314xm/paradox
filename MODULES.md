Справочник модулей
Описание каждого файла в проекте: что делает, ключевые классы и
функции, связи с другими модулями.

Версия ядра: 0.7.0. GUI: v0.1.

Корень пакета pcap_triage/
__init__.py
Версия пакета.

python
__version__ = "0.7.0"
__main__.py
Точка входа для python -m pcap_triage.

python
from pcap_triage.cli import main
if __name__ == "__main__":
    main()
cli.py
CLI-обёртка. Парсинг аргументов, интерактивный ввод пути, вызов
run_pipeline, запись отчётов.

Функции:

_ask_pcap_path() -> Path — интерактивный ввод пути с валидацией

main() — точка входа, парсит аргументы, вызывает pipeline

Флаги: -o/--output (файл или директория), --enrich
(Threat Intel, требует сети).

Связи: config.py, pipeline.py, reporters/json_reporter.py.

config.py
Все настройки и пороги в одном месте. Датакласс Config
(frozen=True). Валидация в __post_init__ через _validate().

Секции (по порядку в файле):

Cloud tunnel domains: cloud_tunnel_domains — 7 сервисов
(trycloudflare, ngrok.io, ngrok-free.app, serveo.net,
localtunnel.me, lhr.life, pinggy.io).

IP check services: ip_check_services (8 доменов),
ip_check_service_ips (Mapping IP → каноническое имя сервиса,
4 записи для ip-api.com и ifconfig.me).

JA3 fingerprinting: ja3_known_malware (7 хешей: Cobalt Strike
×3, Tor, Dridex, Trickbot, Emotet), ja3_known_tools
(3 хеша: python-requests, python-urllib, go-http-client).
Разделены намеренно: tools — не malware.

Command injection: command_injection_patterns_high (Lua, PHP,
Python, Ruby, Node, Java — 20+ паттернов),
command_injection_patterns_medium (shell-синтаксис, утилиты,
require ≥ 2 совпадений), command_injection_min_patterns: 1,
command_injection_aggregate_min: 5.

File carve: file_carve_enabled: True,
file_carve_write_body: False (безопасный metadata-only),
file_carve_min_size: 64, file_carve_max_size: 50 МБ.

DGA: dga_entropy_threshold: 3.5,
dga_min_label_length: 12,
_dga_allowlist_extra (~25 доменов),
dga_allowlist — merge extra + cloud tunnels + ip-check (init=False).

Suspicious ports: 22, 23, 4444, 1337, 31337, 8080, 8443, 12132.
Порт 21 убран — его обрабатывает FTPBruteForceDetector.

Private networks: префиксы 10., 172.16-31., 192.168., 127.,
169.254., multicast 224./239., broadcast.

Port scan: port_scan_min_distinct_dsts: 10,
port_scan_max_flows_per_dst: 3,
port_scan_excluded_ports: {80, 443}.

TCP reassembly: tcp_reassembly_enabled: True,
max_bytes_per_flow: 1 МБ, max_total_bytes: 200 МБ.

Beaconing (v0.7.0 пороги): min_connections: 20,
min_duration_sec: 600, max_jitter_ratio: 0.1,
max_avg_bytes: 5000, max_flows_per_minute: 5.0,
payload_stddev_ratio_max: 0.5, skip_internal_dst: True,
mail_polling_ports: {110, 143, 993, 995} (POP3/IMAP — дизайн,
не C2), allowlist_suffixes (~70 доменов: analytics, CDN,
cloud, MS, Apple), allowlist_ips (пусто).

DNS tunneling: min_qname_length: 50,
min_long_qnames: 20, min_queries: 50,
allowlist (DoH: dns.google, cloudflare-dns.com,
mozilla.cloudflare-dns.com).

Large transfer: min_bytes: 100 МБ,
include_reverse: True, excluded_hosts (7: Windows Update,
Apple CDN), excluded_user_agents (3: BITS, CryptoAPI,
Delivery-Optimization).

Port service mismatch: port_service_allowed —
Mapping порт → frozenset протоколов (22→ssh, 25→smtp+tls, 80→http+tls,
445→smb, 3389→rdp, 5432→postgres, 6379→redis, 27017→mongodb,
всего 18 портов). Порты вне таблицы не проверяются.

Reverse asymmetry: min_total_bytes: 1 МБ,
min_ratio: 10.0, high_ratio: 25.0.

Lateral movement: ports (445, 135, 139, 3389, 5985, 5986),
min_flows_port_only: 5, ua_markers (WinRM, PsExec, Impacket,
wmiexec, evil-winrm, ruby winrm), uri_markers (/wsman,
/cimv2, /root/cimv2, /wmi), admin_srcs (пусто).

FTP brute force: min_flows: 20,
min_unique_src_ports: 20.

NXDOMAIN burst: nxdomain_burst_threshold: 5.

Typosquatting: protected_brands (18 брендов),
legitimate_brand_domains (~60 доменов),
typosquatting_levenshtein_threshold: 2.

SNI mismatch: sni_mismatch_min_flows: 1,
sni_mismatch_allowlist (10: DoH, OCSP, smartscreen).

Domain controller: dc_service_ports (88, 389, 445, 3268, 636),
dc_min_service_flows: 20, dc_min_unique_srcs: 1.

Brute force: min_flows: 20, max_avg_packets: 20,
min_unique_src_ports: 10, uri_ratio_threshold: 0.3,
min_rate_flows_per_sec: 0.01, skip_tls_ports: {443, 8443},
excluded_ports — alias на dc_service_ports (init=False),
login_endpoint_hints (15 подстрок).

Vulnerable paths: vulnerable_paths (Mapping, 16 записей:
wp-login, .env, .git, phpmyadmin, AWS credentials…),
suspicious_download_extensions (.ps1, .vbs, .hta, .jar, .sh,
.exe, .dll, .scr, .iso, .img, .lnk),
web_scanner_min_distinct_paths: 10.

Entities: entities_top_n: 50, gateway_min_flows: 50,
gateway_min_unique_dsts: 10.

Flow report: flow_report_top_n: 500.

Enrichment: enrichment_cache_ttl_days: 7,
enrichment_cache_path: reports/.cache/enrichment.db,
enrichment_enabled_providers (shodan_internetdb, abuseipdb,
virustotal), enrichment_max_iocs: 100.

Output: output_dir: reports.

Связи: передаётся во все слои (extractors, detectors,
contradictions, aggregators, enrichment).

models.py
Контракты данных. Определяет структуры, которыми обмениваются слои.

Датаклассы:

Finding — результат детектора: type, value, confidence,
evidence, first_seen, last_seen, mitre_techniques
(instance-level, приоритетнее type-map в mitre_map.py).

FlowKey — направленный 5-tuple (proto, src_ip, dst_ip,
src_port, dst_port). A→B и B→A — разные ключи.

SessionKey + make_session_key() — нормализованный ключ
(направление схлопывается).

FlowStats — состояние flow: базовая телеметрия (packets,
bytes_sent, first_ts, last_ts, timestamps,
initiated_by_src) + протокол-специфичные поля (sni, ja3,
ja3s, http_host, http_uri, http_method,
http_user_agent).

HostIdentity — профиль хоста (ip, mac, hostnames,
username, realm).

CaptureState — корневая структура:

DNS: dns_queries, dns_nxdomain, dns_nxdomain_by_src,
dns_queries_by_src

flows: flows, session_sni

identity: host_identities, arp_macs (ip → mac →
[first, last, count])

TCP: tcp_streams, tcp_streams_truncated, http_objects,
carved_files

meta: packet_count, first_ts, last_ts, extractor_errors

Связи: импортируется везде.

parsers.py
Быстрый парсер сырых пакетов через struct.unpack. Без scapy
dissect.

Функции:

parse_packet(raw: bytes, ts: float) -> PacketRecord — разбор
Ethernet/VLAN/IPv4/TCP/UDP/ICMP/ARP

Датакласс: PacketRecord — нормализованный пакет (L2-L4 поля

payload).

Константы: ETHERNET_HEADER_LEN, ETHERTYPE_IPV4,
ETHERTYPE_ARP, ETHERTYPE_VLAN, PROTO_TCP, PROTO_UDP,
PROTO_ICMP.

Не поддержано: IPv6, QinQ, non-Ethernet link types.

Производительность: ~25 МБ/с (39x быстрее scapy dissect).

p### `pipeline.py`

Склейка слоёв. Главная функция `run_pipeline()`.

**Функции:**
- `sha256_file(path, chunk_size=1<<20)` — хэш pcap для provenance
- `_extract(pcap_path, state, config)` — читает pcap, вызывает
  экстракторы. Автоопределение classic pcap / pcapng по magic
  bytes. Прогресс-бар через `sys.stdout.isatty()`. Reassembly
  до экстракторов, finalize + HTTPObject + FileCarve после.
- `_detect(state, config)` — запускает все детекторы, потом
  заполняет MITRE-техники через `mitre_map.get_techniques()`
  (instance-level приоритетнее type-map)
- `_summarize_direction(state, config)` — uploaded / downloaded /
  internal / external байты
- `_summarize_mitre(findings)` — Counter техник по всем findings
- `run_pipeline(pcap_path, config) -> dict` — общая точка входа

**Схема JSON:** `schema_version: "0.3.0"`.

**Summary содержит:** `packets`, `unique_dns_queries`,
`nxdomain_count`, `flows`, `findings`, `contradictions`,
`extractor_errors`, `tcp_streams`, `tcp_streams_truncated`,
`http_objects`, `carved_files`, `uploaded_bytes`,
`downloaded_bytes`, `internal_bytes`, `external_bytes`.

**MITRE-сводка** кладётся в `carved_files.mitre` (необычно, но так
в коде): `total_techniques` + `by_technique`.

**Реестры:**
- `EXTRACTORS` — 8, `FlowExtractor` первым
- `DETECTORS` — 17, порядок не важен
- `RULES` (в `contradictions/registry.py`) — 7

**Связи:** `parsers.py`, `extractors/*`, `detectors/*`,
`contradictions/*`, `aggregators/entities.py`, `reporters/*`,
`reassembler.py`, `file_carve.py`.

tls_parse.py
Парсер TLS ClientHello. Извлекает SNI.

Функции:

extract_sni(payload: bytes) -> str | None — разбор записи
TLS handshake, поиск extension server_name

_find_sni_extension(...), _parse_server_name(...) — внутренние

Константы: TLS_CONTENT_HANDSHAKE,
TLS_HANDSHAKE_CLIENT_HELLO, TLS_EXTENSION_SERVER_NAME.

Ограничения: работает на одном TCP-сегменте. Не поддерживает
TLS 1.3 ECH, фрагментированные ClientHello.

http_parse.py
Парсер HTTP-запросов из TCP-payload.

Функции:

parse_request(payload) -> dict | None — разбор первой строки
(method, URI, версия), заголовков (Host, User-Agent)

Константы: HTTP_METHODS (GET, POST, PUT, DELETE, OPTIONS, …).

Не поддержано: HTTP/2, chunked-тела, multipart.

nbns_parse.py
Парсер NBNS (NetBIOS Name Service). Извлекает имя хоста.

Функции:

decode_nbns_name(encoded: bytes) -> (str, int) | None —
декодирует 32-байтовое NetBIOS-имя в (name, suffix)

parse_nbns(payload) -> NBNSName | None — разбор UDP/137

_read_question, _read_answer, _read_name — внутренние

Датакласс: NBNSName(name, suffix, name_type).

Формат: RFC 1002. Имя кодируется попарно: 0x41 0x41 → A.
Суффикс: 0x00 (workstation), 0x20 (server), 0x1C (DC),
0x03 (messenger).

kerberos_parse.py
Минимальный ASN.1 DER парсер для Kerberos.

Функции:

parse_kerberos(payload) -> KerberosInfo | None — разбор AS-REQ,
AS-REP, TGS-REQ, TGS-REP, AP-REQ

_read_tlv(data, pos, strict) — читает TLV

_parse_kerberos_sequence(content) — верхний SEQUENCE

_handle_context_field, _handle_body_field — обработка
[context N]

_parse_principal_name, _extract_first_string — PrincipalName

Датакласс: KerberosInfo(msg_type, cname, crealm, sname, realm).

Формат: RFC 4120. Lenient-режим для фрагментированных
TCP-сообщений.

ja3.py (v0.6.0)
Парсер ClientHello/ServerHello, MD5-fingerprint по Salesforce-методу.

Функции:

compute_ja3(payload) -> str | None — JA3 клиента

compute_ja3s(payload) -> str | None — JA3S сервера

_parse_extensions(...), _parse_ciphers(...),
_parse_curves(...), _parse_point_formats(...) — внутренние

Формат: строка SSLVersion,Cipher,SSLExtension,EllipticCurve,ECPointFormat,
MD5 от неё.

Связи: extractors/tls.py (пишет в flow.ja3 / flow.ja3s),
detectors/ja3_malware.py, contradictions/facts.py.

reassembler.py (v0.6.0)
TCP-склейка сегментов по sequence numbers.

Класс: TCPReassembler.

Логика:

Буферизация по offset, обработка out-of-order и retransmit

Finalize по FIN/RST

Лимиты: 1 МБ per-flow, 200 МБ total

Заполняет state.tcp_streams и state.tcp_streams_truncated

Связи: вызывается из pipeline.py после _extract.

http_object.py (v0.6.0)
Парсер полного HTTP-запроса/ответа из tcp_streams.

Класс: HTTPObjectExtractor.

Логика:

Content-Length, chunked encoding, body limit 1 МБ

Двухпроходная сборка: pass 1 — requests (собираем URI),
pass 2 — responses (URI пробрасывается из парного request
по нормализованному pair-key)

Заполняет state.http_objects

Связи: вызывается из pipeline.py, результат используется
CommandInjectionDetector и FileCarve.

file_carve.py (v0.6.0)
Метаданные payload'ов из HTTP-ответов. Body на диск НЕ пишется
по умолчанию.

Функции:

carve_files(state, config) -> None — заполняет
state.carved_files

Что сохраняется: sha256, размер, MIME, URI, первые 64 байта
в hex. Определение расширения по Content-Type + magic bytes +
URI-fallback.

Флаг file_carve_write_body: если True — сохраняет как
<sha256>.bin (не .exe/.ps1).

Связи: pipeline.py, detectors/vulnerable_path.py.

Слой экстракторов pcap_triage/extractors/
base.py
Protocol-контракт экстрактора.

python
class Extractor(Protocol):
    name: str
    layer: int
    def process(self, pkt, state: CaptureState) -> None: ...
flow.py
Базовый экстрактор. Создаёт FlowStats для каждого 5-tuple.

Порядок: должен идти первым — все остальные экстракторы ищут
существующий flow по FlowKey.

Что пишет: state.flows[key] — packets, bytes_sent, timestamps,
initiated_by_src (по первому SYN без ACK).

dns.py
DNS-экстрактор. Работает на UDP/53.

Что пишет:

state.dns_queries[qname]

state.dns_nxdomain[qname] (rcode=3)

state.dns_nxdomain_by_src[src_ip]

state.dns_queries_by_src[client_ip][qname]

Использует scapy для парсинга DNS-payload (только порт 53).

Strict decode: qname через decode("ascii"), при ошибке
запрос отбрасывается (иначе битые qname дают DGA-FP).

Не парсит ответы — только запросы. Известный долг.

tls.py
TLS-экстрактор. Извлекает SNI + JA3/JA3S из ClientHello/ServerHello.

Что пишет: flow.sni, flow.ja3, flow.ja3s,
state.session_sni.

Ограничение: ClientHello должен уместиться в один TCP-сегмент.
Работает на нестандартных портах (8443, 4443, 9443).

Падает явно, если FlowStats не найден.

http.py
HTTP-экстрактор. Извлекает Host, URI, Method, User-Agent из
HTTP-запросов.

Что пишет: flow.http_host, flow.http_uri,
flow.http_method, flow.http_user_agent.

Только запросы, не ответы. Сигнатура по методу — работает на
нестандартных портах.

host_identity.py
Извлекает MAC из ARP.

Что пишет: state.host_identities[ip].mac,
mac_history (MAC → first_ts, last_ts, count).

Почему без fallback на Ethernet: в routed-сетях eth_src —
MAC шлюза. Fallback приводил к тому, что один MAC шлюза
записывался на десятки IP.

arp_history.py (v0.7.0)
Параллельно с host_identity ведёт полную историю MAC на IP.

Что пишет: state.arp_macs[ip][mac] = [first_ts, last_ts, count].

Почему отдельный: host_identities.mac хранит только последний
MAC. Для mac_ip_conflict нужны все MAC, включая ARP-spoof.

Класс: ARPMacHistoryExtractor, name = "arp_mac_history".

nbns.py
Извлекает hostname из NBNS.

Что пишет: state.host_identities[src_ip].hostnames.add(name).

Фильтр по суффиксам: только 0x00 (workstation) и
0x20 (server).

kerberos.py
Извлекает username, realm, sname из Kerberos.

Что пишет:

state.host_identities[client_ip].username — cname без $

state.host_identities[client_ip].hostnames.add(...) — cname с $

state.host_identities[client_ip].realm — crealm/realm

Обрабатывает оба направления: запросы клиента (dst_port=88)
и ответы KDC (src_port=88).

http_object.py (v0.6.0)
Экстрактор-обёртка над pcap_triage/http_object.py.

Класс: HTTPObjectExtractor.

Метод: run_post_extract(state, config) — вызывается
из pipeline.py после TCPReassembler.

Не process(record, state) — работает не на пакетах, а на
готовых tcp_streams.
Слой детекторов pcap_triage/detectors/
base.py
Protocol-контракт детектора.

python
class LocalDetector(Protocol):
    name: str
    def run(self, state, config) -> list[Finding]: ...
mitre_map.py
Статический маппинг Finding.type → tuple[MITRE techniques].

Константы: MITRE_MAP: dict[str, tuple[str, ...]] —
покрывает recon (T1046, T1595.002, T1190), initial access
(T1110.001, T1189, T1583.001), C2 (T1568.002, T1572, T1041,
T1016, T1071.001), lateral movement (T1021.001) и пр.

Функции:

get_techniques(finding_type) -> tuple[str, ...] — lookup

Приоритет: instance-level Finding.mitre_techniques (если
заполнено детектором, например large_transfer по direction)
перебивает type-map. Логика в reporters/markdown_reporter.py:_mitre_for_finding().

dga.py
DGA-детектор по энтропии label.

Логика:

Длина label ≥ dga_min_label_length

Энтропия Шеннона > dga_entropy_threshold

Игнор дефисов

Allowlist через endswith

Класс: DGADetector. Функция: shannon_entropy(s).

suspicious_port.py
Соединения к внешним адресам на подозрительные порты.

Логика:

Порт в config.suspicious_ports

dst_ip не приватный

Агрегация по (dst_ip, dst_port) — один finding на пару

Фильтр port_scan: если все src в finding'е — сканеры,
finding пропускается

port_scan.py
Горизонтальное сканирование: один src_ip, много dst_ip, один
dst_port.

Логика:

Группировка flows по (src_ip, dst_port)

Порты 80/443 исключены

Порог: ≥ 10 разных dst_ip

Доля «тонких» целей (≤ 3 flow'ов) должна быть ≥ 0.7

Класс: PortScanDetector.

nxdomain_burst.py
Много NXDOMAIN с одного IP.

Логика: dns_nxdomain_by_src[src_ip] >= threshold.

Известный долг: считает за весь файл, не по окну (93 findings
на FIN-2015, часть — FP).

cloud_tunnel.py
Домены на cloud tunnel сервисах.

Логика: суффикс из config.cloud_tunnel_domains.

ip_check_service.py
Обращения к сервисам проверки внешнего IP (ip-api.com,
ifconfig.me и др.).

Логика (v0.5.0):

DNS: state.dns_queries содержит домен сервиса

SNI: flow.sni содержит домен сервиса

HTTP Host: flow.http_host содержит домен сервиса

Direct IP: flow.dst_ip в config.ip_check_service_ips
(mapping IP → каноническое имя)

Все источники дают одинаковое value — findings сливаются
в один. Evidence содержит sources — список совпавших источников.

typosquatting.py
Подделки под известные бренды.

Логика (v0.4.0+):

Матчинг только по SLD (registered domain)

contains: бренд — подстрока в SLD, но не в начале и не
в конце с коротким префиксом

levenshtein: SLD близок к бренду при условиях: длина ≥ 5,
не короче бренда на 2+, первый и последний символы совпадают,
distance / max_len ≤ 0.25

Allowlist legitimate_brand_domains

Функции:

_registered_label(domain) — SLD

_check_squat(sld, brand, lev_threshold) — основная проверка

levenshtein(a, b) — редакторское расстояние

Известное ограничение: двухуровневые TLD (co.uk, com.au)
не поддержаны.

sni_mismatch.py
SNI без DNS-запроса.

Логика:

flow.sni не в dns_queries

Не в sni_mismatch_allowlist

Агрегация по SNI.

Известный долг: 73 findings на FIN-2015 — CDN без DNS в этом
же файле захвата. Не FP, но шумно.

brute_force.py
HTTP-перебор паролей к одному endpoint.

Логика (v0.4.0):

Много flows к одной (src_ip, dst_ip, dst_port)

Средний размер flow маленький (max_avg_packets: 20)

Много уникальных src_ports (min_unique_src_ports: 10)

URI-ratio: много разных URI → браузер

Rate: слишком редко (< 0.01 flow/s) → поллинг

Skip TLS: порты 443/8443 пропускаются

Login hint: HTTP без login-endpoint → браузер

Skip port 21: FTP обрабатывает FTPBruteForceDetector

ftp_brute_force.py
Словарный подбор паролей к FTP-серверу.

Логика:

Группировка flows по (src_ip, dst_ip, dst_port=21)

Порог flow_count >= 20

Порог unique_src_ports >= 20

Каждая попытка = новое TCP-соединение = новый src_port

Confidence: 0.95 при ≥ 100 flows, 0.85 при ≥ 50, 0.75 иначе.

Отличие от HTTP-brute_force: FTP-сессия = 1185 пакетов,
рубится brute_force_max_avg_packets: 20. Отдельный детектор
с отдельными порогами.

beaconing.py
Периодические обращения к C2 (heartbeat).

Логика (v0.7.0 — пороги переработаны):

Группировка flows по (src_ip, dst_ip, dst_port)

N ≥ beaconing_min_connections (20)

Длительность ≥ beaconing_min_duration_sec (600)

jitter = stddev(intervals) / mean(intervals) < 0.1

Средний размер flow < beaconing_max_avg_bytes (5000)

Rate: < beaconing_max_flows_per_minute (5.0)

Payload stddev ratio < 0.5

Multi-tenant filter: если через (src, dst_ip, dst_port)
идёт > 1 уникального SNI/Host — это shared CDN/edge, не C2
(Chrome открывает десятки соединений к одному edge, каждый
к разному домену; C2 использует ОДИН домен)

Mail polling filter: POP3/IMAP (110, 143, 993, 995)
исключаются — клиент дёргает ящик по таймеру, это дизайн

Skip internal dst: если dst приватный — не beaconing

Allowlist по SNI/Host (endswith, ~70 доменов)

Confidence: 0.85 при jitter 0.05, 0.6 при jitter = max_jitter_ratio.

Известный долг: требует windowing для медленных C2
(интервал > часа).

dns_tunneling.py
DNS-туннелирование (exfiltration через DNS).

Логика (v0.6.0):

Группировка по (src_ip, base_domain) — base = последние
2 уровня (attacker.com)

total_queries >= 50

long_qnames_count >= 20 — qname ≥ 50 символов

Allowlist dns_tunneling_allowlist (DoH)

Confidence: 0.9 при long_count ≥ 2×min_long, 0.7 иначе.

Отличие от DGA: DGA — короткие поддомены (10-15 символов),
Tunneling — длинные (>50).

lateral_movement.py
Признаки перемещения по внутренней сети.

Логика (v0.5.0):

Внутренний → внутренний трафик на порты удалённого управления
(445, 135, 139, 3389, 5985, 5986)

UA-маркер (WinRM, PsExec, Impacket, wmiexec, evil-winrm,
Ruby WinRM) — confidence 0.8

URI-маркер (/wsman, /cimv2, /root/cimv2, /wmi) — 0.8

Только порт — confidence 0.6, но требует ≥ 5 flows

Allowlist: lateral_movement_admin_srcs.

large_transfer.py
Аномально большой объём в одном flow.

Логика (v0.7.0 — direction):

Один FlowKey или пара (прямой + обратный) с суммой байт

100 МБ

include_reverse=True — суммирует оба направления

Exclude: large_transfer_excluded_hosts (Windows Update,
Apple CDN) и large_transfer_excluded_user_agents (BITS)

Агрегация по нормализованной паре frozenset({src, dst})

Direction = inbound/outbound/internal/external
(заполняет evidence.direction, evidence.bytes_in,
evidence.bytes_out)

Instance-level MITRE: T1041 (outbound), T1105 (inbound),
T1071.001 (internal)

Confidence: 0.85.

Не помечает роли victim/attacker в entities: статистический
сигнал, не роль. Шлюз, качающий 2 ГБ обновлений, не victim.

vulnerable_path.py
Обращения к уязвимым путям + скачивание опасных файлов +
детекция web-сканеров.

Логика (v0.4.0+):

Нормализация URI: urlsplit(uri).path, percent-decode,
lowercase

vulnerable_path: URI содержит config.vulnerable_paths

script_download: URI заканчивается на
config.suspicious_download_extensions

Две стратегии: individual (для одиночных) и web_scanner
(для ≥ 10 разных URI от одного (src, dst))

Класс: VulnerablePathDetector.

command_injection.py (v0.6.0)
RCE в HTTP URI и POST body.

Логика:

High-confidence паттерны: io.popen, os.execute, system(,
shell_exec(, subprocess.popen( — 1 совпадение достаточно

Medium: $(, backticks, cmd.exe, wget http — требуют
≥ 2 совпадений

Источники: state.http_objects (полные запросы) + flow.http_uri

Агрегация: ≥ 5 hit'ов с одного (src_ip, dst_ip) → один
finding с count вместо N individual

Класс: CommandInjectionDetector.

ja3_malware.py (v0.6.0)
Детектор известных malware-JA3 из config.ja3_known_malware.

Логика: flow.ja3 в map → finding с именем семейства
(Cobalt Strike, Tor, Dridex, Trickbot, Emotet).

Отдельно от ja3_known_tools: python-requests / go-http-client
не считаются malware, не дают finding.

Известный долг: браузерных JA3 в config нет — Chrome/Firefox
классифицируются как normal, ja3_ua_mismatch работает только
на tool/malware.

Слой contradictions pcap_triage/contradictions/ (v0.7.0)
Новый слой анализа. Не детекторы атак, а поиск несогласованностей
между источниками: одно утверждение о мире подтверждается одним
источником и опровергается другим.

__init__.py
Экспортирует run_all (алиас для registry.run_all).

base.py
Модель данных слоя.

Датаклассы:

python
@dataclass(frozen=True)
class Fact:
    source: str          # "dns" | "sni" | "http_host" | "ja3" | "arp" | "flow" | "finding"
    subject: str         # обычно IP
    predicate: str       # "victim_of" | "attacker_of" | "has_mac" |
                         # "sni" | "http_host" | "uses_ja3" | "uses_ua" |
                         # "session_asymmetry" | "protocol_on_port" |
                         # "direct_ip_connect" | "makes_dns_queries"
    value: str           # может быть "" для ролевых фактов
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
Константы: SEVERITY_WEIGHT.

Protocol: ContradictionRule — name, severity_base,
extract_facts(state, findings, config),
find_contradictions(facts).

facts.py
Извлечение фактов из state + findings. Синхронизирован с
aggregators/entities.py по полярности findings.

Функции:

extract_attack_facts(findings) — victim_of / attacker_of
из findings

extract_arp_facts(state) — has_mac из state.arp_macs

extract_tls_host_facts(state, config) — sni / http_host

extract_ja3_ua_facts(state, config) — uses_ja3 / uses_ua

extract_asymmetry_facts(state, config) — session_asymmetry

extract_protocol_on_port_facts(state, config) — protocol_on_port

extract_direct_ip_facts(state, config) — direct_ip_connect +
makes_dns_queries

Полярность findings (синхронизировать с entities.py):

_ATTACK_TYPES (src = attacker): brute_force, ftp_brute_force,
vulnerable_path, command_injection, port_scan, web_scanner,
lateral_movement

_VICTIM_SIGNAL_TYPES (src = victim): beaconing, dns_tunneling,
script_download, nxdomain_burst, ja3_malware, sni_without_dns,
dga_domain, cloud_tunnel, ip_check_service, typosquatting,
suspicious_port

large_transfer — по evidence.direction

Если правишь полярность в одном месте — правь в обоих.

registry.py
Реестр правил и точка входа.

Константы: RULES — 7 инстансов (см. ниже).

Функции:

run_all(state, findings, config) -> list[Contradiction] —
прогоняет все правила, возвращает конкатенацию

rules/ — 7 файлов
Файл	Класс	Правило	Severity base	Источник фактов
b_mac_ip_conflict.py	MacIpConflictRule	ARP-spoof: ≥ 2 MAC на одном IP	critical	state.arp_macs
c_sni_host_mismatch.py	SniHostMismatchRule	Domain fronting: SNI ≠ HTTP Host, разные SLD	high	flows (sni + http_host)
d_ja3_ua_mismatch.py	Ja3UaMismatchRule	JA3 tool + browser UA → мимикрия	high	flows (ja3 + ua)
e_reverse_asymmetry.py	ReverseAsymmetryRule	Пропорция сессии 10:1	medium	flows (сессии)
e_victim_makes_attack.py	VictimMakesAttackRule	Хост одновременно victim и attacker → pivot	critical	findings (роли)
f_port_service_mismatch.py	PortServiceMismatchRule	TLS на 22, HTTP на 445 → туннель	high	flows (protocol on port)
g_direct_ip_no_dns.py	DirectIpNoDnsRule	Клиент ходит на IP без DNS	medium	flows + dns_queries_by_src
Ключевые детали:

VictimMakesAttackRule (PIVOT): conf = min(v_conf, a_conf, 0.90),
tie-breaker на непустой value. Hint различает три случая по
timestamps. Одна Contradiction на subject.

MacIpConflictRule: severity по пересечению временных окон
(critical / high / medium для lease change).

ReverseAsymmetryRule: агрегация по subject, bulk-паттерн
(≥ 5 сессий) → severity low, conf × 0.7. Фикс FP на шлюзах
(CyberCampTask 192.168.1.1 давал 9 «эксфильтраций»).

DirectIpNoDnsRule: фильтр ≥ 3 уникальных dst или ≥ 10 портов
на один.

Порядок в pipeline: после _detect, до build_entities.
Используют findings как факты — до агрегатора, потому что
влияют на роли (pivot — не «жертва или атакующий», а «жертва +
атакующий»).

Слой integrations pcap_triage/integrations/ (v0.6.0)
Threat Intel. Не запускается в основном pipeline — только по
флагу --enrich. Требует сети.

base.py
Protocol Enricher, dataclass EnrichmentResult.

cache.py
EnrichmentCache — SQLite-кэш с TTL.

Путь: reports/.cache/enrichment.db (по умолчанию).

TTL: enrichment_cache_ttl_days (7).

rate_limit.py
TokenBucket — 5 req/sec.

shodan_internetdb.py
Shodan InternetDB. Без ключа.

abuseipdb.py
AbuseIPDB. Требует ABUSEIPDB_API_KEY в env.

enricher.py
EnricherOrchestrator + collect_iocs_from_findings.

Приватные IP не обогащаются.

pipeline.py
enrich_findings() — основной прогон

attach_enrichment_to_findings() — прикрепляет результаты

Универсально: работает и с dict, и с Finding.

Конфиг: enrichment_enabled_providers (shodan_internetdb,
abuseipdb, virustotal), enrichment_max_iocs: 100.
Слой агрегаторов pcap_triage/aggregators/
entities.py
Строит сущности из flow'ов, findings и contradictions.

Функции:

build_entities(state, findings, config, contradictions=None) -> Entities

_ips_from_finding(f) — извлечь IP + сторону из finding

_is_special_ip(ip) — multicast, broadcast, loopback

_touch_times(entity, ts) — обновить first_seen/last_seen

Датаклассы:

Entity — один IP: ip, is_internal, roles, first_seen,
last_seen, flows_out/in, bytes_out/in, unique_dsts/srcs,
sni_domains, dns_names, findings_indices, mac, hostname,
username, realm

Entities(internal, external)

Роли:

Роль	Когда
internal / external	Всегда
domain_controller	Много flows на 88/389/445 от разных внутренних src
attacker_candidate	attacker_tag из findings
victim_candidate	victim_tag из findings
c2_candidate	External с findings
gateway_candidate	Internal, много flows и уникальных dst
pivot	Rule victim_makes_attack сработало на IP
Роль pivot: ставится поверх victim_candidate, если для
IP есть contradiction с rule == "victim_makes_attack". Не заменяет
роль, а дополняет.

Duck-typing: contradictions принимаются через getattr(c, "rule")
и getattr(c, "subject") — модуль contradictions не импортируется
в entities.py, чтобы не плодить циклы.

Семантика тегов (синхронизировать с contradictions/facts.py):

Finding	src → tag	dst → tag
brute_force, ftp_brute_force	attacker_tag	victim_tag
vulnerable_path, web_scanner	attacker_tag	victim_tag
lateral_movement	attacker_tag	victim_tag
port_scan	attacker_tag	(не выделяется)
beaconing, script_download	victim_tag	attacker_tag
suspicious_port	victim_tag	attacker_tag
large_transfer	—	—
large_transfer не помечает роли: статистический сигнал — не
роль. Шлюз, качающий 2 ГБ обновлений, не victim.

Слой reporters pcap_triage/reporters/
json_reporter.py
JSON-отчёт. Сортированный json.dump — детерминизм: один pcap +
config → побитово одинаковый JSON.

Функции:

write_json(report, path)

write_markdown(report, path) — обёртка

Ключи отчёта: schema_version (0.3.0), provenance
(tool_version, pcap_path, pcap_sha256), summary (пакеты, flows,
findings, contradictions, uploaded/downloaded), entities,
findings (с mitre_techniques), contradictions, flows,
http, dns, http_objects, carved_files.

markdown_reporter.py
Markdown-отчёт для тикета или вики.

Функции:

render_markdown(report) -> str — общий рендер

_render_entities(entities) — секция сущностей

_render_http(http) — секция HTTP

_extract_iocs(findings) — извлечь IOC

_chain_for(findings) — TL;DR в порядке kill-chain

_mitre_for_finding(finding) — instance-level MITRE
приоритетнее type-map

_fmt_host(host) — IP-литералы в HTTP Host рендерятся как
<ip> (unknown host)

_fmt_bytes(n), _fmt_duration(s), _short(s, n) — утилиты

Секции отчёта:

Header: файл, sha256, инструмент

TL;DR — цепочка findings в порядке kill-chain, PIVOT первым

Timeline — хронология findings

Carved Files — метаданные payload'ов

Сводка — пакеты, flows, contradictions

Сущности: internal (MAC, hostname, username, realm, pivot)

Findings: таблица + instance-level MITRE

Противоречия — секция с фактами и resolution_hint

HTTP: hosts, URIs, user-agents

IOC: домены, IP, порты

Топ-10 flows

Kill-chain ordering (_CHAIN_ORDER):

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
flow_report.py
conn.log-стиль.

Функции:

build_flow_report(state, config, top_n) -> dict —
top_by_bytes, top_by_packets

build_dns_report(state, top_n) -> dict

build_http_report(state, top_n) -> dict

build_http_object_report(state, top_n) -> dict (v0.6.0)

GUI pcap_triage_gui/ (v0.1)
Отдельный пакет. Ядро pcap_triage/ не трогает — работает
через run_pipeline() в QThread.

Корень
Файл	Назначение
__init__.py	Версия GUI
__main__.py	python -m pcap_triage_gui
app.py	QApplication + showMaximized
main_window.py	QMainWindow, 5 вкладок, меню, Ctrl+O
theme.py	QSS-тема (тёмная) — в коде, не в .qss
_runtime_hook.py	PyInstaller hook для логов крашей (обрезка pcap-triage-error.log при размере)
QSS-файлов нет — вся тема генерируется theme.py.

views/ — 5 вкладок
Файл	Вкладка	Что делает
run_view.py	Прогон	drop zone, summary grid (6 плиток), Observations, Highlights, Contradictions, Findings
enrich_view.py	Обогащение	выбор IOC, статус, результаты
settings_view.py	Настройки	11 секций Config
history_view.py	История	список прогонов + HTML-рендер
roadmap_view.py	Развитие	roadmap проекта
widgets/ — переиспользуемые компоненты
Файл	Назначение
summary_grid.py	6 плиток: Пакеты, Flows, Findings, Противоречия, Uploaded, Downloaded
observations_panel.py	список observations
highlights_panel.py	highlights (важные findings)
contradictions_section.py	секция contradictions
findings_table.py	таблица findings
empty_states.py	пустые состояния (когда данных нет)
toast.py	всплывающие уведомления
dialogs/
Файл	Назначение
contradiction_dialog.py	детали contradiction с facts и hint
finding_dialog.py	детали finding с evidence и MITRE
workers/
QThread-обёртки — не блокируют UI.

Файл	Назначение
analysis_worker.py	run_pipeline() в фоне
enrichment_worker.py	enrich_findings() в фоне
Тесты tests/
## Тесты `tests/`

**25 файлов, 302 теста** (`pytest tests/ -q` — все зелёные).

| Группа | Файлов | Что покрывает |
|---|---|---|
| Парсеры | 2 | `test_tls_parse.py` (10), `test_http_parse.py` — **удалён**, `http_parse` без прямого покрытия |
| Экстракторы | 2 | HTTP (8), TLS (6) |
| HTTPObject / JA3 | 2 | `test_http_object.py` (12), `test_ja3.py` (8) |
| Reassembly | 1 | `test_reassembler.py` (9) |
| Детекторы (базовые) | 3 | `test_detectors.py` (41), `test_beaconing.py` (31), `test_brute_force.py` (9) |
| Детекторы (0.6.0) | 3 | `test_command_injection.py` (10), `test_dns_tunneling.py` (9), `test_file_carve.py` (9) |
| Contradictions | 7 | по 5 тестов на правило × 7 правил |
| Агрегаторы | 1 | `test_aggregators_entities.py` (10) |
| Enrichment | 4 | cache (9), shodan (11), abuseipdb (7), pipeline (4) |
| Регрессии | 1 | `test_regressions.py` — FP-регрессии из FIRST-2015, CyberCampTask, MTA |

**Ключевые файлы:**
- `test_detectors.py` — базовое поведение старых детекторов
- `test_beaconing.py` — BeaconingDetector (31 тест, расширен в 0.7.0)
- `test_victim_makes_attack.py` — pivot-правило
- `test_regressions.py` — FP-регрессии (сохранён)
- `test_reassembler.py` — TCPReassembler (9 тестов)

**Долг:** `http_parse.py` без прямых тестов после удаления мусорного
`test_http_parse.py`.

tools/ — dev-скрипты
Не часть пакета, не импортируются ядром. Запускаются вручную.

Файл	Назначение
diagnose.py	проверка C2-доменов в dns_queries
portscan_check.py	dst_port с одного src_ip к одному dst_ip
ssh_check.py	flows на порт 22 per src_ip
diag_nbns.py	разбор NBNS
diag_kerberos.py	разбор Kerberos AS-REQ/AS-REP
batch_analyze.py	батч-прогон по папке с pcap
make_test_pcap.py	генератор синтетического pcap
Известные проблемы в структуре
nxdomain_burst windowing — считает за весь файл, не по окну.
93 findings на FIN-2015, часть могут быть FP. Требует правки
CaptureState (time-bucketed counts).

sni_mismatch шумно — 73 findings на FIN-2015, CDN без DNS
в том же файле захвата. Не FP, но шумно. Решение — allowlist
по контексту.

beaconing требует windowing — для медленных C2
(интервал > часа). Сейчас работает только в пределах одной
сессии захвата.

victim_makes_attack зависит от beaconing/nxdomain_burst
как источника victim-факта. Если beaconing даёт FP — правило
сработает ложно. Решается через тюнинг beaconing allowlist.

DNS-ответы не парсятся — только запросы. Блокирует точный
direct_ip_no_dns и sni_host_mismatch через DNS.

TLS-сертификаты (CN, SAN) не парсятся — только SNI/JA3.
Блокирует cert_cn_sni_mismatch, self_signed_on_external.

JA3-хеши браузеров не в config — Chrome/Firefox
классифицируются как normal, ja3_ua_mismatch работает
только на tool/malware.

Двухуровневые TLD (co.uk, com.au) не поддержаны в SLD
для typosquatting.

TCP reassembly обрезает потоки > 1 МБ (per-flow limit).

IPv6 не поддержан в парсере.

Внутренний C2 (internal → internal зашифрованный) не
детектируется без HTTP/2 framing.

Timeline / kill-chain отсутствуют — contradictions дают
точки, но не цепочки.

Универсальный контракт Finding не зафиксирован — часть
полей остаётся в evidence со своими именами.

 

Связанные документы
## Связанные документы

- `README.md` — обзор, quick start, метрики.
- `ARCHITECTURE.md` — модель конвейера, слои, реестры, расширение.
- `CHANGELOG.md` — история версий.
- `TODO.md` — что дальше.
- `GUI_PROGRESS.md` — состояние GUI.
