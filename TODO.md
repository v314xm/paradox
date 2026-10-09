# TODO

Состояние проекта: что сделано, что в работе, что дальше.

## Сделано

### Инфраструктура
- [x] CLI с интерактивным вводом пути
- [x] Git репозиторий + история коммитов
- [x] `pyproject.toml` + editable-установка
- [x] Raw parser (struct.unpack) + **39x ускорение**
- [x] Автоопределение classic pcap / pcapng
- [x] Прогресс-бар в парсинге
- [x] Детерминированный JSON (sort_keys, полный вторичный ключ)
- [x] Provenance: sha256 pcap, версия инструмента

### Экстракторы (7)
- [x] `flow.py` — 5-tuple, байты, timestamps, инициатор
- [x] `dns.py` — DNS-запросы, NXDOMAIN, по источнику
- [x] `host_identity.py` — MAC из ARP
- [x] `nbns.py` — hostname из NBNS (NetBIOS)
- [x] `kerberos.py` — username, realm, sname из Kerberos
- [x] `tls.py` — SNI из TLS ClientHello
- [x] `http.py` — Host, URI, Method, User-Agent

### Парсеры
- [x] `parsers.py` — Ethernet/VLAN/IPv4/TCP/UDP/ICMP/ARP
- [x] `tls_parse.py` — ClientHello (ручной, без scapy)
- [x] `http_parse.py` — HTTP-запросы
- [x] `nbns_parse.py` — NBNS (RFC 1002)
- [x] `kerberos_parse.py` — ASN.1 DER (RFC 4120), lenient к фрагментации

### Детекторы (10)
- [x] `dga.py` — энтропия label, allowlist CDN/cloud
- [x] `suspicious_port.py` — внешние порты, агрегация
- [x] `nxdomain_burst.py` — count по src IP
- [x] `cloud_tunnel.py` — trycloudflare, ngrok, serveo
- [x] `ip_check_service.py` — ip-api.com, ifconfig.me
- [x] `typosquatting.py` — contains + Levenshtein
- [x] `sni_mismatch.py` — SNI без DNS, allowlist по суффиксу
- [x] `brute_force.py` — перебор паролей
- [x] `vulnerable_path.py` — уязвимые пути в HTTP
- [x] `script_download.py` — .ps1/.sh/.vbs/.jar (встроен в vulnerable_path)

### Агрегация
- [x] `entities.py` — `build_entities`, `Entity`, `Entities`
- [x] Роли: `internal`, `external`, `domain_controller`,
      `victim_candidate`, `attacker_candidate`, `c2_candidate`,
      `gateway_candidate`
- [x] Профиль хоста: MAC, hostname, username, realm
- [x] Семантические теги `attacker_tag` / `victim_tag`
- [x] Направление трафика (uploaded/downloaded/internal)

### Отчёты
- [x] JSON с `schema_version` и `provenance`
- [x] Markdown для тикета
- [x] Flow report (conn.log-стиль)
- [x] DNS-секция в отчёте
- [x] HTTP-секция в отчёте
- [x] Секция «Сущности» с ролями и профилем

### Тесты
- [x] **106 тестов** в 9 файлах, все зелёные
- [x] Unit-тесты без scapy (кроме тестов экстракторов)
- [x] Регрессии на реальных данных (safebrowsing, MTA)

### Проверено на реальных pcap
- [x] MTA 2025-06-13 — **профиль жертвы 5 из 5**
- [x] CTF CyberCampTask (334 МБ) — brute_force + script_download
- [x] FIRST-2015 (3 pcap'а)
- [x] IDS-пакет (WordPress `/.env`)
- [x] MTA Simple C2 (сканер 78.153.140.203)

### Документация
- [x] README
- [x] ARCHITECTURE
- [x] MODULES
- [x] CHANGELOG
- [x] TODO

## В работе

Ничего не начато.

## Следующее (по приоритету)

### 1. Быстрые false positive (30 минут)

- [ ] `footprintdns.com` в `dga_allowlist` — Cisco Umbrella
      (легитимный DNS, но high-entropy labels)
- [ ] `brute_force` игнорирует порты DC (88, 389, 445, 3268, 636) —
      там «много коротких запросов» это норма для LDAP/Kerberos
- [ ] `brute_force` — ratio `unique_uris / flow_count`. Если у flow'ов
      много разных URI — это не подбор, а нормальная работа
      (Google Safe Browsing случай)

### 2. Kerberos TGS-REQ → sname (30 минут)

- [ ] Извлекать SPN из `[4]` (sname) для TGS-REQ. Пока не всегда
      срабатывает: cname вглубь, но sname не находим

### 3. Threat Intel enrichment (3-4 часа)

- [ ] `VTClient` — клиент VirusTotal API
- [ ] `SqliteCache` — кэш с TTL и negative cache
- [ ] `ThreatIntelDetector` — enrichment режим (только top-N
      сущностей, не весь трафик)
- [ ] Rate limit 4 req/min
- [ ] AbuseIPDB (опционально)

### 4. FlowAggregator + BeaconingDetector (3 часа)

- [ ] `FlowAggregator` — группировка flows по
      `(src_ip, dst_ip, dst_port)` со статистикой интервалов
- [ ] `suspicion_score` — композитный балл
- [ ] `BeaconingDetector` — регулярные C2-серии
- [ ] Секция `flow_groups` в JSON + топ-5 в Markdown

## Дальше (крупные фичи)

- [ ] **Windowing в CaptureState** — окна по времени для
      `nxdomain_burst`, FastFlux, объёмного exfil
- [ ] **StreamReassembler** (TCP reassembly) — для честного TLS/HTTP
      парсинга и полного Kerberos
- [ ] **JA3/JA3S fingerprints** — TLS-фингерпринт малвари
- [ ] **HTTPObjectExtractor** — сохранение тел POST/GET,
      sha256, magic bytes (для VT-проверки)
- [ ] **Correlator** — entity scoring + timeline
- [ ] **Timeline** — хронология инцидента (заражение → C2 →
      lateral movement → exfil)
- [ ] **LDAPExtractor** — для AD-сценариев
- [ ] **AD-детекторы**: Kerberoasting, DCSync, ADRecon,
      lateral movement
- [ ] **IncidentReportReporter** — шаблон для IR
- [ ] **IOCExportReporter** — STIX/TAXII, MISP, CSV
- [ ] **Streamlit / FastAPI обёртка** — веб-интерфейс

## Известные долги

### Производительность и память
- `timestamps` в `FlowStats` растут неограниченно. На 334 МБ —
  106 МБ RAM, но для гигабайтных файлов нужен Welford (онлайн
  mean/variance + reservoir sampling).

### Семантика
- `FlowKey` не нормализует направление. `SessionKey` есть, но не
  используется. Для exfiltration-детекторов понадобится.
- IPv6 не поддержан в парсере (только заглушка `proto="other"`).
- QinQ (двойной VLAN) не поддержан.

### Парсинг
- TLS ClientHello без reassembly — ~5% фрагментированных пропущены.
- Kerberos без reassembly — cname/sname из глубины сообщения
  теряются, если не попали в первый TCP-сегмент.
- HTTP без reassembly — крупные POST не разбираются полностью.

### Детекторы
- `nxdomain_burst` считает за весь файл, не по окну.
- `brute_force` false positive на Google Safe Browsing,
  LDAP-порт 389.
- `dga` false positive на Cisco Umbrella (`footprintdns.com`).
- `typosquatting` — contains-логика грубая, могут быть FP.
- `sni_mismatch` не различает DoH и domain fronting (оба дают
  один и тот же finding).

### Сущности
- Порог `dc_min_unique_srcs: 1` — может быть высок для крупных
  сетей (там реально много источников). Но 20 flows от одного
  клиента — тоже сигнал.
- `service_flows_in` считает только по `dst_port`, не по
  `initiator` (может быть ответ от DC).

### Отчёты
- Markdown не показывает секцию DNS (только в JSON).
- IOC не экспортируется в CSV/STIX.

## Что можно удалить

- `pcap_triage/extractors/extractors.py` — дубликат
  `extractors/http.py`. Не используется.
- `diag_nbns.py`, `diag_kerberos.py` — одноразовые диагностические
  скрипты. Можно удалить или вынести в `tools/`.

## Как обновлять этот файл

**Сделано** — при коммите новой фичи, перемести пункт из
«Следующее» в «Сделано».

**В работе** — то, над чем работаешь сейчас. Не больше 1-2 пунктов.

**Следующее** — приоритизированный список. Когда появляется новая
задача, вставь её в нужное место по приоритету.

**Дальше** — крупные фичи без конкретного срока.

**Известные долги** — то, что осознанно отложено. Не удалять —
это напоминание о компромиссах.



## Следующее (по приоритету)

### 1. Быстрые false positive (30 минут)

- [ ] `footprintdns.com` в `dga_allowlist` — Cisco Umbrella
- [ ] `brute_force` игнорирует порты DC (88, 389, 445, 3268, 636)
- [ ] `brute_force` — ratio `unique_uris / flow_count`

### 2. HTTP-детекторы (2 часа)

Мы видели эти сигналы в реальных pcap, но не детектируем:

- [ ] **`UnusualUserAgentDetector`** — UA не из браузерного списка
      в браузерной сети. Что ловить:
      - `WindowsPowerShell/*` — самая частая загрузка payload
      - `Wget/*`, `curl/*`, `Python-requests/*`
      - `Ruby WinRM Client` — lateral movement
      - `Microsoft NCSI`, `WSDAPI` — служебные, но в контексте
      - `Mozilla/4.0 (compatible; MSIE 7.0)` — старьё
      - Пустой UA на HTTP-запросах — malware
- [ ] **`WinRMLateralDetector`** — порт 5985/5986 + URI `/wsman`.
      В CTF было `POST /wsman` через `Ruby WinRM Client`.
- [ ] **`SuccessfulBruteforceLoginDetector`** — cross-finding:
      `brute_force` + URI с `loginok`/`success`/`dashboard`.
      В CTF было `POST /loginok.html` после 218 POST.

### 3. Kerberos TGS-REQ → sname (30 минут)

- [ ] Извлекать SPN из `[4]` (sname) для TGS-REQ

### 4. Threat Intel enrichment (3-4 часа)

- [ ] `VTClient` — клиент VirusTotal API
- [ ] `SqliteCache` — кэш с TTL и negative cache
- [ ] `ThreatIntelDetector` — enrichment режим
- [ ] Rate limit 4 req/min
- [ ] AbuseIPDB (опционально)

### 5. FlowAggregator + BeaconingDetector (3 часа)

- [ ] `FlowAggregator` — группировка flows по
      `(src_ip, dst_ip, dst_port)` со статистикой интервалов
- [ ] `suspicion_score` — композитный балл
- [ ] `BeaconingDetector` — регулярные C2-серии
- [ ] Секция `flow_groups` в JSON + топ-5 в Markdown

### 6. Новые детекторы (по одному в день)

- [ ] **`RareExternalIPDetector`** — 1-2 flow'а к внешнему IP.
      Beaconing не увидит, а сигнал есть. 30 минут.
- [ ] **`PortScanDetector`** — много исходящих к разным dst за
      короткое время.
- [ ] **`DNS tunneling`** — длинные поддомены, много запросов
      к одной зоне.
- [ ] **`FastFlux`** — один домен → много IP со временем.
- [ ] **`Exfiltration by volume`** — uploaded >> downloaded × 3.
- [ ] **`Long connections`** — сессии >30 минут.

### 7. Расширения отчёта (по 30 минут)

- [ ] **Protocol breakdown** в summary:
      by_l4 (tcp/udp/icmp), by_l7 (dns/tls/http).
- [ ] **Timeline buckets** в Markdown — разбивка по времени.
- [ ] **Malformed packets counter** — счётчик + источник.
- [ ] **`config_hash`** в provenance.
- [ ] **`unique_http_hosts`** в summary.
- [ ] **Секция DNS** в Markdown (сейчас только в JSON).

### 8. Роли хостов — уточнение

- [ ] **`scanner`** — internal, много исходящих к разным dst.
- [ ] **`server`** — internal с открытыми сервисными портами.
- [ ] **`target_candidate`** — на кого идёт атака.
- [ ] **`attacker_candidate`** — добавить правило для internal
      сканера, не только по findings.

### 9. Утилиты (по одной в день)

- [ ] **`pcap-triage follow`** — выгрузить TCP-поток в отдельный
      pcap. То, что аналитик делает в Wireshark после триажа.
- [ ] **`pcap-triage filter`** — фильтр по IP/порту/протоколу.
- [ ] **`pcap-triage diff`** — сравнить два pcap.
- [ ] **CSV IOC export** — для firewall/SIEM.