# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).
Версии: семантическое версионирование (major.minor.patch).

## [Unreleased]

### В работе
- Ничего не начато.

### Запланировано
- Threat Intel enrichment (VirusTotal + SQLite-кэш, rate limit).
- FlowAggregator + BeaconingDetector.
- Windowing в CaptureState.
- StreamReassembler (TCP reassembly).
- HTTPObjectExtractor + FileCarve.
- Correlator (entity scoring, timeline).
- Streamlit / FastAPI обёртка.

### Известные проблемы
- `brute_force` даёт false positive на Google Safe Browsing и на
  LDAP-порт 389 (не исключены порты DC).
- `footprintdns.com` (Cisco Umbrella) — false positive в DGA.
- TCP reassembly отсутствует — Kerberos и большие HTTP читаются
  частично (первый сегмент).
- JA3/JA3S fingerprinting отсутствует.

## [0.3.0] — 2026-10-08

KerberosExtractor. MTA-упражнение закрыто на 5 из 5 (IP, MAC,
hostname, username, realm).

### Добавлено
- `extractors/kerberos.py` — извлечение username, realm, sname
  из Kerberos (AS-REQ/AS-REP/TGS-REQ/TGS-REP/AP-REQ).
- `kerberos_parse.py` — ASN.1 DER парсер Kerberos (RFC 4120).
  Lenient-режим для фрагментированных TCP-сообщений.
- `extractors/nbns.py` — hostname из NBNS (NetBIOS).
- `nbns_parse.py` — парсер NBNS (RFC 1002).
- `HostIdentityExtractor` — MAC из ARP.

### Изменено
- `HostIdentity` расширен полями `username`, `realm`.
- `Entity` расширен полем `realm`.
- `HostIdentityExtractor` — только ARP, fallback из Ethernet убран
  (в routed-сетях давал MAC шлюза на десятки IP).
- Семантика ролей — введены `attacker_tag` / `victim_tag`.
  `script_download` инвертирован: src = жертва, dst = источник.
- Markdown-рендер показывает MAC, hostname, username, realm.

### Исправлено
- Порядок блоков в `entities.py` — host identity перед ролями,
  иначе новые сущности теряли роль `internal`/`external`.
- NBNS: имя принадлежит инициатору (src_ip), не dst.

## [0.2.3] — 2026-10-07

VulnerablePathDetector + поддержка pcapng.

### Добавлено
- `detectors/vulnerable_path.py` — обращение к уязвимым путям
  (wp-login, .env, /.git) + скачивание скриптов (.ps1, .sh, .vbs).
- Автоопределение classic pcap / pcapng по magic bytes в
  `pipeline.py`. Fallback на scapy `PcapReader` для pcapng.
- Секция HTTP в Markdown-отчёте (hosts, URIs, user-agents).

### Исправлено
- Расширения скриптов убраны из `vulnerable_paths` —
  иначе они не попадали в `script_download`.

## [0.2.2] — 2026-10-07

HTTPExtractor + BruteForceDetector + direction summary.

### Добавлено
- `extractors/http.py` — Host, URI, Method, User-Agent.
- `http_parse.py` — ручной парсер HTTP-запросов.
- `detectors/brute_force.py` — перебор паролей к одному endpoint.
- `_summarize_direction` в `pipeline.py` — uploaded / downloaded /
  internal / external байты.
- Секция HTTP в JSON-отчёте.

### Изменено
- Top-flows показывают направление (`inbound`, `outbound`).

## [0.2.1] — 2026-10-07

Entities, direction, session_sni, Markdown v0.2.

### Добавлено
- `aggregators/entities.py` — `build_entities()`, `Entity`,
  `Entities`. Роли: `internal`, `external`, `gateway_candidate`,
  `victim_candidate`, `attacker_candidate`, `c2_candidate`.
- `net_utils.py` — `is_internal_ip`, `classify_direction`.
- `reporters/markdown_reporter.py` — секция «Сущности».
- `reporters/flow_report.py:build_dns_report`, `build_http_report`.
- Секция `entities` в JSON-отчёте.
- Секция DNS в JSON-отчёте.

### Изменено
- `CaptureState` расширен полями `dns_queries_by_src`,
  `host_identities`, `unsupported`.
- `FlowStats` расширен полем `initiated_by_src`.

## [0.2.0] — 2026-10-07

TLSExtractor + SNIMismatchDetector. CTF baseline чист.

### Добавлено
- `extractors/tls.py` — SNI из TLS ClientHello.
- `tls_parse.py` — ручной парсер ClientHello (без scapy).
- `detectors/sni_mismatch.py` — SNI без DNS, allowlist по суффиксу.

### Исправлено
- `dga_allowlist` — добавлены `cloudapp.azure.com`,
  `msedge.net`, `smartscreen.microsoft.com`.
- Склейка строк в `config.py` (две строки объединились без запятой).

## [0.1.1] — 2026-10-07

Raw parser. 39x ускорение.

### Изменено
- `parsers.py` — собственный парсер через `struct.unpack`,
  без scapy dissect.
- `pipeline.py` — `RawPcapReader` вместо `PcapReader` для classic
  pcap.

### Производительность
- 334 МБ pcap: **458 секунд → 12 секунд** (39x).
- Память: 106 МБ на 334 МБ файл.

### Исправлено
- Убран mDNS false positive: DNS-экстрактор теперь проверяет порт
  (только 53), не `haslayer(DNS)`.

## [0.1.0] — 2026-10-06

Initial snapshot. Первый рабочий pipeline.

### Добавлено
- CLI с интерактивным вводом пути.
- `config.py` — все настройки и пороги.
- `models.py` — `Finding`, `FlowKey`, `FlowStats`, `CaptureState`.
- `pipeline.py` — `run_pipeline()`.
- `cli.py` — точка входа.
- Экстракторы: `FlowExtractor`, `DNSExtractor`.
- Детекторы: DGA, SuspiciousPort, NXDOMAINBurst, CloudTunnel,
  IPCheckService, Typosquatting.
- JSON-отчёт с `provenance` (sha256 pcap, версия инструмента).
- Flow report в conn.log-стиле.
- `make_test_pcap.py` — генератор синтетического pcap.
- 24 unit-теста.
- Git репозиторий.

### Исправлено
- DGA не срабатывает на домены с дефисом
  (`safebrowsing-cache.google.com`).
- Имя отчёта сохраняет полный stem pcap, файлы не перезаписывают
  друг друга.

---

## Как читать changelog

**Major** (0 → 1) — несовместимые изменения. Пока не было ни одного.

**Minor** (0.1 → 0.2) — новая функциональность, старая совместима.

**Patch** (0.1.0 → 0.1.1) — исправления и производительность.

### Что считается major

- Удаление поля из JSON-схемы.
- Переименование существующего поля.
- Изменение контракта экстрактора или детектора.

### Что считается minor

- Новый экстрактор или детектор.
- Новое поле в JSON-схеме.
- Новая секция в Markdown-отчёте.

### Что считается patch

- Исправление false positive.
- Исправление бага в парсере.
- Оптимизация производительности без изменения API.