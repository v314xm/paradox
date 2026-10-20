# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).
Версии: семантическое версионирование (major.minor.patch).

## [Unreleased]

## [Unreleased]

#### Запланировано
- ObfuscationDetector (base64/eval в HTTP body).
- WebShellDetector (?cmd=, ?exec= в URI + POST body).
- IOC → STIX 2.1 экспорт.
- Windowing в CaptureState (fix nxdomain_burst долга,
  медленные beaconing).
- FlowAggregator + более сложные эвристики beaconing.
- VirusTotal enricher (третий провайдер, домены).
- DNS-ответы (A/AAAA/CNAME) — для sni_host_mismatch v2
  и direct_ip_no_dns v2.
- TLS certificate parser (CN, SAN).
- SMB2/DHCP/SSH/SMTP экстракторы.
- IPv6 поддержка в парсере.
- REST API + Web UI.

### Известные проблемы
- `nxdomain_burst` считает за весь файл, не по окну — 93 findings
  на FIN-2015, часть могут быть FP.
- `sni_without_dns` — 73 findings на FIN-2015, CDN без DNS в этом
  же файле захвата. Не FP, но шумно.
- `beaconing` чувствителен к jitter: реальные C2 с jitter > 0.1
  не ловятся. Может давать FP на CDN-трафик. Требует windowing.
- `victim_makes_attack` использует `beaconing`/`nxdomain_burst`
  как источник victim-факта. Если beaconing FP — правило сработает
  ложно. Решается через тюнинг beaconing allowlist.
- TCP reassembly обрезает потоки > 1 МБ (per-flow limit).
- Двухуровневые TLD (co.uk, com.au) не поддержаны в SLD.
- `http_parse.py` без прямых тестов.
- Внутренний C2 (internal → internal зашифрованный) не
  детектируется без HTTP/2 framing.
- Timeline / kill-chain отсутствуют как структура.
- Универсальный контракт Finding не зафиксирован.

## [0.7.0] — 2026-10-13

ContradictionDetector — новый слой анализа. Не детекторы атак, а
поиск несогласованностей между источниками: одно утверждение о мире
подтверждается одним источником и опровергается другим. 7 правил в
одной инфраструктуре. Тестов 265 → 302. Детекторов 17 (без изменений),
но появляется 18-й слой — `contradictions/`.

### Добавлено

**ContradictionDetector (каркас):**
- `paradox/contradictions/` — новый пакет:
  - `base.py` — `Fact`, `Contradiction`, `ContradictionRule` Protocol,
    `SEVERITY_WEIGHT`, `priority = severity × confidence`.
  - `facts.py` — извлечение фактов из state + findings:
    `extract_attack_facts`, `extract_arp_facts`,
    `extract_tls_host_facts`, `extract_ja3_ua_facts`,
    `extract_asymmetry_facts`, `extract_protocol_on_port_facts`,
    `extract_direct_ip_facts`.
  - `registry.py` — `RULES`, `run_all()`.
  - `rules/` — 7 файлов, по одному правилу.

**7 правил:**

1. **`victim_makes_attack` (PIVOT)** — хост одновременно victim и
   attacker. Severity `critical`, conf = min(v_conf, a_conf, 0.90).
   Tie-breaker на непустой value. Hint различает три случая по
   timestamps. На FIN-2015: 11 срабатываний. На CyberCampTask: 1
   (192.168.1.12, conf=0.8).

2. **`mac_ip_conflict` (ARP spoof)** — ≥2 MAC на одном IP в ARP-трафике.
   Severity по пересечению временных окон: `critical` (overlap + оба
   стабильны), `high` (overlap, один единичный), `medium` (без overlap,
   lease change). Новый экстрактор `extractors/arp_history.py` +
   `CaptureState.arp_macs`.

3. **`sni_host_mismatch` (domain fronting)** — SNI ≠ HTTP Host в одном
   flow, разные SLD. Severity `high`, conf × 0.9. Фильтр по
   `sni_mismatch_allowlist` + `beaconing_allowlist_suffixes`.

4. **`ja3_ua_mismatch` (спуфинг UA)** — `malware-JA3 + любой UA`
   (critical), `tool-JA3 + browser-UA` (high, мимикрия),
   `browser-JA3 + tool-UA` (medium). per-client, не per-flow.

5. **`reverse_asymmetry` (эксфильтрация)** — одна сторона сессии в
   разы больше другой. Ratio ≥ 10 + total ≥ 1 МБ. Агрегация по
   subject: bulk-паттерн (≥5 сессий) → severity `low`, conf × 0.7.

6. **`port_service_mismatch` (протокольный туннель)** — TLS на 22,
   HTTP на 445, TLS на 53. `config.port_service_allowed` — таблица
   порт → протоколы. STARTTLS узаконен.

7. **`direct_ip_no_dns` (hardcoded IP / прямой C2)** — клиент ходит
   на external IP без единого DNS-запроса в pcap. Severity `medium`,
   conf 0.7. Фильтр: ≥3 уникальных dst или ≥10 портов на один.

**Интеграция:**
- `pipeline.py` — `run_contradictions()` между `_detect` и
  `build_entities`. Схема отчёта: 0.2.0 → 0.3.0.
- `aggregators/entities.py` — `build_entities(..., contradictions=None)`.
  Роль `pivot` (поверх `victim_candidate`).
- `reporters/markdown_reporter.py` — секция «Противоречия», TL;DR
  с `**PIVOT:**` первым приоритетом.
- `models.py` — `CaptureState.arp_macs`.
- `config.py` — `port_service_allowed`,
  `reverse_asymmetry_min_total_bytes`, `reverse_asymmetry_min_ratio`,
  `reverse_asymmetry_high_ratio`.

### Изменено
- `LargeTransferDetector`: `direction` = inbound/outbound/internal/
  external (было single/pair). Разделены `bytes_in`/`bytes_out`.
  `mitre_techniques` заполняются инстансом по асимметрии:
  T1041 (outbound), T1105 (inbound), T1071.001 (internal).
- `aggregators/entities.py`: `large_transfer` больше не помечает роли
  `victim_tag`/`attacker_tag`. Статистический сигнал — не роль.
- `reporters/markdown_reporter.py`: TL;DR в порядке kill-chain
  (`_CHAIN_ORDER` + `_chain_for()`), не по confidence.
- `reporters/markdown_reporter.py`: `_mitre_for_finding()` — instance
  `mitre_techniques` приоритетнее type-map.
- `reporters/markdown_reporter.py`: `_fmt_host()` — IP-литералы в
  HTTP Host рендерятся как `<ip> (unknown host)`.
- `cli.py`: `-o` корректно работает с директориями (добавляет `.json`,
  создаёт родительскую директорию). Раньше `-o existing_dir` падал
  с `PermissionError`.
- `extractors/host_identity.py`: помимо `mac` пишет `mac_history`
  (MAC → first_ts, last_ts, count). Нужно правилу `mac_ip_conflict`.

### Исправлено
- **Односторонние факты в `victim_makes_attack`.** `port_scan` и
  `nxdomain_burst` имеют только `src_ip`. Реальный pivot на FIN-2015
  (192.168.0.53) пропускался. Фикс: `fact.value` допускает пустую
  строку.
- **Полярность `suspicious_port` в `facts.py`** была инвертирована
  относительно `entities.py`. Перенесён в `_VICTIM_SIGNAL_TYPES`.
- **Hint при отсутствии timestamps** содержал `(unknown)` дважды —
  `_describe(fact)` теперь показывает `finding_type`.
- **Рендер facts в Markdown** — пустой `value` отличается от
  отсутствующего, добавлен `[finding_type]` из evidence.
- **`nxdomain_count` в summary** — мёртвая ветка `hasattr(state,
  "nx_domain")`. Упрощено.
- **`_classify_ja3` дублировался** в `facts.py` — вторая версия
  перезаписывала первую. Оставлена одна с `"normal"`, фильтр по
  `_ACTIONABLE_JA3_FAMILIES`.
- **`reverse_asymmetry` FP на шлюзах** — 9 «эксфильтраций» на
  `192.168.1.1` в CyberCampTask. Агрегация по subject + bulk-паттерн
  (≥5 сессий) → severity `low`, conf × 0.7. Было 12, стало 3.
- **`make_session_key` / `is_internal_ip` не были импортированы**
  в `facts.py` — падало при первом запуске правила `reverse_asymmetry`.

### Производительность
- FIN-2015 полный батч (58 pcap, 9.5M пакетов, 4.7 ГБ): 583 сек.
  Overhead contradictions — минимальный, извлечение фактов линейно
  по findings + flows.
- CyberCampTask (627k пакетов): 18.6 сек.
- 2015-03-17 (329k пакетов): 18.4 сек.

### Тесты
- 265 → **302 passed** (+37):
  - `test_victim_makes_attack.py` — 5
  - `test_mac_ip_conflict.py` — 5
  - `test_sni_host_mismatch.py` — 5
  - `test_ja3_ua_mismatch.py` — 5
  - `test_reverse_asymmetry.py` — 5
  - `test_port_service_mismatch.py` — 5
  - `test_direct_ip_no_dns.py` — 5
  - +2 в `test_regressions.py` (совместимость `build_entities`
    с `contradictions=None`)

### Проверено на
- **FIRST-2015 полный батч** (58 pcap, 9.5M пакетов, 4.7 ГБ):
  - findings: **386** (0.5.0 → 349, Δ +37).
  - contradictions: **11** `victim_makes_attack`. Остальные 6
    правил — 0 срабатываний.
  - 0 ошибок, 0 исключений.
  - Топ findings: `nxdomain_burst` 93, `sni_without_dns` 73,
    `script_download` 50, `vulnerable_path` 46,
    `command_injection` 33.
- **FIRST-2015 2015-03-17** (329k пакетов, 50 findings):
  - contradictions: 3 `reverse_asymmetry` (`192.168.0.2` medium,
    `192.168.0.51` medium, `192.168.0.54` low).
- **CyberCampTask.pcap** (627k пакетов, 7 findings):
  - contradictions: 2 — `victim_makes_attack` на `192.168.1.12`
    (critical, 0.8) и `reverse_asymmetry` на `192.168.1.1`
    (low, 0.541 — bulk-паттерн шлюза).
  - Роль `pivot` в сущности `192.168.1.12`.

## [0.6.0] — 2026-10-12

Огромный скачок detection power. TCP Reassembly, HTTPObject, Command
Injection, FileCarve, JA3, Beaconing, DNS Tunneling, Enrichment.
Детекторов 15 → 17. Тестов 145 → 244.

### Добавлено

**TCP Reassembly:**
- `reassembler.py` — `TCPReassembler`. Склейка TCP-сегментов по
  sequence numbers. Буферизация по offset, обработка out-of-order и
  retransmit, finalize по FIN/RST. Лимиты памяти: 1 МБ per-flow,
  200 МБ total. 9 тестов.
- `CaptureState.tcp_streams: dict[FlowKey, bytes]` — заполняется
  после экстракции.

**HTTPObjectExtractor:**
- `http_object.py` — парсер полного HTTP-запроса/ответа из потока.
  Content-Length, chunked encoding, body limit 1 МБ.
- `extractors/http_object.py` — `HTTPObjectExtractor`. Двухпроходная
  сборка: pass 1 — requests (собираем URI), pass 2 — responses
  (пробрасываем URI из парного request через нормализованный
  pair-key).
- `CaptureState.http_objects: list[(FlowKey, HttpObject)]`.
- На CyberCampTask — **456 HTTP-объектов**.

**CommandInjectionDetector:**
- `detectors/command_injection.py` — RCE в URI и POST body.
  High-confidence паттерны: `io.popen`, `os.execute`, `system(`,
  `shell_exec(`, `subprocess.popen(`. Medium: `$(`, backticks,
  `cmd.exe`, `wget http` — требуют ≥ 2 совпадений.
- **На CyberCampTask обнаружена Lua RCE**: `io.popen("wget http://...")`
  в поле `username` POST `/loginok.html`. Confidence 0.9.
  10 тестов.

**FileCarve (metadata-only, безопасный):**
- `file_carve.py` — извлечение метаданных payload'ов из HTTP-ответов.
  **Body на диск НЕ пишется** по умолчанию. Сохраняются: sha256,
  размер, MIME, URI, первые 64 байта в hex.
- Определение расширения по Content-Type + magic bytes + URI-fallback.
- MIME `text/x-sh`, `text/x-powershell` и др.
- Если `file_carve_write_body=True` + `output_dir` — сохранит как
  `<sha256>.bin` (не `.exe`).
- На CyberCampTask: **`/ftp_update.sh`** — sha256
  `e83fb5b6...`, 77 байт. 9 тестов.

**JA3/JA3S fingerprinting:**
- `ja3.py` — парсер ClientHello/ServerHello, MD5-fingerprint
  по Salesforce-методу.
- `FlowStats.ja3`, `FlowStats.ja3s`.
- `detectors/ja3_malware.py` — детектор известных malware-JA3.
  В `config.ja3_known_malware` — 10 хешей (Cobalt Strike, Tor,
  Dridex, Trickbot, Emotet, python-requests, go-http-client).
- На CyberCampTask: 14 из 500 flows имеют ja3 (все — Chrome).
  8 тестов.

**BeaconingDetector:**
- `detectors/beaconing.py` — периодические C2-heartbeat. Признаки:
  ≥ 10 соединений к одной паре (src, dst, port), длительность
  ≥ 300 сек, jitter (stddev/mean) < 0.2, средний размер flow < 5 КБ.
  Confidence 0.6 при jitter 0.2, 0.85 при 0.05. 10 тестов.

**DNSTunnelingDetector:**
- `detectors/dns_tunneling.py` — длинные уникальные поддомены под
  одним базовым доменом. Пороги: qname ≥ 50 символов, ≥ 20 длинных
  уникальных, ≥ 50 запросов. Allowlist DoH. 9 тестов.

**Enrichment (Threat Intel):**
- `integrations/` — новый слой.
- `integrations/cache.py` — `EnrichmentCache`. SQLite-кэш с TTL.
- `integrations/rate_limit.py` — `TokenBucket`. 5 req/sec.
- `integrations/base.py` — `Enricher` Protocol, `EnrichmentResult`.
- `integrations/shodan_internetdb.py` — Shodan InternetDB (без ключа).
- `integrations/abuseipdb.py` — AbuseIPDB (нужен `ABUSEIPDB_API_KEY`
  в env).
- `integrations/enricher.py` — `EnricherOrchestrator`,
  `collect_iocs_from_findings`. Приватные IP не обогащаются.
- `integrations/pipeline.py` — `enrich_findings()`,
  `attach_enrichment_to_findings()`. Универсально работает и с dict,
  и с `Finding`.
- CLI флаг `--enrich`. Кэш в `reports/.cache/enrichment.db`.
- 28 тестов.

### Изменено
**Правило `mac_ip_conflict` (ARP spoof):**
- Срабатывает, когда на одном IP в ARP-трафике видны ≥ 2 MAC.
- Severity зависит от пересечения временных окон:
  - `critical` — окна пересекаются, оба MAC устойчивы (count ≥ 2).
  - `high` — пересечение есть, один MAC единичный.
  - `medium` — окна не пересекаются (lease change, смена NIC).
- Confidence = min(conf_a, conf_b) × {1.0, 0.85, 0.6} по severity.
- Новый экстрактор `extractors/arp_history.py` — параллельно
  с `host_identity`, ведёт полную историю `CaptureState.arp_macs`
  (IP → MAC → first_ts, last_ts, count). `host_identities.mac`
  хранит только последний MAC — теряет ARP-spoof.
- На FIN-2015 0 срабатываний: ARP-spoof в корпусе отсутствует.

**Правило `sni_host_mismatch` (domain fronting):**
- SNI в TLS ClientHello ≠ HTTP Host в том же flow.
- Фильтр: DoH/OCSP + CDN allowlist (уже в config).
- Severity: `high`. Confidence = min(conf_sni, conf_host) × 0.9.
- ОГРАНИЧЕНИЕ: SNI в TLS (443), Host в plaintext HTTP (80) — обычно
  разные соединения. Правило ловит узкий кейс. На FIN-2015 0
  срабатываний — внутри TLS Host не видим, шифр.

**Правило `ja3_ua_mismatch` (спуфинг TLS-стека / UA):**
- JA3 клиента несовместим с UA в HTTP.
- `malware-JA3 + любой UA` → critical.
- `tool-JA3 (python/go/curl) + browser-UA` → high (мимикрия).
- `browser-JA3 + tool-UA` → medium.
- ОГРАНИЧЕНИЕ: Chrome/Firefox JA3-хешей в config нет, все
  браузерные JA3 классифицируются как `normal` и не дают фактов.
  Правило срабатывает только на tool/malware JA3. На FIN-2015
  0 срабатываний — в корпусе нет известных tools с JA3.
- per-client (src_ip), не per-flow: JA3 и UA обычно на разных
  соединениях, внутри TLS UA не виден.

**Правило `reverse_asymmetry` (эксфильтрация / односторонний канал):**
- Одна сторона сессии передала в разы больше другой.
- Пороги: ratio ≥ 10 + total ≥ 1 МБ. Дополняет large_transfer:
  тот ловит absolute > 100 МБ, этот — пропорцию.
- Severity: `high` (ratio ≥ 25), `medium` (ratio ≥ 10),
  `low` (bulk-паттерн, ≥ 5 сессий с одного IP).
- Confidence = min(0.95, 0.5 + log10(ratio) × 0.15) × 0.7 для bulk.
- Агрегация по subject: одна Contradiction на IP, не на каждую
  сессию. Иначе шлюз (192.168.1.1) даёт 9 «эксфильтраций».
- На CyberCampTask: шлюз `192.168.1.1` → `low` (9 сессий, bulk).
- На FIN-2015 2015-03-17: 3 contradictions — `192.168.0.2` и
  `192.168.0.51` (`medium`), `192.168.0.54` (`low`).
- `pipeline.py` — reassembly в `_extract`, HTTPObject построение
  после finalize, FileCarve вызов снаружи HTTPObject try/except.
- `reporters/flow_report.py` — новая функция
  `build_http_object_report()`.
- `json_reporter` — секции `http_objects`, `carved_files`,
  `enrichment_stats`.
- `Config` — 13 новых полей: `tcp_reassembly_*`,
  `command_injection_*`, `file_carve_*`, `ja3_known_malware`,
  `beaconing_*`, `dns_tunneling_*`, `enrichment_*`.

### Исправлено
- **HTTPObject URI pairing**: response не имел URI (он в request).
  Двухпроходный парсинг с нормализованным pair-key.
- **FileCarve skip MIME**: `text/x-sh` не был в таблице, короткие
  loaders (< 1 КБ) обрезались по min_size 1024. Снижено до 64.
- **FileCarve вызов** был внутри `except HTTPObjectExtractor` —
  никогда не выполнялся, вынесен наружу.
- **Duplicates** в `DETECTORS` (FTPBruteForceDetector — 2 раза,
  BeaconingDetector — потерялся при рефакторинге).
- **`carve_files` на диск** — переписано на metadata-only.
  Запись body в `.bin` только по явному флагу.

### Производительность
- FIN-2015 полный батч: 58 файлов, 9.5M пакетов, 4.7 ГБ.
  Время с reassembly ~9-10 минут (было 8).
- CyberCampTask (627k пакетов): 19 сек (было 12 без reassembly).

### Тесты
- 145 → **244 passed** (+99 новых).
- Новые файлы: `test_reassembler.py` (9),
  `test_http_object.py` (12), `test_command_injection.py` (10),
  `test_file_carve.py` (9), `test_ja3.py` (8),
  `test_beaconing.py` (10), `test_dns_tunneling.py` (9),
  `test_enrichment_cache.py` (9), `test_shodan_enricher.py` (11),
  `test_abuseipdb.py` (7), `test_enrich_pipeline.py` (4).

### Проверено на
- **CyberCampTask.pcap** (627k пакетов):
  - findings: 7 (без изменений).
  - contradictions: 2 — `victim_makes_attack` на `192.168.1.12`
    (critical, 0.8) и `reverse_asymmetry` на `192.168.1.1`
    (low, 0.541, bulk-паттерн — шлюз).
  - Роль `pivot` в сущности `192.168.1.12`.
  - 
- **CyberCampTask.pcap** — 7 findings, **0 FP**:
  - `command_injection` — Lua RCE (io.popen + wget)
  - `brute_force` — HTTP /loginok.html
  - `ftp_brute_force` — 474 попытки
  - `lateral_movement` — Ruby WinRM Client
  - `large_transfer` — 126 MB rtbcdn.ru
  - `script_download` × 2
  - `carved_files` — `/ftp_update.sh` (77 байт, sha256)
  - `http_objects` — 456 объектов
  - `enrichment` — AbuseIPDB по `80.64.102.71` (RU, CJSC Rascom,
    abuseConfidenceScore=0)
- **FIRST-2015** — полный батч (результаты в batch_run.log).

## [0.5.1] — 2026-10-12

Фиксы после 0.5.0.

### Исправлено
- **LargeTransfer FP на Windows Update.** Большие .exe через BITS
  (100+ МБ) определялись как `large_transfer`. Добавлен exclude-list
  хостов (`*.windowsupdate.com`, `*.download.microsoft.com`,
  `*.update.microsoft.com`, `*.swcdn.apple.com`, `*.swdist.apple.com`,
  `*.mesu.apple.com`, `*.gdmf.apple.com`) и User-Agent
  (`Microsoft BITS`, `Microsoft-CryptoAPI`,
  `Microsoft-Delivery-Optimization`).
- **Дублирование на port 21.** Один FTP-скан давал три finding'а:
  `suspicious_port`, `brute_force`, `ftp_brute_force`. Порт 21 убран
  из `suspicious_ports` — теперь обрабатывается только
  `FTPBruteForceDetector`.
- **Дубликат `FTPBruteForceDetector()` в `DETECTORS`** — вызывался
  дважды, выдавал два одинаковых finding'а на один FTP-скан.

### Добавлено
- `config.large_transfer_excluded_hosts` — 7 записей.
- `config.large_transfer_excluded_user_agents` — 3 записи.
- 2 регрессионных теста на LargeTransfer exclude (Windows Update
  не finding, rtbcdn.ru finding).

### Тесты
- 145 → **146 passed**.

## [0.5.0] — 2026-10-09

Латеральное движение, большие трансферы, FTP-брутфорс, расширение
ip_check_service. 4 новых детектора (один — расширение). Тесты
127 → 145. Проверено на CyberCampTask: закрыто 4 из 5 гэпов
ручного анализа.

### Добавлено
- **`detectors/lateral_movement.py`** — `LateralMovementDetector`.
  Внутренний → внутренний трафик на порты удалённого управления
  (445 SMB, 135 RPC, 139 NetBIOS, 3389 RDP, 5985/5986 WinRM).
  Confidence 0.8 при срабатывании UA/URI-маркера (WinRM, PsExec,
  Impacket), 0.6 при «только порт» и ≥5 flows. Есть allowlist
  jump-хостов.
- **`detectors/large_transfer.py`** — `LargeTransferDetector`.
  Один flow (или пара прямого + обратного) с объёмом > 100 МБ.
  Режим `include_reverse=True` суммирует байты в оба направления.
- **`detectors/ftp_brute_force.py`** — `FTPBruteForceDetector`.
  Много flows к одному `(src, dst, 21)` с уникальными src_ports.
  Отдельный от HTTP-brute_force: FTP-сессия = 1185 пакетов,
  рубится `brute_force_max_avg_packets: 20`.
- `config.lateral_movement_ports`, `lateral_movement_min_flows_port_only`,
  `lateral_movement_ua_markers`, `lateral_movement_uri_markers`,
  `lateral_movement_admin_srcs`.
- `config.large_transfer_min_bytes`, `large_transfer_include_reverse`.
- `config.ftp_brute_force_min_flows`, `ftp_brute_force_min_unique_src_ports`.
- `config.ip_check_service_ips` — Mapping IP → каноническое имя
  сервиса (ip-api.com, ifconfig.me).
- `tests/test_regressions.py` расширен: +8 тестов на новые детекторы.

### Изменено
- **`IPCheckServiceDetector` расширен.** Матчит по четырём источникам:
  DNS, SNI, HTTP Host, прямой IP. Все источники дают одинаковое
  value (каноническое имя сервиса) — findings от DNS/SNI/direct_ip
  сливаются в один. Раньше матчил только `state.dns_queries`.
- `suspicious_port.py` — фильтр `scan_pairs` не пропускает пары,
  покрытые `PortScanDetector`.
- `config.private_networks` используется в `lateral_movement` для
  определения внутреннего src.

### Исправлено
- **LateralMovement FP** на FIN-2015: 2 находки на одиночный
  RDP (`192.168.0.1 → 192.168.0.51:3389`) и одиночный WinRM-HTTPS.
  Оба были «порт сам по себе». Фикс: порт без UA/URI требует ≥5 flows.
- **IPCheckServiceDetector direct_ip** давал finding с value = IP,
  параллельно с finding от SNI с value = домен. Два finding на одну
  активность. Фикс: mapping IP → имя сервиса.

### Проверено на
- **CyberCampTask.pcap** (627k пакетов): 6 findings, **0 FP**.
  Покрывает 4 из 5 гэпов ручного анализа:
  - `brute_force` `10.0.1.50 → 192.168.1.12:80` (HTTP `/loginok.html`)
  - `ftp_brute_force` `10.0.1.50 → 192.168.1.12:21` (474 попытки)
  - `lateral_movement` `192.168.1.12 → 192.168.1.1:5985` (Ruby WinRM)
  - `large_transfer` `192.168.1.1 ↔ 80.64.102.71` (126 MB, rtbcdn.ru)
  - `script_download` × 2 (`/ftp_update.sh`, `/watch_movie.ps1`)

  Не покрыт: внутренний C2 `10.0.1.247` (требует HTTPObjectExtractor).
- **FIRST-2015 2015-03-17** (329k пакетов): 0 FP новых детекторов.

### Тесты
- 127 → **145 passed**.

## [0.4.0] — 2026-10-09

Массовая чистка FP. 5872 findings → 343 на датасете FIRST-2015
(58 pcap'ов, 9.5M пакетов). Новый детектор port_scan. 127 тестов.

### Добавлено
- `detectors/port_scan.py` — `PortScanDetector`. Горизонтальное
  сканирование: один src_ip, много dst_ip, один dst_port.
  Агрегация: `(src_ip, dst_port) → set[dst_ip]`. Порог — 10 dsts,
  доля «тонких» целей ≥ 0.7.
- `tests/test_regressions.py` — 21 регрессионный тест на FP из
  FIRST-2015. Каждый тест привязан к конкретному домену/сценарию.
- Combo-сигнал `web_scanner` в `VulnerablePathDetector` —
  агрегирует 290 URI от одного сканера в 1 finding.
- `config.port_scan_excluded_ports: {80, 443}` — браузер неотличим
  от скана, исключаем полностью.
- `config.login_endpoint_hints` — список подстрок login-endpoint'ов
  для brute_force.
- `config.brute_force_skip_tls_ports: {443, 8443}`.
- DGA allowlist расширен: Stack Exchange, Live Messenger поддомены
  с цифрами, длинные блоги (acuityplatform, sourceforge,
  mysqlperformanceblog, hotpropertydesigns, thrivinglifestylez,
  hdwallpapersfactory, migratoryspecies).

### Изменено
- **`TyposquattingDetector` — переписан целиком.** Матчинг только
  по SLD (registered domain). Поддомены игнорируются.
  `googleads.g.doubleclick.net` → SLD `doubleclick`, не `google`.
  Levenshtein дополнительно ограничен: длина ≥ 5, разница длин ≤ 1,
  первый и последний символ совпадают, distance / max_len ≤ 0.25.
  Это убирает FP на `app.loadimpact.com`, `app.webinspector.com`,
  `behance.net` vs `binance`.
- **`VulnerablePathDetector` — агрегация по нормализованному URI.**
  `urlsplit(uri).path`, percent-decode, lowercase. `/WP-LOGIN.PHP?n=1`
  и `/wp-login.php?n=2` → один bucket. Две стратегии: individual
  (для одиночных) и web_scanner (для ≥ 10 разных URI от одного
  (src, dst)).
- **`BruteForceDetector` — три новых фильтра.** Skip TLS-портов
  (443/8443), login-hint в URI, корректный rate-check (был
  недостижимый код). Фильтры вынесены на верхний уровень цикла.
- **`SuspiciousPortDetector` — фильтр `scan_pairs`.** Пары
  `(src_ip, dst_port)`, покрытые `PortScanDetector`, пропускаются.
- `.js` исключён из `suspicious_download_extensions` — JavaScript
  есть на каждом сайте, тысячи FP.
- `dns.py` — strict ASCII decode qname. Не-ASCII → запрос
  отбрасывается целиком.

### Исправлено
- **Typosquatting FP (6 доменов):** googleads.g.doubleclick.net,
  googleads4.g.doubleclick.net, google-analytics.com,
  google-code-prettify.googlecode.com, app.loadimpact.com,
  app.webinspector.com.
- **Typosquatting FP после SLD-фикса (10 доменов):** id.google.se,
  www.google.se, rcp.c.appier.net, www.behance.net,
  aax.amazon-adsystem.com, c.amazon-adsystem.com, i.s-microsoft.com,
  www.googletagservices.com, www.microsoftstore.com,
  www.paypalobjects.com.
- **DGA FP:** stackoverflow.com, baymsgr*.*.gateway.messenger.live.com,
  acuityplatform.com, ibmsoftwaredelivery.sourceforge.net,
  windowsteamblog.com, mysqlperformanceblog.com.
- **Brute force FP:** 25 findings на 2015-03-17 (CDN-трафик на
  80/443 от браузера). Все ушли через TLS/login-фильтры.
- **Port scan FP:** 53 findings на порту 80 + 34 на 443 на 2015-04-07
  (браузер `192.168.0.53`, 675 сайтов за день). Ушли через
  `port_scan_excluded_ports`.
- **Port scan в `EXTRACTORS` вместо `DETECTORS`** — детектор
  вызывался per-packet, отсюда 304k "extractor errors".

### Производительность
- FIN-2015 полный батч: 58 файлов, 9.5M пакетов, 4.7 ГБ — 8 минут.
  Ни одной ошибки.
- findings: 5872 → 430 → **343** (после port_scan fix).

### Тесты
- 106 → 127 (+21 в test_regressions.py).

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
- Оптимизация производительности без изменения API .