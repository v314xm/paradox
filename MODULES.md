# Справочник модулей Paradox v1.8.0

Описание каждого файла: что делает, ключевые классы и функции,
связи с другими модулями. Для аналитика, разработчика и того, кто
хочет понять, куда смотреть при отладке.

**Версия ядра:** 1.8.0 (тег git: v1.8.0)
**Версия GUI:** 1.8.0 (тег git: v1.8.0)
**Строк кода:** ядро — 23 273, GUI — 19 705, всего 42 978
  (замер 2026-11-11)
**Тестов:** 1622 в 184 файлах (замер 2026-11-13)

---

## Содержание

1. [Корень пакета `paradox/`](#корень-пакета-paradox)
2. [Парсеры](#парсеры)
3. [Экстракторы (12 + post-extract)](#экстракторы)
4. [Детекторы (30)](#детекторы)
5. [Contradictions (13 правил)](#contradictions)
6. [Объяснения (`paradox/explain`)](#объяснения-paradoxexplain)
7. [Анализаторы](#анализаторы)
8. [Multi-pcap](#multi-pcap)
9. [Timeline / Kill-chain](#timeline)
10. [Интеграции (9 провайдеров)](#интеграции)
11. [Агрегаторы](#агрегаторы)
12. [Reporters](#reporters)
13. [GUI](#gui)
14. [Тесты](#тесты)
15. [Известные проблемы](#известные-проблемы)

---

## Корень пакета `paradox/`

| Файл | Строк | Что делает |
|---|---|---|
| `__init__.py` | 1 | `__version__ = "1.8.0"` |
| `__main__.py` | 4 | `python -m paradox` → `cli.main()` |
| `cli.py` | 230 | CLI: `-o`, `--enrich`, `--stix`, `--html`, `--plugins`, `--tls-keylog`, `--behavioral` |
| `config.py` | 1100 | Все настройки (frozen dataclass), валидация таблицей `_VALIDATION_RULES` |
| `models.py` | 460 | `Finding`, `FlowKey` (NamedTuple), `SessionKey`, `FlowStats`, `HostIdentity`, `CaptureState`, `packet_size_cv` |
| `ml/` | 200 | Чистый Python Isolation Forest (`isolation_forest.py`) — детерминированный поиск статистических выбросов, без scikit-learn |
| `host_profiler.py` | 220 | `HostProfiler`: базовая роль хоста по OUI MAC + наблюдение поведения (веб/SMB-сервер, сканер) |
| `pipeline/` | 860 | `run_pipeline` + `run_multi_pipeline` в фасаде; `extract` (пакетный цикл, экстракторы), `detect` (детекторы), `summarize` (L4/L7, направления, MITRE), `report` (`_build_report`), `errors` |
| `explain/` | 1 730 | Объяснения находок и противоречий человеческим языком: `model`, `catalog` (38 типов), `contradiction_catalog` (13 правил), `render` |
| `pcap_reader.py` | 120 | Минимальный читатель pcap: записи + sha256 за один проход, без scapy |
| `detector_plugins.py` | 126 | Загрузка пользовательских детекторов из `~/.paradox/plugins` |
| `multi_pcap.py` | 228 | `merge_capture_states(states)` — слияние N датасетов |
| `timeline.py` | 320 | `build_timeline`, `summarize_by_phase`, kill-chain |
| `domain_utils.py` | 151 | `split_domain`, `base_domain`, `registered_label`, `matches_suffix` |
| `net_utils.py` | 58 | `is_internal_ip`, `classify_direction` |
| `reassembler.py` | 211 | `TCPReassembler` — склейка TCP по seq |
| `file_carve.py` | 199 | Метаданные payload'ов (sha256, MIME, magic) |
| `payload_excerpt.py` | 134 | Выдержки тел в base64; части multipart с префиксом каждого файла |
| `payload_analysis.py` | 490 | Тип файла, хеши, строки, IOC, энтропия, вложенные PE/ELF/ZIP/PDF |
| `payload_deobfuscate.py` | 240 | Безопасные слои Base64/Gzip/Hex/PowerShell/JS/PHP |
| `payload_export.py` | 120 | Markdown-заметка кейса с редакцией секретов |
| `http_object.py` | 321 | `parse_http_request`, `iter_http_requests/responses` (keep-alive, pipelining); request-line режется общим `parse_request_line` |
| `http_parse.py` | 135 | `parse_request_line` (URI с пробелами), быстрый `parse_request` первого сегмента |
| `tls_cert.py` | 122 | `parse_certificate_from_stream` — X.509 из TLS |
| `ja3.py` | 218 | `parse_client_hello`, `parse_server_hello` (JA3/JA3S) |
| `kerberos_parse.py` | 291 | Kerberos AS/TGS/AP поверх общего `der.read_tlv` |
| `smb2_parse.py` | 261 | SMB2 из NetBIOS-рамки: команды, share/путь, диалекты, NTLMSSP Type 3 |
| `ldap_parse.py` | 238 | LDAP bind/search, текстовый рендер фильтра, атрибуты |
| `dcerpc_parse.py` | 262 | DCE/RPC: BIND (UUID/версия интерфейса), REQUEST (context id, opnum), AUTH3; DRSUAPI и naming context |
| `tls_keys.py` | 394 | SSLKEYLOGFILE, PRF/HKDF, AEAD-расшифровка записей TLS 1.2/1.3 |
| `tls_decrypt.py` | 368 | Handshake info (random, cipher suite), расшифровка пары потоков |
| `http2_parse.py` | 250 | HTTP/2-кадры, HEADERS/CONTINUATION/DATA, HPACK через `hpack` |
| `nbns_parse.py` | 179 | NBNS-имена |
| `x509_der.py` | 61 | Совместимый фасад; реализация — в `der.py` |
| `der.py` | 266 | Общий ASN.1 DER/TLV: `read_tlv` (strict / lenient), дерево `DerNode`, `as_int`/`as_oid`/`as_str`/`as_time` |
| `x509_cert.py` | 194 | `Certificate` из DER: CN, SAN, validity, self_signed |

### Секции `config.py`

- `cloud_tunnel_domains` (7), `ip_check_services` (8), `ip_check_service_ips` (4)
- `ja3_known_malware` (7), `ja3_known_tools` (3), `ja3s_known_malware` (по
  умолчанию пуст)
- `command_injection_patterns_high` / `_medium`, `command_injection_min_patterns=1`
- `http_body_decompress=True`, `http_body_max_decoded_bytes` = 8 МБ
- `payload_excerpt_enabled=True`, `payload_excerpt_bytes` = 64 КБ,
  `payload_multipart_file_bytes` = 64 КБ,
  `payload_multipart_total_bytes` = 256 КБ
- `http_binary_upload_min_posts=3`, `http_binary_upload_min_body_bytes=1024`,
  `http_text_content_types`, `http_binary_upload_ignored_content_types`
- `suspicious_ports` (8), `private_networks`, `dc_service_ports` (5)
- `beaconing_*` (min_conn=20, duration≥600 с, jitter<0.1, rate<5/min,
  mail_polling_ports, allowlist_suffixes — включая обновления Safe
  Browsing Chrome)
- `beaconing_slow_*` (3 соединения, ≥3600 с, jitter<0.15, rate<0.2/min)
- `dns_tunneling_*` (qname≥50, long≥20, queries≥50, allowlist DoH)
- `large_transfer_*` (100 МБ, `include_reverse`, excluded_hosts/uas)
- `port_service_allowed` (Mapping 17 портов → frozenset)
- `reverse_asymmetry_*` (1 МБ, ratio 10/25)
- `lateral_movement_*` (6 портов, UA/URI markers)
- `ssh_brute_force_min_flows=20`, `smtp_spam_min_recipients=50`
- `nxdomain_burst_*` (threshold=5, window=60, ratio=0.2)
- `typosquatting_*` (levenshtein threshold=2)
- `port_scan_min_distinct_dsts=10`, `port_scan_max_flows_per_dst=3`,
  `port_scan_excluded_ports={80,443}`
- `vulnerable_paths` (16), `suspicious_download_extensions` (11)
- `entities_top_n=50`, `gateway_min_flows=50`
- `enrichment_enabled_providers` (9), `enrichment_cache_ttl_days=7`
- `tcp_reassembly_enabled=True`, `file_carve_write_body=False`
- `plugins_enabled=False`, `plugins_dir=~/.paradox/plugins`
- `ioc_export_enabled=True`, `output_dir=reports/`

---

## Парсеры

### `parsers.py` (301 строка)
Быстрый разбор пакетов через `struct.unpack`. Без scapy. Поддержано: Ethernet, 802.1Q VLAN, IPv4 (фрагментация), TCP (seq/ack/flags), UDP, ICMP, ARP.

**Класс `PacketRecord`:** L2-L4 поля + payload + `ipv6_meta` (dict).

**`parse_packet(raw, ts)`** — один пакет за вызов, без dissect.

### `parsers_ipv6.py` (229 строк)
IPv6: заголовок + extension chain (HopByHop, Routing, Fragment, ESP, Auth, DestOptions, Mobility), извлечение src/dst портов.

**Мета в `ipv6_meta`:** `traffic_class`, `flow_label`, `hop_limit`, `extension_chain`, `is_fragment`, `fragment_id`, `final_next_header`.

---

## Экстракторы

Слой `paradox/extractors/`. Contract: `Extractor` Protocol — `name`, `layer`, `process(record, state)`.

**12 экстракторов**, у всех `layer = 0`. `FlowExtractor` обязательно первый (остальные ищут существующий flow).

| Файл | name | Что пишет |
|---|---|---|
| `flow.py` (51) | flow | `state.flows[key]` — packets, bytes, timestamps, `initiated_by_src` по первому SYN |
| `dns.py` (138) | dns | `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`, `dns_queries_by_src`, `dns_answers_by_name`, `dns_answers_by_ip`, `dns_nxdomain_ts_by_src`, `dns_query_ts_by_name/by_src` |
| `tls.py` (111) | tls | `flow.sni`, `flow.ja3`, `flow.ja3s`, `session_sni` (+ `run_post_extract` для склеенных потоков) |
| `http.py` (77) | http | `flow.http_{host,uri,method,user_agent}` — только запросы |
| `host_identity.py` (50) | host_identity | `host_identities[ip].mac` (только ARP, без eth_src) |
| `arp_history.py` (61) | arp_mac_history | `arp_macs[ip][mac] = [first, last, count]` |
| `dhcp.py` (180) | dhcp | MAC + hostname из BOOTP/DHCP |
| `ssh_banner.py` (104) | ssh_banner | `ssh_server_versions`, `ssh_client_versions`, `ssh_client_attempts` |
| `smtp.py` (130) | smtp | `smtp_helo_by_src`, `smtp_from_by_src`, `smtp_rcpt_by_src`, `smtp_mailer_by_src` |
| `nbns.py` (54) | nbns | `hostnames` из NBNS (suffix 0x00/0x20) |
| `kerberos.py` (77) | kerberos | `username` / `hostnames` / `realm` из cname |
| `ndp.py` (133) | ndp | `ndp_neighbors`, `ndp_routers`, `ndp_total` (`layer = 0`) |

### Post-extract (не в `EXTRACTORS`)

| Файл | Что делает |
|---|---|
| `extractors/http_object.py` (127) | `HTTPObjectExtractor.run_post_extract()` — обёртка над `paradox/http_object.py`, работает на `tcp_streams`. Разбирает ВСЕ сообщения потока (keep-alive), ответы матчатся с запросами по порядку; лимит `http_object_max_messages_per_stream` |
| `extractors/tls_cert.py` (71) | `TlsCertificateExtractor.run_post_extract()` → `state.tls_certs` |
| `extractors/smb2.py` (111) | `SMB2Extractor.run_post_extract()` — SMB2 из потоков 445: команды, диалекты, share, пути, статусы, объёмы READ/WRITE; NTLMSSP Type 3 → `host_identities` (user/domain/workstation) |
| `extractors/ldap.py` (118) | `LDAPExtractor.run_post_extract()` — bind/search из потоков 389/3268: bind DN, base DN, фильтры, атрибуты, коды результата; bind DN → `host_identities` |
| `extractors/dcerpc.py` (95) | `DCERPCExtractor.run_post_extract()` — DRSUAPI bind и opnum из всех потоков (SMB2 named pipe и `ncacn_ip_tcp`), naming context, учётка из AUTH3 |
| `extractors/http2.py` (231) | `HTTP2Extractor.run_post_extract()` — h2c и h2 из расшифрованного TLS: объекты в `http_objects`, pairing по stream id, счётчики расшифровки; расшифрованный HTTPS/1.1 тоже разбирается |
| `reassembler.py` | `TCPReassembler` — склейка TCP; лимиты 1 МБ/flow и 200 МБ total, потоки сверх лимита помечаются truncated |
| `tls.py` | `TLSExtractor.run_post_extract()` — SNI/JA3 из склеенных потоков (ClientHello бывает больше одного сегмента) |
| `file_carve.py` | `carve_files()` → `state.carved_files` |

Post-extract вызывается из `_extract` после чтения всех пакетов;
`state.tcp_streams` освобождаются сразу после него (до 200 МБ
сырых байтов не висят до конца прогона).

---

## Детекторы

Слой `paradox/detectors/`. Contract: `LocalDetector` — `name`, `run(state, config) -> list[Finding]`.

**30 детекторов.**

| Детектор | Строк | Что ищет |
|---|---|---|
| `dga.py` | 78 | Высокая энтропия label |
| `port_scan.py` | 99 | ≥10 уникальных dst, ≤3 flow на dst |
| `suspicious_port.py` | 106 | External dst на портах 4444/31337/… |
| `nxdomain_burst.py` | 142 | NXDOMAIN в скользящем окне (v0.9.0) |
| `cloud_tunnel.py` | 53 | trycloudflare/ngrok/serveo |
| `ip_check_service.py` | 113 | ip-api.com/ifconfig.me (DNS+SNI+Host+direct IP) |
| `typosquatting.py` | 157 | SLD близок к бренду (contains/levenshtein) |
| `sni_mismatch.py` | 122 | SNI без DNS-ответа |
| `rare_external_ip.py` | 134 | 1–2 соединения на внешний IP без DNS-ответа и без SNI/Host |
| `encoded_payload.py` | 180 | base64/hex в query/теле формы, декодируется в URL или домен |
| `long_connections.py` | 98 | TCP наружу >30 мин без имени на неслужебном порту |
| `ja3_malware.py` | 82 | JA3 из `ja3_known_malware` |
| `ja3s_malware.py` | 84 | JA3S из `ja3s_known_malware` (v1.4; по умолчанию список пуст) |
| `brute_force.py` | 227 | HTTP-перебор (src_ports, URI-ratio, rate) + `successful_bruteforce` |
| `ftp_brute_force.py` | 99 | 20+ flows на порт 21 |
| `beaconing.py` | 283 | Jitter + multi-tenant + payload stddev + slow-режим |
| `dns_tunneling.py` | 121 | Длинные уникальные qname под одним base |
| `ssh_brute_force.py` | 79 | 20+ SSH-баннеров на пару |
| `smtp_spam.py` | 118 | 50+ уникальных RCPT TO |
| `lateral_movement.py` | 144 | SMB/RDP/WinRM internal→internal |
| `large_transfer.py` | 252 | 100MB в одном flow (или паре) |
| `vulnerable_path.py` | 315 | wp-login/.env/.git + script_download + web_scanner |
| `command_injection.py` | 201 | RCE в HTTP URI/текстовом body |
| `http_binary_upload.py` | 155 | Серия бинарных POST'ов на внешний хост (C2/exfil) |
| `php_payload.py` | 189 | `<?php` в теле: `php_download` / `webshell_upload` |
| `webshell_markers.py` | 237 | Маркеры шеллов PHP/ASP/JSP + семейства WSO/b374k/c99/r57 → тип `webshell_signature` |
| `yara_detector.py` | 91 | YARA на carved_files (опционально) |
| `kerberoasting.py` | 78 | TGS-REQ к сервисным SPN: RC4 (etype 23) или 3+ SPN с одного хоста |
| `ad_recon.py` | 65 | Перечисление каталога: чувствительные LDAP-атрибуты по клиенту |
| `dcsync.py` | 73 | DRSUAPI `DsGetNCChanges` (opnum 3) в привязанном контексте |

**`_http_body.py` (193)** — общее для трёх детекторов: распаковка
`gzip`/`deflate` (в т.ч. по magic `1f 8b` без `content-encoding`),
критерий текстовости и `body_for_scan()`. Нужен `command_injection`
(не искать shell в бинаре, но видеть сжатый текст),
`php_payload` (сканировать скачанный/залитый файл) и
`http_binary_upload` (искать именно бинарь «на проводе»).

**`mitre_map.py` (65)** — `MITRE_MAP: dict[str, tuple[str, ...]]`. Instance-level `Finding.mitre_techniques` приоритетнее.

**`explainer.py` (56)** — `build_reasons(evidence)` для `Finding.confidence_reasons`.

### Пороги детекторов (важные)

- **beaconing:** min_conn=20, duration≥600s, jitter<0.1, avg_bytes<5000, rate<5/min, payload_var<0.5, multi-tenant filter (>1 SNI/Host = CDN), mail_ports={110,143,993,995}, skip_internal=True
- **beaconing slow (v1.4):** min_conn=3, duration≥3600s, jitter<0.15, rate<0.2/min, confidence 0.55–0.7, `evidence.mode="slow"`
- **http_binary_upload:** ≥3 POST'ов, body≥1KB, non-text body, outbound; skip ocsp-request и allowlist_suffixes
- **php_payload:** ответ 2xx, маркер `<?php` в первых 64 байтах (BOM/пробелы допускаются), HTML-ответы пропускаются, gzip/deflate распаковываются; заливка — POST/PUT/PATCH с `<?php` в первых 64 КБ тела
- **webshell_markers:** набор токенов целиком в первых 64 КБ; HTML-ответы и тела с printable < 0.6 пропускаются; confidence 0.85, известные семейства — 0.9
- **decompression:** gzip/x-gzip + deflate (zlib и raw), magic-сниффинг `1f 8b`; лимит `http_body_max_decoded_bytes` = 8 МБ; brotli/zstd не сканируются
- **nxdomain_burst:** threshold=5, window=60s, min_ratio=0.2
- **rare_external_ip:** 1–2 соединения (`rare_external_ip_max_connections`), IP нет в `dns_answers_by_ip`, нет SNI/Host, инфрапорты (53/67/68/123/137/138/853/1900/3702/5353/5355) исключены; без DNS-ответов в захвате молчит
- **encoded_payload:** значение ≥16 символов, base64 (std/urlsafe) или hex, декодируется в абсолютный URL/домен (`encoded_payload_min_value_len`, `encoded_payload_max_decoded_len`); тело — только `application/x-www-form-urlencoded` и не обрезанное; закодированный URL на тот же `Host` пропускается (форма `return=`)
- **long_connections:** TCP internal→external, SYN виден, ≥1800s, ≥5 пакетов, SNI/Host не из allowlist, порты SSH/почты/VPN/БД/RDP/VNC/прокси исключены
- **successful_bruteforce:** только вместе с `brute_force` на ту же пару; URI с `loginok`/`login_ok`/`/success`/`dashboard`; HTTP-статуса в FlowStats нет, confidence ≤0.85
- **dns_tunneling:** qname≥50, long≥20, queries≥50
- **large_transfer:** 100 MB, `large_transfer_include_reverse` — сумма обоих направлений
- **port_scan:** ≥10 уникальных dst, ≤3 flow на dst, excluded={80,443}

---

## Contradictions

Слой `paradox/contradictions/` — **v0.7.0+**, главная ценность Paradox. Не детекторы, а поиск несогласованности между источниками.

### Модель

**`Fact`** (frozen): `source`, `subject`, `predicate`, `value`, `ts`, `confidence`, `evidence`.

**`Contradiction`:** `rule`, `subject`, `facts`, `severity`, `confidence`, `likely_causes`, `resolution_hint`, `priority` (property = severity_weight × confidence).

**`ContradictionRule`** Protocol: `name`, `severity_base`, `extract_facts(state, findings, config)`, `find_contradictions(facts)`.

### `facts*.py` — факты по источникам

`facts.py` (59) — совместимый фасад; реализация в трёх модулях.
Правила вызывают нужный экстрактор, а не общий dispatcher:

- `facts_attack.py` (113) — `extract_attack_facts`
- `facts_net.py` (368) — `extract_arp_facts`, `extract_asymmetry_facts`, `extract_protocol_on_port_facts`, `extract_direct_ip_facts`
- `facts_tls.py` (399) — `extract_tls_host_facts`, `extract_ja3_ua_facts`, `extract_tls_cert_facts`
- `facts_role.py` (80) — `extract_role_facts` (`assigned_role`, `observed_behavior`)

- `extract_attack_facts(findings)` — `victim_of` / `attacker_of` (синхронизировано с `entities.py`)
- `extract_arp_facts(state)` — `has_mac` из `arp_macs`
- `extract_tls_host_facts(state, config)` — `sni`, `http_host` + CNAME-цепочка через `_collect_ips_for`
- `extract_ja3_ua_facts(state, config)` — `uses_ja3`, `uses_ua`
- `extract_asymmetry_facts(state, config)` — `session_asymmetry` (через `make_session_key`)
- `extract_protocol_on_port_facts(state, config)` — `protocol_on_port` (tls/http)
- `extract_direct_ip_facts(state, config)` — `direct_ip_connect`, `makes_dns_queries`
- `extract_tls_cert_facts(state)` — `tls_cert` из `state.tls_certs`
- `extract_role_facts(state, config)` — `assigned_role` (по OUI MAC) + `observed_behavior` (веб/SMB-сервер, сканер)

### `registry.py` (110) — 13 правил

| Правило | severity_base | Источник | Что ищет |
|---|---|---|---|
| `SniWithoutDnsRule` (95) | medium | sni | SNI без DNS-ответа |
| `DnsAnswerMismatchRule` (114) | medium | sni | SNI ≠ резолвнутый IP |
| `SniCertMismatchRule` (93) | medium | tls_cert | SNI ≠ CN/SAN сертификата |
| `SelfSignedCertRule` (71) | medium | tls_cert | issuer == subject |
| `ExpiredCertRule` (76) | low | tls_cert | not_after < ts flow |
| `VictimMakesAttackRule` (149) | **critical** | findings | X — victim_of(A) и attacker_of(B) → **pivot** |
| `MacIpConflictRule` (138) | **critical** | arp | ≥2 MAC на одном IP (spoof/lease) |
| `SniHostMismatchRule` (134) | high | flows | SNI ≠ Host (domain fronting) |
| `Ja3UaMismatchRule` (144) | high | flows | tool-JA3 + browser-UA → мимикрия |
| `ReverseAsymmetryRule` (185) | medium | flows | session ratio ≥10 (bulk → low) |
| `PortServiceMismatchRule` (166) | high | flows | TLS на 22 / HTTP на 445 → туннель |
| `DirectIpNoDnsRule` (129) | medium | flows | IP без DNS, ≥3 dst или ≥10 flows к одному dst |
| `RoleDeviationRule` (210) | high | role | поведение противоречит базовой роли по OUI (WS→webserver critical, server→scanner high) |

**`run_all(state, findings, config, rules=None)`** — прогон,
сортировка по (severity, -confidence, subject). Упавшее правило
считается в `extractor_errors["rule:<name>"]`, остальные работают.

### Полярность findings (синхронизировать с `entities.py`)

- `_ATTACK_TYPES` → src=attacker: `brute_force`, `ftp_brute_force`, `ssh_brute_force`, `vulnerable_path`, `command_injection`, `port_scan`, `web_scanner`, `lateral_movement`
- `_VICTIM_SIGNAL_TYPES` → src=victim: `beaconing`, `dns_tunneling`, `script_download`, `nxdomain_burst`, `ja3_malware`, `sni_without_dns`, `dga_domain`, `cloud_tunnel`, `ip_check_service`, `typosquatting`, `suspicious_port`, `smtp_spam`
- `large_transfer` — по `evidence.direction`

**Если правишь полярность — правь в обоих местах** (вынос в
`taxonomy.py` — в TODO.md).

---

## Объяснения (`paradox/explain`)

Человеческое объяснение находки и противоречия: что произошло, почему это
важно, куда смотреть дальше, где детектор может ошибаться и как сказать
то же самое новичку. Строится в ядре, а не в GUI: один и тот же текст
идёт в JSON-отчёт, модалку находки и Markdown. Иначе появятся три версии,
которые разойдутся — как уже было с internal/external IP до `ip_scope()`.

| Файл | Строк | Что делает |
|---|---|---|
| `model.py` | 107 | `Explanation` (`headline`, `why`, `next_steps`, `alternatives`, `confidence_note`, `beginner`, `phase`, `techniques`), `to_dict`/`from_dict`, `to_markdown` (копирование и будущий раздел отчёта) |
| `catalog.py` | 991 | Шаблоны для 37 типов из `taxonomy.SEVERITY_BY_TYPE`; пороги, направление и ключи evidence сверены с кодом детекторов |
| `contradiction_catalog.py` | 302 | Шаблоны для 12 правил: «почему важно», пивоты, «новичку». «Что произошло» берётся из `resolution_hint` правила, альтернативы — из `likely_causes`. Тексты верны при любом направлении перекоса |
| `render.py` | 144 | Подстановки `{key}` (поля находки + скалярные ключи `evidence`), разряды больших чисел, русские метки `direction`/`kind`, метки фаз, шкала уверенности |
| `__init__.py` | 163 | `explain_finding`, `explain_contradiction`, `explanation_for` (строка отчёта или расчёт на месте для старых отчётов); fallback для типов плагинов |

Отчёт: `pipeline/report.py` (`_explained`) добавляет ключ `explanation` к
каждой находке и каждому противоречию. Ошибка объяснения не валит отчёт —
считается в `extractor_errors["explain:<finding|contradiction>"]`.

Страж покрытия — `tests/test_explain.py`: новый тип finding или правило
без объяснения валит прогон так же, как отсутствие MITRE-маппинга.

---

## Анализаторы

Слой `paradox/analyzers/` — v1.0.0/v1.2.0.

### `behavioral_analyzer.py` (410) — **v1.8.0**

Поведенческий ML-слой: Isolation Forest над признаками сессий и профилями хостов.

**Классы:** `BehavioralAnalyzer`.

- **`score_sessions(state, config)`** — статистические выбросы по двунаправленным сессиям (объём, темп, асимметрия, `payload_cv`, `gap_cv`).
- **`score_hosts(state, config)`** — хосты с аномальным профилем → находки `host_behavior_anomaly`.
- **`corroborate(findings, state, config)`** — аннотирует rule-находки `behavioral_score`/`behavioral_corroborated`.

По умолчанию выключен (`behavioral_enabled=False`), включается `--behavioral`. Сессионный слой находок не создаёт — только усиливает существующие и помечает хосты; `contamination` откалиброван (0.02) на трёх эталонах.

### `attack_graph.py` (391) — **v1.2.0**

Directed graph атаки из findings + contradictions. Узлы = IP, рёбра = findings с (src, dst), пути = BFS от entry к impact.

**Классы:** `AttackNode`, `AttackEdge`, `AttackPath`, `AttackGraph`.

**`build_attack_graph(findings, config, entities, contradictions, max_paths=10, max_depth=6)`**

- Entry: внутренние с ролью из `ENTRY_ROLES` или (external→internal в фазе из `ENTRY_PHASES`)
- Impact: внешние с ролью из `IMPACT_ROLES` или фаза из `IMPACT_PHASES`
- Pivot: `taxonomy.pivot_subjects(contradictions)` — тот же помощник, что у `entities`
- `_PHASE_OF_TYPE` маппинг тип → фаза kill-chain

Ошибка сборки не валит прогон: в отчёте остаётся пустой граф.

### `absence.py` (53)
`analyze_absence(state)` — DNS без ответа, TCP без обратного flow.

### `counterfactual.py` (77)
`evaluate_what_if(report, exclude_ips, exclude_domains)` — What-If: что останется, если убрать.

### `ndp.py` (46)
`analyze_ndp(packets)` — NDP-статистика (neighbors, routers).

### `story.py` (65)
`build_host_story(report, target_ip)` — хронология событий для IP.

---

## Multi-pcap

### `multi_pcap.py` (228) — **v1.2.0**

**`merge_capture_states(states: list[CaptureState]) -> CaptureState`**

Слияние: Counter.update, dict update с dedup, sum FlowStats по FlowKey, extend списков, min(first_ts)/max(last_ts). С v1.6.0 сливаются и агрегаты волны 4: SMB2/LDAP, Kerberos TGS, DCE/RPC (bind, opnum, naming context), HTTP/2 и счётчики расшифровки TLS, а также объединение `ldap_sensitive_attrs_by_src`.

Байты TCP одного 5-tuple из разных файлов не склеиваются: коллизия
считается в `extractor_errors["multi_pcap_stream_conflict"]` —
поток на стыке файлов был бы выдуманным. Post-extract уже отработал
внутри каждого файла, поэтому `http_objects`, `tls_certs` и
`carved_files` просто складываются списками.

Не трогает `run_pipeline`, вызывается из `run_multi_pipeline` (append-only в `pipeline/`).

---

## Timeline

### `timeline.py` (320) — **v1.2.0**

Kill-chain reconstruction из findings + contradictions + carved_files.

**`TimelineEvent`:** `ts`, `kind` (finding/contradiction/carved_file), `type`, `subject`, `severity`, `confidence`, `phase`, `chain_order`, `description`, `mitre_id`, `ref_id`.

**`_PHASE_BY_TYPE`** — тип → фаза (recon/initial_access/execution/persistence/lateral_movement/c2/exfiltration/impact/other).

**`_PHASE_ORDER`** — численный порядок фаз (recon=10 … impact=80, other=999).

**`build_timeline(findings, contradictions, carved_files)`** — сортировка по (ts, chain_order, subject, type, kind). Детерминированно.

**`summarize_by_phase(events)`** — группировка.

---

## Интеграции

Слой `paradox/integrations/` — Threat Intel, только `--enrich`, требует сети.

| Файл | Строк | Ключ | IOC-типы |
|---|---|---|---|
| `base.py` | 53 | — | `Enricher` Protocol, `EnrichmentResult` |
| `base_enricher.py` | 215 | — | Базовый класс, HTTP-клиент, error handling |
| `cache.py` | 155 | — | SQLite-кэш с TTL |
| `rate_limit.py` | 61 | — | `TokenBucket` |
| `shodan_internetdb.py` | 116 | без | ip |
| `abuseipdb.py` | 128 | `ABUSEIPDB_API_KEY` | ip |
| `virustotal.py` | 47 | `VIRUSTOTAL_API_KEY` | ip/domain/hash |
| `greynoise.py` | 20 | без | ip |
| `alienvault_otx.py` | 24 | без | ip/domain/hash |
| `urlscan.py` | 36 | без | domain/url |
| `urlhaus.py` | 51 | `ABUSECH_AUTH_KEY` | domain/url |
| `malwarebazaar.py` | 39 | `ABUSECH_AUTH_KEY` | hash |
| `threatfox.py` | 40 | `ABUSECH_AUTH_KEY` | ip/domain/hash |
| `enricher.py` | 198 | — | `EnricherOrchestrator`, `collect_iocs_from_findings` |
| `pipeline.py` | 144 | — | `enrich_findings`, `attach_enrichment_to_findings` |
| `registry.py` | 42 | — | `REGISTRY` (9 провайдеров) |

Приватные IP не обогащаются (`_is_private_ip` + CGNAT 100.64/10).

---

## Агрегаторы

### `entities.py` (471) — **v0.3.0+**

Один IP = одна Entity (вместо N flow-строк).

**`Entity`:** ip, is_internal, roles, first/last_seen, flows_in/out, bytes_in/out, unique_dsts/srcs, sni_domains, dns_names, service_flows_in, findings_indices, mac, hostname, username, realm.

**Роли:**
- `internal` / `external` — всегда
- `domain_controller` — много flows на 88/389/445
- `attacker_candidate` — attacker_tag
- `victim_candidate` — victim_tag
- `c2_candidate` — external с findings
- `gateway_candidate` — internal, много flows + dst
- `pivot` — **поверх** victim_candidate (из `victim_makes_attack`)

**Duck-typing для contradictions** — через `getattr(c, "rule")`, без импорта (циклы).

**Семантика ролей** синхронизирована с `contradictions/facts_attack.py`.

---

## Reporters

| Файл | Строк | Что делает |
|---|---|---|
| `json_reporter.py` | 20 | `write_json` (sort_keys для детерминизма), `write_markdown` |
| `markdown/` | 996 | `render_markdown` — TL;DR, таймлайн, carved, сводка, противоречия, findings, сущности, HTTP, IOC, топ-10 flows. Модули: `document`, `tldr`, `timeline`, `sections`, `format`, `mitre`, `iocs` |
| `flow_report.py` | 234 | `build_flow_report`, `build_dns_report`, `build_http_report`, `build_http_object_report` |
| `ioc_reporter.py` | 371 | **v1.0.0** — `build_ioc_report`, `write_ioc_files` (txt/csv/json/suricata/queries) |
| `html_reporter.py` | 338 | **v1.5.0** — `render_html`, `write_html` — самодостаточный HTML (печать в PDF), экранирование значений |
| `stix_reporter.py` | 153 | **v1.5.0** — `build_stix_bundle`, `render_stix_json`, `write_stix` — STIX 2.1, детерминированные UUIDv5; используется CLI (`--stix`) и GUI |

`run_pipeline` сам файлы не пишет (кроме IOC и carved): flow-отчёты
собираются внутри pipeline, JSON/Markdown/HTML/STIX пишут CLI или GUI.

**`CHAIN_ORDER`** в `paradox/taxonomy.py` — порядок findings в TL;DR (pivot=5, web_scanner=10 … large_transfer=110).

**IOC reporter** — `_looks_like_ip` через `ipaddress` (IPv4+IPv6), SID база 9000000, KQL+Splunk queries. IPv6-путь тестами не покрыт.

---

## GUI

Пакет `paradox_gui/` — **17 388 строк**. Не трогает ядро, вызывает `run_pipeline`/`run_multi_pipeline` в QThread.

### Корень

| Файл | Строк | Что делает |
|---|---|---|
| `__main__.py` | 26 | Патчит `sys.stdout/stderr` на devnull (PyInstaller --windowed) |
| `app.py` | 92 | `QApplication` + splash + main window |
| `main_window.py` | 23 | Совместимый фасад `paradox_gui/window/` |
| `window/` | 995 | Главное окно: `window` (каркас, вкладки, статус-бар), `menus`, `actions`, `export`, `shortcuts` |
| `theme/` | 7 файлов | QSS-тема: `palette`, `qss_global`, `qss_widgets`, `qss`, `assets`, `apply` |
| `splash.py` | 161 | **v1.2.0** — Splash screen с прогресс-баром |
| `logo.py` | 110 | **v1.2.0** — `render_logo`, `get_app_icon`, `logo_label` |
| `_runtime_hook.py` | 90 | PyInstaller: faulthandler → `Paradox-error.log` |
| `storage.py` | 154 | SQLite-история (`%APPDATA%/Paradox/history.db`) |
| `settings_store.py` | 124 | JSON-settings с атомарной записью |
| `settings_rehydrate.py` | 70 | Восстановление типов (Path, frozenset) из JSON |
| `secrets_store.py` | 153 | Keyring → session → env (fallback) |
| `config_builder.py` | 50 | `build_config_with_overrides(overrides)` |
| `profiles.py` | 96 | Профили: default / ctf / corporate |
| `detector_help.py` | 95 | Tooltips детекторов |
| `field_help.py` | 230 | Tooltips полей Config |
| `contradiction_help.py` | 49 | Tooltips правил |
| `ioc_utils.py` | 81 | `detect_ioc_type`, `provider_link` |
| `formatting.py` | 20 | `fmt_bytes` / `fmt_count` — единое форматирование чисел в GUI |
| `payload_decode.py` | 152 | Цепочка URL → Base64 → Gzip/Deflate; `Variant.label` для деобфускации |
| `payload_highlighter.py` | 158 | Язык по содержимому, sinks/источники |
| `payload_preview.py` | 221 | Санитайзер разметки для статического предпросмотра |

### i18n — **v1.5.0**

| Файл | Строк | Что делает |
|---|---|---|
| `i18n/__init__.py` | 122 | `tr()`, `set_language`, `get_language`, `validate_translations`; fallback текущий → en → ru → сам ключ |
| `i18n/_ru.py` | 981 | Русские строки (дефолт) |
| `i18n/_en.py` | 981 | Английские строки |

Ключи плоские dot-нотации (`tab.run`, `menu.file.open`), подстановка
через `str.format()`. Склонений нет. Неизвестный язык —
предупреждение и no-op.

### Views — 9 вкладок

| Файл | Строк | Вкладка |
|---|---|---|
| `run_view.py` | 742 | **Прогон** — drop zone, summary, findings, правая колонка действий («Граф связей/атаки/Файлы/What-If», переходы в «Код инжекта» и «Обогащение») |
| `history_view.py` | 588 | **История** — список прогонов + HTML-превью |
| `payload_view.py` | 1372 | **Код инжекта** — поиск, hex-страницы, части multipart, деобфускация, инспектор, экспорт |
| `enrich_view.py` | 620 | **Обогащение** — IOC-выбор + результаты |
| `settings/` | 2611 | **Настройки** — 13 секций; `view.py` (679) + `pages/*` по странице, `builders`, `parsers`, `constants` |
| `ipv6_view.py` | 126 | **IPv6** — NDP + потоки |
| `timeline_view.py` | 259 | **Таймлайн** — kill-chain tree |
| `export_view.py` | 163 | **Экспорт** — CSV/STIX/HTML preview |
| `diff_view.py` | 297 | **Сравнение** — diff двух JSON-отчётов |
| `quick_check_window.py` | 332 | Отдельное окно быстрой проверки IOC |
| `payload_window.py` | 44 | Окно «Код инжекта» (`Ctrl+Shift+P`), без parent |

Секции настроек: Общие, Пороги, Детекторы, Противоречия,
Allowlist, DGA, Brute force, Сеть, Отчёты, Плагины, YARA,
Threat Intel, Производительность.

### Dialogs

| Файл | Строк | Что |
|---|---|---|
| `attack_graph_dialog.py` | 703 | **v1.2.0** — Attack Graph (граф + Time Machine + PNG/DOT/GraphML) |
| `graph_dialog.py` | 517 | «Граф связей» — карта сети |
| `contradiction_dialog.py` | 195 | Детали Contradiction |
| `explanation_dialog.py` | 310 | **Окно объяснений** находки/противоречия: что произошло, почему важно, что дальше, чипы «как новичку»/«альтернативы», копирование в Markdown |
| `finding_dialog.py` | 200 | Детали Finding + кнопка «Объяснение» |
| `carved_files_dialog.py` | 155 | Список payload'ов с предупреждением |
| `certificates_dialog.py` | 127 | TLS-сертификаты: соединение, CN, срок, self-signed, SAN в tooltip |
| `host_story_dialog.py` | 95 | История хоста |
| `what_if_dialog.py` | 72 | Ввод исключений для What-If |

### Widgets

| Файл | Строк | Что |
|---|---|---|
| `highlights_panel.py` | 684 | «Что привлекло внимание» — приоритетные карточки (противоречия, находки, объём, DNS, HTTP, потоки), фильтры, история хоста |
| `editable_list.py` | 369 | Список с inline-edit и импортом/экспортом |
| `findings_table.py` | 374 | Таблица с фильтрами (поиск, тип, conf) |
| `finding_actions.py` | 320 | Правая колонка действий у находок: детали, объяснение, переходы в «Код инжекта»/«Обогащение», инструменты отчёта |
| `observations_panel.py` | 472 | «Что видел инструмент»: строки разбора (HTTP/DNS/потоки/хосты/TCP/файлы, трафик, протоколы, TLS, ошибки) + кликабельные плитки итога с severity |
| `absence_panel.py` | 254 | «Аномалии»: DNS без ответа, TCP без ответа, объём по хостам с выбросами |
| `provider_card.py` | 222 | Карточка провайдера обогащения |
| `contradiction_card.py` | 176 | Карточка одного правила; «Подробнее» и «Объяснение» |
| `drop_zone.py` | 158 | Drag&drop + логотип |
| `toast.py` | 120 | Всплывающие уведомления |
| `contradictions_section.py` | 111 | Секция со скроллом |

### Workers

| Файл | Строк | Что |
|---|---|---|
| `analysis_worker.py` | 149 | QThread: `run_pipeline` / `run_multi_pipeline`, отмена через `requestInterruption`; отключение детекторов/правил — параметрами `detectors`/`rules`, без monkey-patch |
| `enrichment_worker.py` | 78 | QThread: `enrich_findings` |
| `quick_check_worker.py` | 77 | QThread: параллельный опрос провайдеров |

### Analysers

**`run_diff.py` (202)** — **v1.2.0** — diff двух report dict'ов. Возвращает added/removed/changed по findings, contradictions, flows.

---

## Тесты

**1580 тестов в 180 файлах** (замер 2026-11-12: ядро объяснений,
окно объяснений, переписанные тексты, allowlist Safe Browsing).
Раскладка по группам меняется от волны к волне, поэтому здесь —
только ключевые файлы, а не таблица с быстро устаревающими числами.

- **Ядро:** `test_detectors.py`, `test_beaconing.py`, `test_attack_graph.py`,
  `test_regressions.py`, `test_timeline.py`, `test_taxonomy.py`.
- **Объяснения:** `test_explain.py` — покрытие типов и правил, подстановки,
  fallback, Markdown, отсутствие имён полей и MITRE в прозе;
  `test_gui_explanation_dialog.py` — окно, чипы, копирование, кнопки в
  колонке действий и на карточке противоречия.
- **Границы ввода:** `test_cli_input.py`, `test_pipeline_callbacks.py`,
  `test_version_consistency.py`.
- **GUI (offscreen):** `test_gui_payload_view.py`, `test_payload_preview.py`,
  `test_editable_list.py`, `test_gui_observations.py`.

**Известный долг тестов:**
- `test_extractors_ndp.py` — 1 тест (только happy path)
- `test_auto_explain.py` — 5 тестов (explainer покрыт поверхностно)
- IPv6-путь `ioc_reporter` тестами не покрыт

---

## Известные проблемы

### Закрыто в v1.0–v1.5

- ~~IPv6 не поддержан~~ → `parsers_ipv6.py` + `NDPExtractor` + `IPv6View`
- ~~DNS-ответы не парсятся~~ → `dns_answers_by_name/ip` + A/AAAA/CNAME
- ~~TLS-сертификаты не парсятся~~ → `x509_cert.py` + 3 правила (sni_cert, self_signed, expired)
- ~~Двухуровневые TLD не поддержаны~~ → `domain_utils.py` (co.uk, com.au, co.jp, …)
- ~~NXDOMAIN burst по всему файлу~~ → скользящее окно (`nxdomain_burst_window_sec=60`)
- ~~Timeline отсутствует~~ → `timeline.py` + вкладка
- ~~Нет multi-pcap~~ → `multi_pcap.py` + `run_multi_pipeline` + кнопка в GUI
- ~~Нет attack graph~~ → `attack_graph.py` + диалог + PNG/DOT/GraphML
- ~~`config.py` не валидирует провайдеров~~ → warning в `build_default_orchestrator` (не raise — Config низкий слой)
- ~~`NDPExtractor` без `layer = 0`~~ → `layer = 0` (`extractors/ndp.py`)
- ~~`test_multi_pcap.py` пуст, слияние не покрыто~~ → `test_multi_pcap_merge.py`, 21 тест
- ~~`beaconing` не ловил медленный C2~~ → slow-режим (v1.4, `beaconing_slow_*`)
- ~~Из keep-alive потока читался один запрос~~ → `iter_http_requests/responses` (v1.4)
- ~~Нет HTML/STIX-отчёта~~ → `html_reporter.py`, `stix_reporter.py` (v1.5)
- ~~Детекторы отключаются monkey-patch~~ → параметры `detectors`/`rules` (v1.4)
- ~~Нет entry point~~ → `paradox` в `[project.scripts]`
- ~~Version drift~~ → `1.5.0` в коде, `pyproject.toml` и теге

### Открыто в 1.7.0

Полный план с приоритетами — в `TODO.md`. Здесь только то, что
видно из кода и подтверждается тестами.

| Проблема | Влияние | Направление |
|---|---|---|
| `sni_mismatch` шумит? | Замер 2026-11-10: 0 findings на FIN-2015 — сравнение с DNS-ответами и CDN-allowlist уже закрывают прежние 73 FP | Перепроверять на новых захватах |
| JA3-браузеров нет в `ja3_known_tools` | `ja3_ua_mismatch` работает только на tool/malware | Нужны проверенные хеши от владельца |
| `ja3s_known_malware` пуст по умолчанию | `ja3s_malware` молчит до ручного заполнения | Дизайн: нужны проверенные хеши |
| TLS 1.3 certificate зашифрован | Правила на сертификатах только для TLS 1.2 | Технический лимит |
| `internal→internal` зашифрованный C2 | Вне зоны видимости | Нужен разбор протоколов |
| brotli/zstd не распаковываются | Часть тел не сканируется | Внешние зависимости |
| HTTP/2 без keylog | h2 поверх TLS виден только как flow | Передать `SSLKEYLOGFILE` через `--tls-keylog` |
| TLS CBC-сьюты и 0-RTT | Записи не расшифровываются | Только AEAD (AES-GCM, ChaCha20) |
| Потоки сверх бюджета reassembly (200 МБ) truncated | Потеря тел; число видно в summary и в Markdown-предупреждении | Инкрементальный разбор и вытеснение |
| IPv6 в `ioc_reporter` не тестируется | Может ломаться на специфичных форматах | Тест + `ipaddress` |

### Технический долг (не блокеры)

- `config.py` — плоский dataclass на 1025 строк. Валидация уже табличная
  (`_VALIDATION_RULES`: поле, предикат, сообщение), но сами секции
  (beaconing, dns_tunneling, http_body) по-прежнему живут в одном классе.
- `pipeline/` разложен по этапам (`extract`, `detect`, `summarize`,
  `report`), фасад — 137 строк; сшивать этапы по-прежнему в одном
  месте, но читать их можно по отдельности.
- `http_object.py` — HTTP/1.x; HTTP/2 разбирается отдельно (`http2_parse.py`
  + `extractors/http2.py`), HPACK — через пакет `hpack`.
- TLS-расшифровка работает только по keylog и только для AEAD-сьютов;
  CBC, renegotiation и 0-RTT не поддержаны.
- `file_carve.py` — `_MIME_TO_EXT` (18 записей) и `_MAGIC` (9 сигнатур). Не покрывает APK, MSI, DMG.
- `_MIME_TO_EXT`/`_MAGIC` и `payload_excerpt.py` не знают про brotli/zstd — тела с таким сжатием просто не сканируются.
- Нет end-to-end теста «запусти GUI → загрузи pcap → получи отчёт» (только offscreen на отдельных виджетах).
- `summary` считает `tcp_streams_truncated`, но не различает «поток обрезан» и «поток выброшен из-за бюджета 200 МБ».

---
