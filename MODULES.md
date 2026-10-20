# Справочник модулей Paradox v1.2.0

Описание каждого файла: что делает, ключевые классы и функции,
связи с другими модулями. Для аналитика, разработчика и того, кто
хочет понять, куда смотреть при отладке.

**Версия ядра:** 1.0.0 (тег git: v1.2.0)
**Версия GUI:** 1.0.0 (тег git: v1.2.0)
**Строк кода:** ядро — 15 870, GUI — 11 931, всего ~27 800
**Тестов:** 942 в 110 файлах

---

## Содержание

1. [Корень пакета `paradox/`](#корень-пакета-paradox)
2. [Парсеры](#парсеры)
3. [Экстракторы (12)](#экстракторы)
4. [Детекторы (20)](#детекторы)
5. [Contradictions (12 правил)](#contradictions)
6. [Анализаторы](#анализаторы)
7. [Multi-pcap](#multi-pcap)
8. [Timeline / Kill-chain](#timeline)
9. [Интеграции (9 провайдеров)](#интеграции)
10. [Агрегаторы](#агрегаторы)
11. [Reporters](#reporters)
12. [GUI](#gui)
13. [Тесты](#тесты)
14. [Известные проблемы](#известные-проблемы)

---

## Корень пакета `paradox/`

| Файл | Строк | Что делает |
|---|---|---|
| `__init__.py` | 1 | `__version__ = "1.0.0"` |
| `__main__.py` | 6 | `python -m paradox` → `cli.main()` |
| `cli.py` | 146 | CLI: аргументы, `-o`, `--enrich`, interactive |
| `config.py` | 790 | Все настройки (frozen dataclass), валидация |
| `models.py` | 349 | `Finding`, `FlowKey`, `SessionKey`, `FlowStats`, `HostIdentity`, `CaptureState` |
| `pipeline.py` | 590 | `run_pipeline` + `run_multi_pipeline`, `_extract`, `_detect` |
| `multi_pcap.py` | 169 | `merge_capture_states(states)` — слияние N датасетов |
| `timeline.py` | 305 | `build_timeline`, `summarize_by_phase`, kill-chain |
| `domain_utils.py` | 151 | `split_domain`, `base_domain`, `registered_label`, `matches_suffix` |
| `net_utils.py` | 39 | `is_internal_ip`, `classify_direction` |
| `reassembler.py` | 162 | `TCPReassembler` — склейка TCP по seq |
| `file_carve.py` | 199 | Метаданные payload'ов (sha256, MIME, magic) |
| `http_object.py` | 254 | `parse_http_request`, `parse_http_response` (полный HTTP) |
| `http_parse.py` | 106 | Быстрый `parse_request` первого сегмента |
| `tls_parse.py` | 181 | `extract_sni(ClientHello)` |
| `tls_cert.py` | 122 | `parse_certificate_from_stream` — X.509 из TLS |
| `ja3.py` | 218 | `parse_client_hello`, `parse_server_hello` (JA3/JA3S) |
| `kerberos_parse.py` | 338 | ASN.1 DER для Kerberos AS/TGS/AP |
| `nbns_parse.py` | 179 | NBNS-имена |
| `x509_der.py` | 248 | Минимальный DER-парсер |
| `x509_cert.py` | 194 | `Certificate` из DER: CN, SAN, validity, self_signed |

### Секции `config.py`

- `cloud_tunnel_domains` (7), `ip_check_services` (8), `ip_check_service_ips` (4)
- `ja3_known_malware` (7), `ja3_known_tools` (3)
- `command_injection_patterns_high` / `_medium`, `command_injection_min_patterns=1`
- `suspicious_ports` (8), `private_networks`, `dc_service_ports` (5)
- `beaconing_*` (min_conn=20, jitter<0.1, mail_polling_ports, allowlist_suffixes ~70)
- `dns_tunneling_*` (qname≥50, allowlist DoH)
- `large_transfer_*` (100MB, excluded_hosts/uas)
- `port_service_allowed` (Mapping 18 портов → frozenset)
- `reverse_asymmetry_*` (1MB, ratio 10/25)
- `lateral_movement_*` (6 портов, UA/URI markers)
- `ssh_brute_force_min_flows=20`, `smtp_spam_min_recipients=50`
- `nxdomain_burst_*` (threshold=5, window=60, ratio=0.2)
- `typosquatting_*` (18 брендов, threshold=2)
- `port_service_*`, `vulnerable_paths` (16), `suspicious_download_extensions` (10)
- `entities_top_n=50`, `gateway_min_flows=50`
- `enrichment_enabled_providers` (9), `enrichment_cache_ttl_days=7`
- `tcp_reassembly_enabled=True`, `file_carve_write_body=False`
- `ioc_export_enabled=True`, `output_dir=reports/`

---

## Парсеры

### `parsers.py` (274 строки)
Быстрый разбор пакетов через `struct.unpack`. Без scapy. Поддержано: Ethernet, 802.1Q VLAN, IPv4 (фрагментация), TCP (seq/ack/flags), UDP, ICMP, ARP.

**Класс `PacketRecord`:** L2-L4 поля + payload + `ipv6_meta` (dict).

**`parse_packet(raw, ts)`** — 25 MB/s (~39x быстрее scapy).

### `parsers_ipv6.py` (207 строк)
IPv6: заголовок + extension chain (HopByHop, Routing, Fragment, ESP, Auth, DestOptions, Mobility), извлечение src/dst портов.

**Мета в `ipv6_meta`:** `traffic_class`, `flow_label`, `hop_limit`, `extension_chain`, `is_fragment`, `fragment_id`, `final_next_header`.

---

## Экстракторы

Слой `paradox/extractors/`. Contract: `Extractor` Protocol — `name`, `layer`, `process(record, state)`.

**12 экстракторов.** `FlowExtractor` обязательно первый (остальные ищут существующий flow).

| Файл | name | Что пишет |
|---|---|---|
| `flow.py` (51) | flow | `state.flows[key]` — packets, bytes, timestamps, `initiated_by_src` по первому SYN |
| `dns.py` (110) | dns | `dns_queries`, `dns_nxdomain`, `dns_nxdomain_by_src`, `dns_queries_by_src`, `dns_answers_by_name`, `dns_answers_by_ip`, `dns_nxdomain_ts_by_src` |
| `tls.py` (78) | tls | `flow.sni`, `flow.ja3`, `flow.ja3s`, `session_sni` |
| `http.py` (77) | http | `flow.http_{host,uri,method,user_agent}` — только запросы |
| `host_identity.py` (50) | host_identity | `host_identities[ip].mac` (только ARP, без eth_src) |
| `arp_history.py` (61) | arp_mac_history | `arp_macs[ip][mac] = [first, last, count]` |
| `dhcp.py` (180) | dhcp | MAC + hostname из BOOTP/DHCP |
| `ssh_banner.py` (104) | ssh_banner | `ssh_server_versions`, `ssh_client_versions`, `ssh_client_attempts` |
| `smtp.py` (130) | smtp | `smtp_helo_by_src`, `smtp_from_by_src`, `smtp_rcpt_by_src`, `smtp_mailer_by_src` |
| `nbns.py` (47) | nbns | `hostnames` из NBNS (suffix 0x00/0x20) |
| `kerberos.py` (77) | kerberos | `username` / `hostnames` / `realm` из cname |
| `ndp.py` (132) | ndp | `ndp_neighbors`, `ndp_routers`, `ndp_total` ⚠️ **без `layer=0`** |
| `tls_cert.py` (52) | tls_cert | `state.tls_certs` — вызывает `run_post_extract` |

**`http_object.py` (107)** — `HTTPObjectExtractor.run_post_extract()` — обёртка над `paradox/http_object.py`, работает на `tcp_streams`, не на пакетах.

---

## Детекторы

Слой `paradox/detectors/`. Contract: `LocalDetector` — `name`, `run(state, config) -> list[Finding]`.

**20 детекторов.**

| Детектор | Строк | Что ищет |
|---|---|---|
| `dga.py` | 61 | Высокая энтропия label |
| `port_scan.py` | 85 | 1 src → много dst на 1 порт |
| `suspicious_port.py` | 106 | External dst на портах 4444/31337/… |
| `nxdomain_burst.py` | 95 | NXDOMAIN в скользящем окне (v0.9.0) |
| `cloud_tunnel.py` | 36 | trycloudflare/ngrok/serveo |
| `ip_check_service.py` | 77 | ip-api.com/ifconfig.me (DNS+SNI+Host+direct IP) |
| `typosquatting.py` | 141 | SLD близок к бренду (contains/levenshtein) |
| `sni_mismatch.py` | 118 | SNI без DNS-ответа |
| `ja3_malware.py` | 82 | JA3 из `ja3_known_malware` |
| `brute_force.py` | 188 | HTTP-перебор (src_ports, URI-ratio, rate) |
| `ftp_brute_force.py` | 99 | 20+ flows на порт 21 |
| `beaconing.py` | 254 | Jitter + multi-tenant + payload stddev |
| `dns_tunneling.py` | 104 | Длинные уникальные qname под одним base |
| `ssh_brute_force.py` | 58 | 20+ SSH-баннеров на пару |
| `smtp_spam.py` | 108 | 50+ уникальных RCPT TO |
| `lateral_movement.py` | 143 | SMB/RDP/WinRM internal→internal |
| `large_transfer.py` | 252 | 100MB в одном flow (или паре) |
| `vulnerable_path.py` | 310 | wp-login/.env/.git + script_download + web_scanner |
| `command_injection.py` | 180 | RCE в HTTP URI/body |
| `yara_detector.py` | 81 | YARA на carved_files (опционально) |

**`mitre_map.py` (60)** — `MITRE_MAP: dict[str, tuple[str, ...]]`. Instance-level `Finding.mitre_techniques` приоритетнее.

**`explainer.py` (56)** — `build_reasons(evidence)` для `Finding.confidence_reasons`.

### Пороги детекторов (важные)

- **beaconing:** min_conn=20, duration≥600s, jitter<0.1, avg_bytes<5000, rate<5/min, payload_var<0.5, multi-tenant filter (>1 SNI/Host = CDN), mail_ports={110,143,993,995}, skip_internal=True
- **nxdomain_burst:** threshold=5, window=60s, min_ratio=0.2
- **dns_tunneling:** qname≥50, long≥20, queries≥50
- **large_transfer:** 100 MB, pair mode (сумма обоих направлений)
- **port_scan:** ≥10 уникальных dst, thin-ratio ≥ 0.7, excluded={80,443}

---

## Contradictions

Слой `paradox/contradictions/` — **v0.7.0+**, главная ценность Paradox. Не детекторы, а поиск несогласованности между источниками.

### Модель

**`Fact`** (frozen): `source`, `subject`, `predicate`, `value`, `ts`, `confidence`, `evidence`.

**`Contradiction`:** `rule`, `subject`, `facts`, `severity`, `confidence`, `likely_causes`, `resolution_hint`, `priority` (property = severity_weight × confidence).

**`ContradictionRule`** Protocol: `name`, `severity_base`, `extract_facts(state, findings, config)`, `find_contradictions(facts)`.

### `facts.py` (927 строк) — самый большой файл ядра

7 экстракторов фактов (правила вызывают нужный):

- `extract_attack_facts(findings)` — `victim_of` / `attacker_of` (синхронизировано с `entities.py`)
- `extract_arp_facts(state)` — `has_mac` из `arp_macs`
- `extract_tls_host_facts(state, config)` — `sni`, `http_host` + CNAME-цепочка через `_collect_ips_for`
- `extract_ja3_ua_facts(state, config)` — `uses_ja3`, `uses_ua`
- `extract_asymmetry_facts(state, config)` — `session_asymmetry` (через `make_session_key`)
- `extract_protocol_on_port_facts(state, config)` — `protocol_on_port` (tls/http)
- `extract_direct_ip_facts(state, config)` — `direct_ip_connect`, `makes_dns_queries`
- `extract_tls_cert_facts(state)` — `tls_cert` из `state.tls_certs`

### `registry.py` (85) — 12 правил

| Правило | severity_base | Источник | Что ищет |
|---|---|---|---|
| `SniWithoutDnsRule` (95) | medium | sni | SNI без DNS-ответа |
| `DnsAnswerMismatchRule` (114) | medium | sni | SNI ≠ резолвнутый IP |
| `SniCertMismatchRule` (93) | medium | tls_cert | SNI ≠ CN/SAN сертификата |
| `SelfSignedCertRule` (64) | medium | tls_cert | issuer == subject |
| `ExpiredCertRule` (76) | low | tls_cert | not_after < ts flow |
| `VictimMakesAttackRule` (149) | **critical** | findings | X — victim_of(A) и attacker_of(B) → **pivot** |
| `MacIpConflictRule` (138) | **critical** | arp | ≥2 MAC на одном IP (spoof/lease) |
| `SniHostMismatchRule` (130) | high | flows | SNI ≠ Host (domain fronting) |
| `Ja3UaMismatchRule` (144) | high | flows | tool-JA3 + browser-UA → мимикрия |
| `ReverseAsymmetryRule` (185) | medium | flows | session ratio ≥10 (bulk → low) |
| `PortServiceMismatchRule` (166) | high | flows | TLS на 22 / HTTP на 445 → туннель |
| `DirectIpNoDnsRule` (129) | medium | flows | IP без DNS, ≥3 dst или ≥10 портов |

**`run_all(state, findings, config)`** — прогон, сортировка по (severity, -confidence, subject).

### Полярность findings (синхронизировать с `entities.py`)

- `_ATTACK_TYPES` → src=attacker: `brute_force`, `ftp_brute_force`, `ssh_brute_force`, `vulnerable_path`, `command_injection`, `port_scan`, `web_scanner`, `lateral_movement`
- `_VICTIM_SIGNAL_TYPES` → src=victim: `beaconing`, `dns_tunneling`, `script_download`, `nxdomain_burst`, `ja3_malware`, `sni_without_dns`, `dga_domain`, `cloud_tunnel`, `ip_check_service`, `typosquatting`, `suspicious_port`, `smtp_spam`
- `large_transfer` — по `evidence.direction`

**Если правишь полярность — правь в обоих местах.**

---

## Анализаторы

Слой `paradox/analyzers/` — новый в v1.0.0/v1.2.0.

### `attack_graph.py` (382) — **v1.2.0**

Directed graph атаки из findings + contradictions. Узлы = IP, рёбра = findings с (src, dst), пути = BFS от entry к impact.

**Классы:** `AttackNode`, `AttackEdge`, `AttackPath`, `AttackGraph`.

**`build_attack_graph(findings, config, entities, contradictions, max_paths=10, max_depth=6)`**

- Entry: внутренние `victim_candidate` или (external→internal с initial_access)
- Impact: внешние `c2_candidate` / `attacker_candidate` или impact-phase
- Pivot: из `victim_makes_attack`
- `_PHASE_OF_TYPE` маппинг тип → фаза kill-chain

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

### `multi_pcap.py` (169) — **v1.2.0**

**`merge_capture_states(states: list[CaptureState]) -> CaptureState`**

Слияние: Counter.update, dict update с dedup, sum FlowStats по FlowKey, extend списков, min(first_ts)/max(last_ts).

Не трогает `run_pipeline`, вызывается из `run_multi_pipeline` (append-only в `pipeline.py`).

---

## Timeline

### `timeline.py` (305) — **v1.2.0**

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
| `base_enricher.py` | 209 | — | Базовый класс, HTTP-клиент, error handling |
| `cache.py` | 155 | — | SQLite-кэш с TTL |
| `rate_limit.py` | 61 | — | `TokenBucket` |
| `shodan_internetdb.py` | 116 | без | ip |
| `abuseipdb.py` | 128 | `ABUSEIPDB_API_KEY` | ip |
| `virustotal.py` | 47 | `VIRUSTOTAL_API_KEY` | ip/domain/hash |
| `greynoise.py` | ~30 | без | ip |
| `alienvault_otx.py` | 24 | без | ip/domain/hash |
| `urlscan.py` | 36 | без | domain/url |
| `urlhaus.py` | 51 | `ABUSECH_AUTH_KEY` | domain/url |
| `malwarebazaar.py` | 39 | `ABUSECH_AUTH_KEY` | hash |
| `threatfox.py` | 40 | `ABUSECH_AUTH_KEY` | ip/domain/hash |
| `enricher.py` | 212 | — | `EnricherOrchestrator`, `collect_iocs_from_findings` |
| `pipeline.py` | 144 | — | `enrich_findings`, `attach_enrichment_to_findings` |
| `registry.py` | 42 | — | `REGISTRY` (9 провайдеров) |

Приватные IP не обогащаются (`_is_private_ip` + CGNAT 100.64/10).

---

## Агрегаторы

### `entities.py` (453) — **v0.3.0+**

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

**Семантика ролей** синхронизирована с `contradictions/facts.py`.

---

## Reporters

| Файл | Строк | Что делает |
|---|---|---|
| `json_reporter.py` | 45 | `write_json`, `write_markdown` (sort_keys для детерминизма) |
| `markdown_reporter.py` | 976 | `render_markdown` — 11 секций (TL;DR, Timeline, Carved, Сводка, Сущности, Findings, Противоречия, HTTP, IOC, Top-10 flows) |
| `flow_report.py` | 231 | `build_flow_report`, `build_dns_report`, `build_http_report`, `build_http_object_report` |
| `ioc_reporter.py` | 349 | **v1.0.0** — `build_ioc_report`, `write_ioc_files` (txt/csv/json/suricata/queries) |

**`_CHAIN_ORDER`** в markdown_reporter — порядок findings в TL;DR (pivot=5, web_scanner=10 … large_transfer=110).

**IOC reporter** — `_looks_like_ip` через `ipaddress` (IPv4+IPv6), SID база 9000000, KQL+Splunk queries.

---

## GUI

Пакет `paradox_gui/` — **11 931 строка**. Не трогает ядро, вызывает `run_pipeline`/`run_multi_pipeline` в QThread.

### Корень

| Файл | Строк | Что делает |
|---|---|---|
| `__main__.py` | ~30 | Патчит `sys.stdout/stderr` на devnull (PyInstaller --windowed) |
| `app.py` | 62 | `QApplication` + splash + main window |
| `main_window.py` | 860 | 8 вкладок, меню, `ClickableLabel` (лого + версия), статус-бар |
| `theme.py` | 575 | QSS-тема (генерируется кодом) |
| `splash.py` | 159 | **v1.2.0** — Splash screen с прогресс-баром |
| `logo.py` | 110 | **v1.2.0** — `render_logo`, `get_app_icon`, `logo_label` |
| `_runtime_hook.py` | 90 | PyInstaller: faulthandler → `Paradox-error.log` |
| `storage.py` | 134 | SQLite-история (`%APPDATA%/Paradox/history.db`) |
| `settings_store.py` | 124 | JSON-settings с атомарной записью |
| `settings_rehydrate.py` | 63 | Восстановление типов (Path, frozenset) из JSON |
| `secrets_store.py` | 153 | Keyring → session → env (fallback) |
| `config_builder.py` | ~50 | `build_config_with_overrides(overrides)` |
| `profiles.py` | 96 | Профили: default / ctf / corporate |
| `detector_help.py` | 75 | Tooltips детекторов |
| `field_help.py` | 222 | Tooltips полей Config |
| `contradiction_help.py` | ~50 | Tooltips правил |
| `ioc_utils.py` | 81 | `detect_ioc_type`, `provider_link` |

### Views — 8 вкладок

| Файл | Строк | Вкладка |
|---|---|---|
| `run_view.py` | 627 | **Прогон** — drop zone, summary, findings, кнопки «Граф связей/атаки/Файлы/What-If» |
| `history_view.py` | 551 | **История** — список прогонов + HTML-превью |
| `enrich_view.py` | 548 | **Обогащение** — IOC-выбор + результаты |
| `settings_view.py` | 2021 | **Настройки** — 12 секций, профили, поиск |
| `ipv6_view.py` | 114 | **IPv6** — NDP + потоки |
| `timeline_view.py` | 251 | **Таймлайн** — kill-chain tree |
| `export_view.py` | 190 | **Экспорт** — CSV/STIX preview |
| `diff_view.py` | 190 | **Сравнение** — **v1.2.0** diff двух JSON-отчётов |
| `roadmap_view.py` | 100 | **Развитие** — статический roadmap |
| `quick_check_window.py` | 339 | Отдельное окно быстрой проверки IOC |

### Dialogs

| Файл | Строк | Что |
|---|---|---|
| `attack_graph_dialog.py` | 651 | **v1.2.0** — Attack Graph (граф + Time Machine + PNG/DOT/GraphML) |
| `graph_dialog.py` | 460 | «Граф связей» — карта сети |
| `contradiction_dialog.py` | 186 | Детали Contradiction |
| `finding_dialog.py` | 183 | Детали Finding |
| `carved_files_dialog.py` | 150 | Список payload'ов с предупреждением |
| `host_story_dialog.py` | 69 | История хоста |
| `what_if_dialog.py` | 52 | Ввод исключений для What-If |

### Widgets

| Файл | Строк | Что |
|---|---|---|
| `editable_list.py` | 369 | Список с inline-edit и импортом/экспортом |
| `findings_table.py` | 319 | Таблица с фильтрами (поиск, тип, conf) |
| `provider_card.py` | 217 | Карточка провайдера обогащения |
| `contradiction_card.py` | 178 | Карточка одного правила |
| `summary_grid.py` | 136 | 6 плиток (packets/flows/findings/contradictions/size/time) |
| `drop_zone.py` | 133 | Drag&drop + логотип |
| `toast.py` | 119 | Всплывающие уведомления |
| `observations_panel.py` | 108 | «Что видел инструмент» |
| `contradictions_section.py` | 89 | Секция со скроллом |
| `absence_panel.py` | 85 | Оборванные сессии |
| `highlights_panel.py` | 83 | «Что привлекло внимание» |

### Workers

| Файл | Строк | Что |
|---|---|---|
| `analysis_worker.py` | 144 | QThread: `run_pipeline` / `run_multi_pipeline` (v1.2.0) |
| `enrichment_worker.py` | 74 | QThread: `enrich_findings` |
| `quick_check_worker.py` | 77 | QThread: параллельный опрос провайдеров |

### Analysers

**`run_diff.py` (105)** — **v1.2.0** — diff двух report dict'ов. Возвращает added/removed/changed по findings, contradictions, flows.

---

## Тесты

**942 теста в 110 файлах.** Покрытие по группам:

| Группа | Файлов | Тестов | Ключевые файлы |
|---|---|---|---|
| Парсеры | 3 | 44 | `test_parsers.py` (11), `test_parsers_ipv6.py` (11), `test_http_parse.py` (22) |
| Экстракторы | 8 | 57 | `test_dhcp.py` (12), `test_smtp.py` (22), `test_ssh_banner.py` (17) |
| HTTP/TLS/JA3 | 5 | 54 | `test_http_object.py` (12), `test_ja3.py` (8), `test_tls_cert.py` (8) |
| Reassembly | 1 | 9 | `test_reassembler.py` |
| Детекторы (базовые) | 5 | 92 | `test_detectors.py` (49), `test_beaconing.py` (31), `test_regressions.py` (42) |
| Детекторы (новые) | 4 | 44 | `test_smtp_spam.py` (16), `test_ssh_brute_force.py` (16) |
| Contradictions | 9 | 60 | `test_cert_rules.py` (17), `test_timeline.py` (37) |
| Анализаторы | 3 | 21 | `test_attack_graph.py` (15) |
| Агрегаторы | 1 | 10 | `test_aggregators_entities.py` |
| Enrichment | 15 | 92 | `test_enricher_orchestrator.py` (11) |
| GUI (offscreen) | 12 | 66 | `test_provider_card.py` (8), `test_editable_list.py` (12) |
| Регрессии / FP | 2 | 42 | `test_regressions.py` — FP-каталог |
| Мульти-pcap | 1 | 0 ⚠️ | `test_multi_pcap.py` — **пустой, наполняется вручную** |

**Ядро проекта:** `test_detectors.py`, `test_beaconing.py`, `test_attack_graph.py`, `test_regressions.py`, `test_timeline.py`.

**Известный долг тестов:**
- `test_multi_pcap.py` — 0 тестов (сейчас только ручной `tools/test_multi_pcap.py`)
- `test_extractors_ndp.py` — 1 тест (только happy path)
- `test_auto_explain.py` — 5 тестов (explainer покрыт поверхностно)

---

## Известные проблемы

### Закрыто в v1.0–v1.2

- ~~IPv6 не поддержан~~ → `parsers_ipv6.py` + `NDPExtractor` + `IPv6View`
- ~~DNS-ответы не парсятся~~ → `dns_answers_by_name/ip` + A/AAAA/CNAME
- ~~TLS-сертификаты не парсятся~~ → `x509_cert.py` + 3 правила (sni_cert, self_signed, expired)
- ~~Двухуровневые TLD не поддержаны~~ → `domain_utils.py` (co.uk, com.au, co.jp, …)
- ~~NXDOMAIN burst по всему файлу~~ → скользящее окно (`nxdomain_burst_window_sec=60`)
- ~~Timeline отсутствует~~ → `timeline.py` + вкладка
- ~~Нет multi-pcap~~ → `multi_pcap.py` + `run_multi_pipeline` + кнопка в GUI
- ~~Нет attack graph~~ → `attack_graph.py` + диалог + PNG/DOT/GraphML
- ~~`config.py` не валидирует провайдеров~~ → warning в `build_default_orchestrator` (не raise — Config низкий слой)

### Открыто в v1.2.0

| Проблема | Влияние | Кандидат на v1.3 |
|---|---|---|
| `test_multi_pcap.py` пуст (0 тестов) | Нет регрессии для `merge_capture_states` | Высокий приоритет |
| `NDPExtractor` без `layer = 0` | Нарушает Protocol `Extractor` | 1 строка |
| `beaconing` требует windowing для медленных C2 (интервал > часа) | В одном pcap не поймать | v1.3 |
| `sni_mismatch` шумит (73 FP на FIN-2015) | Много noise | Context-aware allowlist |
| JA3-браузеров нет в config | ja3_ua_mismatch не работает на Chrome/Firefox | Расширить `ja3_known_tools` |
| IPv6 в IOC reporter — есть, но не тестируется | Может ломаться на специфичных форматах | Тест + `ipaddress` |
| TLS 1.3 certificate зашифрован | Правила на сертификатах работают только для TLS 1.2 | Технический лимит |
| `markdown_reporter.py` — 976 строк | Сложно поддерживать | Разбить на подмодули |
| `settings_view.py` — 2021 строка | Монолит | Разбить по секциям |
| `contradictions/facts.py` — 927 строк | Один файл на 7 экстракторов | Разбить по source |
| `entities.py` дублирует полярность findings с `facts.py` | Рассинхрон → FP | Вынести в общий модуль |
| Нет `pyproject.toml [project.scripts]` entry point | `paradox` не в PATH после `pip install -e` | 5 строк |
| `__version__` в `paradox/__init__.py` и `paradox_gui/__init__.py` = `"1.0.0"`, а тег `v1.2.0` | Version drift | Поднять до `"1.2.0"` |

### Технический долг (не блокеры)

- `config.py` — 790 строк, но flat dataclass. Работает, но параллельные секции (beaconing, dns_tunneling) дают 200+ строк валидации — можно разнести в per-section `_validate_*`.
- `pipeline.py` — `run_multi_pipeline` дублирует ~140 строк `run_pipeline`. Extract в common `_build_report(state, findings, contradictions, config)`.
- `http_object.py` — поддерживает HTTP/1.x, не HTTP/2. Для HTTP/2 нужен бинарный парсер (h2-фреймы).
- `file_carve.py` — `_MIME_TO_EXT` (16 записей) и `_MAGIC` (9 сигнатур). Не покрывает APK, MSI, DMG.
- Нет end-to-end теста «запусти GUI → загрузи pcap → получи отчёт» (только offscreen на отдельных виджетах).

---
