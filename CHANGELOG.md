# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).
Версии: семантическое версионирование (major.minor.patch).

## [Unreleased]

### Запланировано (v1.3.0)
- Плагинная система: `~/.paradox/plugins/*.py`, автозагрузка детекторов.
- PDF-экспорт Markdown-отчёта.
- Лендинг + GitHub Pages.
- STIX 2.1 экспорт IOC.
- `beaconing` windowing для медленных C2 (интервал > часа).
- Унификация полярности findings (сейчас дублируется в `entities.py` и `facts.py`).

### Известные проблемы
- `test_multi_pcap.py` — 0 тестов (ручной `tools/test_multi_pcap.py`).
- `NDPExtractor` без `layer = 0` — нарушает Protocol `Extractor`.
- `sni_mismatch` шумит (73 FP на FIN-2015) — нужен context-aware allowlist.
- JA3 браузеров не в config — ja3_ua_mismatch работает только на tool/malware.
- TLS 1.3 Certificate зашифрован — правила на сертификатах только для TLS 1.2.
- `markdown_reporter.py` — 976 строк, `settings_view.py` — 2021, `facts.py` — 927. Кандидаты на разбивку.
- `beaconing` не ловит медленный C2 (интервал > часа) — нужен windowing.
- Внутренний C2 (internal→internal зашифрованный) — вне зоны видимости.
- Двухуровневые TLD поддержаны (domain_utils), но не в typosquatting SLD-фильтре для части кейсов.

## [1.2.0] — 2026-10-20

Release v1.2.0. Attack Graph + Multi-pcap + Splash + Logo + Diff.
Тестов 938 → 942. Детекторов 20. Экстракторов 12. Правил 12.

### Добавлено

**Attack Graph (ядро + GUI):**
- `paradox/analyzers/attack_graph.py` (382) — directed graph
  из findings + contradictions. Узлы = IP, рёбра = findings с
  (src, dst), пути = BFS от entry до impact.
- `AttackNode`, `AttackEdge`, `AttackPath`, `AttackGraph`.
- `build_attack_graph(findings, config, entities, contradictions)`.
- Entry: `victim_candidate` или (external→internal с initial_access).
  Impact: `c2_candidate` / `attacker_candidate` или impact-phase.
- `_PHASE_OF_TYPE` маппинг тип → kill-chain фаза.
- `paradox_gui/dialogs/attack_graph_dialog.py` (651) — диалог
  визуализации: узлы по фазам, рёбра цветные, пути слева,
  детали справа.
- Time Machine: слайдер + кнопка Play, узлы/рёбра проявляются
  по времени.
- Экспорт PNG / DOT (Graphviz) / GraphML (Gephi/Neo4j).
- Кнопка «Граф атаки» в RunView, активируется если есть nodes.
- `paradox/analyzers/attack_graph.py::build_attack_graph` вызывается
  в `run_pipeline` и `run_multi_pipeline` (try/except fallback).
- `Finding.attack_graph` в JSON-схеме.
- 15 тестов в `tests/test_attack_graph.py`.

**Multi-pcap:**
- `paradox/multi_pcap.py` (169) — `merge_capture_states(states)`.
  Слияние N датасетов: Counter.update, dict merge с dedup,
  sum FlowStats по FlowKey, extend списков, min/max timestamps.
- `paradox/pipeline.py::run_multi_pipeline` (append-only, не
  трогает `run_pipeline`).
- `paradox_gui/workers/analysis_worker.py` — принимает
  `str | list[str]`, выбирает single/multi.
- Кнопка «Открыть несколько pcap для слияния…» в RunView.
- `provenance.merged_files` в JSON.
- Summary показывает сумму packets/flows по всем файлам.

**Splash screen:**
- `paradox_gui/splash.py` (159) — `ParadoxSplash`.
  640×400, тёмный градиент, логотип PARADOX, прогресс-бар,
  4 стадии загрузки (Threat Intel keys → тема → MainWindow → готово).
- Градиентный прогресс-бар (сине-голубой).

**Логотип-система:**
- `paradox_gui/logo.py` (110) — `render_logo`, `get_app_icon`,
  `logo_label`, `wordmark_pixmap`. Рисуется кодом (`QPainter`),
  без внешних PNG/SVG.
- Иконка приложения в taskbar и title bar (∞ в круге, градиент).
- Логотип в шапке главного окна (слева от меню).
- About-диалог с лого 96×96, версией, списком модулей,
  копирайтом.
- DropZone: логотип вместо эмодзи 📁.

**Diff двух прогонов:**
- `paradox_gui/analyzers/run_diff.py` (105) — сравнение двух
  report dict'ов: added/removed/changed по findings,
  contradictions, flows.
- `paradox_gui/views/diff_view.py` (190) — вкладка «Сравнение»:
  загрузка двух JSON, показ разницы.
- 10 тестов в `tests/test_run_diff.py`.

**Branding:**
- `ClickableLabel` — лого в шапке и версия в статус-баре
  кликабельны → About.
- Версия в статус-баре: `v1.2.0 · © v314xm`.
- Markdown-отчёты: футер `**Paradox** v1.2.0 · © 2026 Andrey Grigoryev (v314xm)`.

**Enrichment providers (9 вместо 3):**
- Добавлены: `greynoise`, `alienvault_otx`, `urlscan` (без ключа),
  `urlhaus`, `malwarebazaar`, `threatfox` (требуют `ABUSECH_AUTH_KEY`).
- `BaseEnricher` — базовый класс для новых провайдеров с
  общим HTTP-клиентом (certifi CA, error handling, timeout).

**IOC reporter:**
- `paradox/reporters/ioc_reporter.py` (349) — экспорт IOC:
  `iocs.txt`, `iocs.csv`, `iocs.json`, `suricata.rules` (SID 9000000+),
  `queries.txt` (KQL + Splunk).
- IPv4 + IPv6 через `ipaddress`.

### Изменено
- `paradox/models.py::_SEVERITY_BY_TYPE` — добавлены
  `smtp_spam`, `sni_without_dns`, `cloud_tunnel_domain`.
- `paradox_gui/views/settings_view.py` — 4 severity-метки
  синхронизированы с `rule.severity_base` ядра
  (SniWithoutDnsRule, DnsAnswerMismatchRule, SniCertMismatchRule,
  ExpiredCertRule).
- `paradox/pipeline.py` — `build_attack_graph` в `run_pipeline`,
  `run_multi_pipeline` добавлен (append-only).
- `paradox_gui/theme.py` — QTreeWidget/QTreeView стилизованы
  под тёмную тему (было: белые строки в Diff/Timeline).
- `paradox/detectors/smtp_spam.py` — `dst_ip` из flows на порты
  25/465/587, `recipients_sample` в evidence.
- `paradox/reassembler.py` — разделены `_total_bytes` (для лимита,
  уменьшается при finalize) и `_bytes_seen_total` (для stats,
  монотонный).
- `paradox/reporters/markdown_reporter.py` — футер с версией и автором.
- `paradox_gui/main_window.py` — `ClickableLabel`, кликабельный
  логотип, статус-бар с версией.
- Attack Graph стрелки: рисуются по касательной к границе узла,
  обрезка линии по радиусам кругов, `setData(0/1)` для корректной
  подсветки путей.

### Исправлено
- **Attack Graph не строился в `run_pipeline`** после `git checkout`
  pipeline.py в середине сессии — восстановлен через отдельный патч.
- **`AttackGraphDialog` — NameError: QTimer** — добавлен импорт.
- **Дубликат splitter** в `_build()` — вызывал
  `RuntimeError: Internal C++ object already deleted`.
- **Attack Graph фазы `"other"`** — PHASE_ORDER comparison не
  срабатывал из-за инициализации `phase_order=999`. Инициализация
  `phase_order=0`, реальные фазы обновляют.
- **QHBoxLayout missing в main_window.py** — потерян при патче шапки.
- **`_looks_like_ip` не видел IPv6** в IOC reporter — переведён на
  `ipaddress.ip_address`.
- **`_SEVERITY_BY_TYPE["cloud_tunnel"]`** не матчил реальный
  `type="cloud_tunnel_domain"` — добавлен алиас.
- **Evidence fallbacks:** `suspicious_port` (`src_ips`) и
  `ja3_malware` (`top_dst_ips`) не поднимались в top-level `src_ip`/
  `dst_ip` — добавлены в `Finding.__post_init__`.

### Производительность
- `paradox/` — 15 870 строк, `paradox_gui/` — 11 931. Всего ~27 800.
- 942 теста в 110 файлах, полный suite ~22 сек.

### Тесты
- 938 → **942 passed** (+15 attack_graph, +10 diff, −13 при
  рефакторинге +0).
- Новые файлы: `test_attack_graph.py` (15), `test_run_diff.py` (10),
  `test_multi_pcap.py` (0 — заглушка).

## [1.1.0] — 2026-10-16

Severity guards, evidence fallbacks, IPv6 IOC, provider validation fix.
Тестов 925 → 938.

### Добавлено
- `tests/test_severity_map.py` — страж: все типы findings из
  детекторов должны быть в `_SEVERITY_BY_TYPE`.
- `tests/test_gui_severity_sync.py` — страж: severity в GUI-лейблах
  правил должна совпадать с `rule.severity_base`.
- `tools/verify_all.py` — прогон всех фиксов + targeted + full suite.
- `tools/rollback.py` — откат через git checkout.
- `tools/cleanup_before_publish.py` — dry-run очистка проекта.

### Изменено
- `paradox/models.py::Finding.__post_init__` — fallback на
  `evidence.src_ips` и `evidence.top_dst_ips`. `suspicious_port` и
  `ja3_malware` findings теперь привязываются к сущностям.
- `paradox/reporters/ioc_reporter.py::_looks_like_ip` — `ipaddress`
  вместо regex-like проверки.
- `paradox/config.py` — убрана валидация имён провайдеров из
  `_validate()` (нарушала слои: Config → integrations).
  Валидация переехала в `build_default_orchestrator` как warning.
- `paradox/reassembler.py` — разделены `_total_bytes` (лимит) и
  `_bytes_seen_total` (stats).

### Исправлено
- **5 тестов `test_orchestrator_*` падали** на `Config()` из-за
  валидации имён провайдеров (mock). Возврат к warning.
- **`test_stats` падал** на `bytes_total == 2` — reassembler
  возвращал текущий буфер, а не монотонный счётчик.

### Тесты
- 925 → **938 passed**.

## [1.0.0] — 2026-10-15

Стабилизация 0.x → 1.0.0. Тестов 302 → 925. Детекторов 17 → 20.
Экстракторов 8 → 12. Правил 7 → 12.

### Добавлено

**Экстракторы (12 вместо 8):**
- `extractors/dhcp.py` (180) — MAC + hostname из BOOTP/DHCP.
- `extractors/ssh_banner.py` (104) — SSH server/client version,
  `ssh_client_attempts` для brute_force.
- `extractors/smtp.py` (130) — EHLO/MAIL FROM/RCPT TO/mailer.
- `extractors/ndp.py` (132) — NDP для IPv6 (neighbors, routers).
- `extractors/kerberos.py` (77) — cname, realm, sname.
- `extractors/tls_cert.py` (52) — X.509 из TLS handshake.

**Детекторы (20 вместо 17):**
- `detectors/ssh_brute_force.py` (58) — 20+ SSH-баннеров на пару.
- `detectors/smtp_spam.py` (108) — 50+ уникальных RCPT TO.
- `detectors/yara_detector.py` (81) — YARA на carved_files
  (опционально, если `yara-python` установлен).

**Правила Contradictions (12 вместо 7):**
- `a_sni_without_dns.py` — SNI без DNS-ответа.
- `h_dns_answer_mismatch.py` — SNI ≠ резолвнутый IP.
- `i_sni_cert_mismatch.py` — SNI ≠ CN/SAN сертификата.
- `j_self_signed_cert.py` — issuer == subject.
- `k_expired_cert.py` — not_after < ts flow.

**IPv6:**
- `paradox/parsers_ipv6.py` (207) — IPv6-парсер с extension chains.
- `paradox/analyzers/ndp.py` (46) — `analyze_ndp(packets)`.
- `paradox_gui/views/ipv6_view.py` (114) — вкладка IPv6.
- `PacketRecord.ipv6_meta` — traffic_class, flow_label,
  extension_chain, fragment_id.

**X.509:**
- `paradox/x509_der.py` (248) — DER-парсер.
- `paradox/x509_cert.py` (194) — `Certificate`, `parse_certificate`.
- `paradox/tls_cert.py` (122) — `parse_certificate_from_stream`.
- `CaptureState.tls_certs`.

**DNS-ответы:**
- `CaptureState.dns_answers_by_name`, `dns_answers_by_ip`.
- CNAME-цепочки через `_collect_ips_for` в facts.py.
- A/AAAA/CNAME из DNS-ответов (только `qr=1`).

**NXDOMAIN window:**
- `nxdomain_burst_window_sec=60`, `nxdomain_burst_min_ratio=0.2`.
- `CaptureState.dns_nxdomain_ts_by_src`.
- `_max_in_window` — двухpointer sliding window.

**Domain utils:**
- `paradox/domain_utils.py` (151) — `split_domain`, `base_domain`,
  `registered_label`, `matches_suffix`. Двухуровневые TLD
  (co.uk, com.au, co.jp, co.br, …).

**Timeline:**
- `paradox/timeline.py` (305) — `TimelineEvent`, `build_timeline`,
  `summarize_by_phase`. Kill-chain reconstruction.
- `_PHASE_BY_TYPE`, `_PHASE_ORDER`.
- `paradox_gui/views/timeline_view.py` (251) — вкладка «Таймлайн».

**Анализаторы:**
- `paradox/analyzers/absence.py` (53) — DNS без ответа,
  TCP без обратного flow.
- `paradox/analyzers/counterfactual.py` (77) — What-If.
- `paradox/analyzers/story.py` (65) — история хоста.

**IOC reporter:**
- `paradox/reporters/ioc_reporter.py` (349).

**GUI вкладки (8 вместо 5):**
- IPv6, Таймлайн, Экспорт, (Сравнение в v1.2.0).

**GUI компоненты:**
- `splash.py`, `logo.py`, `storage.py` (SQLite history),
  `settings_store.py`, `settings_rehydrate.py`, `secrets_store.py`,
  `profiles.py`, `ioc_utils.py`, `editable_list.py`.

### Изменено
- `paradox/__init__.py` — `__version__ = "1.0.0"`.
- `paradox_gui/__init__.py` — `__version__ = "1.0.0"`.
- `paradox/config.py` — новые секции:
  `nxdomain_burst_window_sec`, `nxdomain_burst_min_ratio`,
  `smtp_spam_min_recipients`, `ssh_brute_force_min_flows`,
  `yara_rules_path`, `dns_tunneling_*`.
- `paradox/models.py` — `Finding.__post_init__` нормализует
  `src_ip`/`dst_ip`/`severity`/`mitre_techniques` из evidence.
  `_SEVERITY_BY_TYPE` карта.
- `paradox/reporters/markdown_reporter.py` — секция Timeline.

### Исправлено
- `cloud_tunnel_domain` — `type` переименован из `cloud_tunnel`
  (детектор не находился).
- `_SEVERITY_BY_TYPE` не покрывал новые типы — тест-страж в v1.1.0.

### Тесты
- 302 → **925 passed** (+623 за 3 версии, в основном contradictions
  и экстракторы).

## [0.9.0] — 2026-10-14

DNS-ответы, X.509, SSH/SMTP/DHCP/YARA, IPv6, 5 правил, NXDOMAIN window.
Детекторов 17 → 20. Экстракторов 8 → 12. Правил 7 → 12.
Тестов 302 → 500+.

### Добавлено

См. v1.0.0 — здесь ядро репозитория перешло от «набора работающих
правил» к полной инфраструктуре. Все модули, перечисленные выше
в v1.0.0, появились в v0.9.0 и были стабилизированы в v1.0.0.

Ключевые изменения:
- **DNS-ответы:** `dns_answers_by_name`, `dns_answers_by_ip`.
- **X.509 парсер:** `x509_der.py`, `x509_cert.py`, `tls_cert.py`.
- **5 новых правил:** sni_without_dns, dns_answer_mismatch,
  sni_cert_mismatch, self_signed_cert, expired_cert.
- **NXDOMAIN window:** `nxdomain_burst_window_sec=60`.
- **Экстракторы:** DHCP, SSH banner, SMTP, NDP, Kerberos, TLS cert.
- **Детекторы:** SSH brute force, SMTP spam, YARA.
- **IPv6:** `parsers_ipv6.py`, NDP-анализатор, IPv6View.
- **domain_utils.py:** двухуровневые TLD.

### Исправлено
- `cloud_tunnel` → `cloud_tunnel_domain` (не находится детектором).
- `ExpiredCertRule` — `not_after_ts` из ISO в unix ts.
- `SniCertMismatchRule` — wildcard `*.example.com` matches
  `a.example.com`, не `a.b.example.com` (RFC 6125).

### Тесты
- 302 → 500+ (полная переработка тестовой инфраструктуры,
  `pytest-qt`, offscreen).

## [0.8.0] — 2026-10-14

Timeline / kill-chain reconstruction.

### Добавлено
- `paradox/timeline.py` (305) — `TimelineEvent`, `build_timeline`,
  `summarize_by_phase`.
- `_PHASE_BY_TYPE`, `_PHASE_ORDER` — маппинг type/rule → фаза.
- Секция Timeline в Markdown-отчёте.
- `report["timeline"]` — плоский список TimelineEvent, отсортирован.
- `paradox_gui/views/timeline_view.py` (251) — вкладка «Таймлайн»
  (QTreeWidget по фазам).

### Изменено
- `paradox/reporters/markdown_reporter.py` — секция Timeline
  использует `report["timeline"]`, fallback на старое поведение.
- `paradox/models.py::Finding` — `mitre_techniques` instance-level
  приоритетнее type-map.

### Исправлено
- Deterministic timeline: sort by (ts, chain_order, subject, type, kind).

### Тесты
- 302 → 339 (+37 в `test_timeline.py`).

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

**Major** (1 → 2) — несовместимые изменения API.

**Minor** (1.1 → 1.2) — новая функциональность, старая совместима.

**Patch** (1.2.0 → 1.2.1) — исправления, оптимизация.

### Что считается major

- Удаление поля из JSON-схемы.
- Переименование существующего поля.
- Изменение контракта экстрактора или детектора.

### Что считается minor

- Новый экстрактор, детектор, правило contradictions.
- Новое поле в JSON-схеме.
- Новая секция в Markdown-отчёте.
- Новая вкладка в GUI.

### Что считается patch

- Исправление false positive.
- Исправление бага в парсере.
- Оптимизация производительности без изменения API.
