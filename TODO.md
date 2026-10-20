# TODO — Paradox v1.2.0

Состояние проекта на 2026-10-20. Что в работе, что дальше.
Сделанное — в `CHANGELOG.md`, описание модулей — в `MODULES.md`.

## В работе

Ничего. v1.2.0 закоммичен, тесты зелёные (942 passed), тег `v1.2.0`
поставлен.

## Перед публичным релизом

### 1. Сборка .exe (обязательно)

- [ ] `pyinstaller pcap-triage.spec --clean`
- [ ] Проверить `hiddenimports` под v1.2.0: `attack_graph`,
      `multi_pcap`, `splash`, `logo`, `run_diff` — все в spec
- [ ] Запустить `dist/Paradox/Paradox.exe` на **чистой машине**
      без Python (VM или другой ПК)
- [ ] Проверить: splash → окно → прогон pcap → граф атаки →
      multi-pcap → About → история

### 2. Мелкие баги в коде

- [ ] `NDPExtractor` без `layer = 0` — нарушает Protocol `Extractor`.
      `paradox/extractors/ndp.py`, 1 строка.
- [ ] `paradox/__init__.py` + `paradox_gui/__init__.py` —
      `__version__ = "1.0.0"`, тег `v1.2.0`. Синхронизировать
      на `"1.2.0"`.
- [ ] `tests/test_multi_pcap.py` — **0 тестов** (файл есть, пуст).
      Написать 3-4 минимальных теста на `merge_capture_states`.
- [ ] `pyproject.toml` — нет `[project.scripts]`. `paradox` не в
      PATH после `pip install -e .`. Добавить:
      ```toml
      [project.scripts]
      paradox = "paradox.cli:main"
      paradox-gui = "paradox_gui.app:main"
3. GitHub Release
□ Создать Release на github.com/v314xm/paradox/releases/new
□ Прикрепить Paradox-v1.2.0-win64.zip (папка dist/Paradox/)
□ В описании: ссылка на README, скриншоты, фичи
4. Лендинг (GitHub Pages)
□ index.html — hero, фичи, скриншоты, Download-кнопка
□ style.css — тёмная тема в стиле GUI
□ Settings → Pages → deploy from main/root
□ Ссылка на сайт — в README и Release
Следующее (v1.3.0)
Плагинная система (1-2 дня)
Главная фича v1.3. Превращает Paradox из «коробки» в «платформу».

□ paradox/plugins/loader.py — автозагрузка .py из
~/.paradox/plugins/, валидация контракта LocalDetector
/ ContradictionRule, изоляция ошибок.
□ Config.plugins_dir: Path | None, Config.enabled_plugins.
□ pipeline._detect() — конкатенация DETECTORS + load_plugins().
□ GUI: вкладка «Плагины» — список, статус загрузки, ошибки.
□ plugins/README.md — контракт + пример.
□ tests/test_plugins.py — рабочий плагин, битый плагин,
приоритет над встроенными.
PDF-экспорт (2-3 часа)
□ Кнопка «Экспорт → PDF» в главном меню.
□ paradox_gui/reporters/pdf_reporter.py — QPdfWriter +
QTextDocument. Markdown уже готов → конвертировать в HTML
→ PDF.
□ Тест: PDF создаётся, размер > 0.
STIX 2.1 экспорт (1 день)
□ paradox/reporters/stix_reporter.py — Indicator (ipv4,
domain, hash) + Bundle + Relationship к Malware.
□ paradox/reporters/ioc_reporter.py — добавить stix.json
в экспорт.
Улучшения detection
□ beaconing windowing — медленные C2 (интервал > часа).
Требует CaptureState с временными окнами или
FlowAggregator.
□ sni_mismatch — уменьшить шум. На FIN-2015 было 73 FP.
Context-aware allowlist: если CDN в этом же pcap — не шуметь.
□ JA3 браузеров в config.ja3_known_tools — Chrome/Firefox.
Сейчас ja3_ua_mismatch работает только на tool/malware.
□ SuccessfulBruteforceLogin — cross-finding:
brute_force + URI с loginok/success/dashboard.
В CyberCampTask было POST /loginok.html после 218 POST.
□ RareExternalIP — 1-2 flow к внешнему IP. Beaconing
не увидит, а сигнал есть.
□ LongConnections — сессии > 30 минут.
□ ProtocolBreakdown в summary: by_l4 (tcp/udp/icmp),
by_l7 (dns/tls/http).
Дальше (v2.0+)
Крупные фичи, требующие отдельной итерации:

□ REST API (FastAPI) + Web UI — веб-версия без PySide6.
□ HTTP/2 framing — HPACK для headers, для внутреннего C2.
□ SMB2-парсер — для AD-сценариев.
□ LDAPExtractor — для AD-сценариев.
□ AD-детекторы: Kerberoasting, DCSync, ADRecon.
□ IncidentReportReporter — шаблон для IR с timeline-фокусом.
□ MISP export — iocs.misp.json для threat-sharing.
□ Paradox follow — выгрузить TCP-поток в отдельный pcap.
□ Paradox diff-pcap — сравнить два pcap (не отчёта).
□ Paradox filter — фильтр по IP/порту/протоколу.
Известные долги
Технические
□ paradox/contradictions/facts.py — 927 строк. Разбить по
source (attack, arp, tls, ja3, asym, port, direct, cert).
□ paradox/reporters/markdown_reporter.py — 976 строк.
Вынести секции в подмодули.
□ paradox_gui/views/settings_view.py — 2021 строк. Разбить
по секциям (_build_thresholds_page → settings/thresholds.py).
□ paradox/aggregators/entities.py дублирует полярность
findings с contradictions/facts.py. Вынести в общий
paradox/findings_polarity.py.
□ run_multi_pipeline дублирует ~140 строк run_pipeline.
Извлечь общий _build_report(state, findings, contradictions).
Семантика
□ Finding.severity = "medium" — не «дефолт», а «не задано».
Сейчас детектор не может явно поставить medium для типа из
_SEVERITY_BY_TYPE. Изменить на severity: str | None = None
(breaking, для v2.0).
□ NXDOMAINBurstDetector ratio-фильтр — работает, но beaconing
ещё требует windowing.
Detection
□ beaconing не ловит медленный C2 (интервал > часа).
□ Внутренний C2 (internal→internal зашифрованный) — вне зоны
видимости без HTTP/2 framing.
□ TLS 1.3 Certificate зашифрован — правила на сертификатах
только для TLS 1.2.
Парсинг
□ QinQ (двойной VLAN) не поддержан.
□ IPv6 IOC в reporter — есть, но не покрыт тестом.
□ make_test_pcap.py генерирует только IPv4.
