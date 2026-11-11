# TODO — Paradox: роадмап после 1.5.0

Состояние на 2026-11-10. Последний релиз — **1.5.1**, тег `v1.5.1`;
волна 1 — коммит `c4e0535`. Волна 2 сделана по коду в `main`, но ещё
не выпущена. Сделанное — в `CHANGELOG.md`, описание модулей — в
`MODULES.md`.

Приоритеты: **P0** — неверный вердикт, потеря данных или сломанный релиз;
**P1** — заметная ошибка или риск; **P2** — долг, который пока не жжёт.
Порядок волн выбран владельцем: **1 → 2 → 3 → 4**.

## Базовые метрики (тесты и скорость — 2026-11-10, остальное — 2026-11-09)

| Метрика | Значение | Как измерено |
|---|---|---|
| Тесты | 1234 без Qt + 129 GUI = **1363** | `pytest --junitxml`, маркер `gui` |
| Покрытие ядра | **85.7%** | `tools/coverage_gate.py` |
| Покрытие GUI | **63.0%** | там же, GUI-тесты входят в прогон |
| Ruff | чисто | `ruff check paradox tests paradox_gui tools` |
| Прогон 335 МБ / 627 694 пакетов | **14.4 с**, 8 findings, 2 contradictions | `CyberCampTask.pcap`, без tracemalloc (было 24.2 с) |
| Пик Python-heap | ~32 МБ | tracemalloc (с замедлением прогона) |

---

# Волна 1 — Правда и качество (v1.5.1 → v1.6.0)

Цель: документация и интерфейс перестают врать, молчаливые потери данных
становятся видимыми, у находок один источник правды о ролях.

Пункты с `[x]` закрыты в волне 1 (2026-11-09). Текст под ними описывает
исходную проблему; актуальное поведение — в коде и тестах.

**Результат волны 1:** 1288 теста (0 падений), покрытие ядра 85.4%,
`ruff` чист, контрольный прогон 627 694 пакетов — 7 findings и
2 contradictions без изменений. Добавлены `paradox/taxonomy.py`,
`paradox/errors.py`, `tools/coverage_gate.py`, `SECURITY.md`,
`docs/OPERATIONS.md`.

## 1.1 Документация = код

- [x] **P0** `ARCHITECTURE.md` — заголовок и «Известные ограничения»:
      версия 1.5.0, 24 детектора (не 20), 12 экстракторов + 3 post-extract,
      убрать исправленные NDP/merge/version пункты, добавить `payload_excerpt`,
      `html_reporter`, `stix_reporter`, `detector_plugins`.
- [x] **P0** `MODULES.md` — заголовок 1.5.0; таблица детекторов: 24 строки
      (нет `ja3s_malware`); экстракторы 12 + post-extract отдельно; убрать
      расхождения 11 931 / 13 479 и 892 / 790; починить per-group таблицу тестов.
- [x] **P1** `README.md` — из «Дальше» убрать PDF-экспорт и вкладку плагинов
      (вышли в 1.5.0), оставить реальный backlog; дать ссылку на сайт;
      синхронизировать число тестов с прогоном.
- [x] **P1** `docs/OPERATIONS.md` — установка `.exe` и `setup.exe`, обновление,
      удаление, где лежат данные (`%APPDATA%\Paradox`, `~/.paradox/plugins`,
      `reports/`), коды выхода, лимиты pcap/RAM, где смотреть
      `Paradox-error.log`, предупреждение «плагин = произвольный Python».
- [x] **P1** `SECURITY.md` — модель доверия: плагины исполняются с правами
      пользователя, `--enrich` отправляет IOC во внешние сервисы, отчёт может
      содержать чувствительные данные. Ссылка из README.
- [x] **P2** `CHANGELOG.md` — восстановить запись `1.3.0` по коммитам
      (тег `v1.3.0` есть, записи нет).
      Сделано: раздел `[1.3.0] — 2026-10-22` по коммитам до `ba22bc4`,
      с пометкой, что он восстановлен задним числом.
- [x] **P2** Удалить `paradox_gui/views/roadmap_view.py`: файл нигде не
      подключён, описывает v0.7.0 и противоречит текущему GUI. Единственный
      роадмап — этот файл. Заодно убрать QSS-правило `#roadmapBrowser`.
      Сделано 2026-11-10: файл удалён, QSS-блок и комментарий убраны,
      упоминания вычищены из `ARCHITECTURE.md` и `MODULES.md`.

## 1.2 Границы API и ввод

- [x] **P0** `run_pipeline` / `run_multi_pipeline` принимают `str | Path`:
      сейчас `run_pipeline("file.pcap", ...)` падает на
      `pcap_path.stat()`. Нормализовать `Path(p)` на входе.
- [x] **P1** Ошибки формата pcap: не-`pcap`, обрезанный файл, `.pcapng`
      сейчас вылетают трейсбеком из `RawPcapReader`. Ввести
      `ParadoxInputError` с понятным сообщением, перехватывать в CLI и GUI;
      `.pcapng` — либо поддержать `PcapNgReader`, либо явно отказать.
      Сделано: pcapng, отсутствие файла и обрезанная запись →
      `ParadoxInputError` (код 3); собственный `PcapRecordReader`
      бросает `PcapFormatError`, pipeline переводит его в ошибку входа.
- [x] **P1** `paradox capture.pcap --version`; зафиксировать коды выхода
      (0 — успех, 2 — нет файла, 3 — формат, 4 — внутренняя ошибка) и
      описать их в `OPERATIONS.md`.
- [x] **P2** `sha256_file` читает pcap вторым полным проходом после разбора.
      Считать хэш в том же цикле или до него по открытому файлу.
      Сделано: `PcapRecordReader` считает sha256 в том же проходе,
      что и разбор; второй проход остался только страховкой на случай
      хвостового мусора.

## 1.3 Единая таксономия findings — `paradox/taxonomy.py`

Сейчас «кто атакующий, кто жертва» задаётся в двух таблицах, которые уже
разошлись; MITRE, фазы kill-chain, порядок цепочки и ранги severity —
в пяти местах. Из-за этого `http_binary_upload` (исходящая эксфильтрация)
попадает в `attacker_candidate`, а TL;DR печатает «внутренний атакует
внешний».

- [x] **P0** `SRC_ROLE_BY_TYPE` — по одному типу из
      `paradox/detectors/*`: `attacker` или `victim` на `src_ip`.
      Подключить в `contradictions/facts.py`, `aggregators/entities.py`,
      `timeline.py`, `analyzers/attack_graph.py`.
- [x] **P0** Тест-страж: собрать все `Finding.type`, которые умеют
      выдавать детекторы, и проверить, что каждый описан ровно один раз.
- [x] **P1** Перенести в `taxonomy.py` `MITRE_BY_TYPE`, `PHASE_BY_TYPE`,
      `PHASE_ORDER`, `SEVERITY_BY_TYPE`, `SEVERITY_RANK`; удалить копии из
      `detectors/mitre_map.py`, `reporters/markdown_reporter.py`,
      `timeline.py`, `attack_graph.py`, `contradictions/base.py`,
      `reporters/{ioc,html}_reporter.py`.
- [x] **P1** `Finding.severity: str | None = None`: сейчас детектор не может
      явно поставить `medium` для типа, у которого в карте стоит `high`.
      Сделано: `None` — «взять из карты», любое заданное значение (в том
      числе `medium`) остаётся как есть.
- [x] **P2** Убрать расхождения MITRE: `brute_force` T1110.001 vs T1110,
      `script_download` T1189 vs T1105, `command_injection` (T1190,T1059)
      vs T1059, `lateral_movement` T1021.00x vs T1021.
      Сделано вместе с волной 1: после сведения в `taxonomy.py` копий
      больше нет. Осознанные исключения — `large_transfer` (техника по
      направлению) и `carved_file` в timeline.

## 1.4 Тихие потери данных и неверные вердикты

- [x] **P0** Multi-pcap: `merge_capture_states` склеивает байты TCP-потоков
      одного 5-tuple из разных файлов (`multi_pcap.py`) — получается поток,
      которого не было, и ложные webshell/YARA/сертификаты. Хранить потоки
      по файлам или отбрасывать коллизию со счётчиком.
- [x] **P0** Исчерпание бюджета reassembly (200 МБ) сейчас молча отключает
      HTTP/webshell/YARA до конца захвата и не освобождает уже разобранные
      потоки. Освобождать после post-extract, считать `streams_dropped_bytes`
      и показывать предупреждение в summary/TL;DR.
- [x] **P0** `g_direct_ip_no_dns`: правило не смотрит на собранные
      `makes_dns_queries`, а «≥10 flows» считает как «≥10 портов».
      Добавить guard по DNS-запросам, считать реальные flows, переписать
      устаревший docstring.
- [x] **P1** Одно определение internal/external IP: сейчас четыре
      (`net_utils.is_internal_ip`, `is_private_ip`, `facts._looks_like_public_ip`,
      `suspicious_port._is_private`), из-за чего STIX/IOC/entities
      расходятся по одному адресу. Один `ip_scope()` на `ipaddress` +
      `Config.private_networks`; тесты на `FE80::1`, `::ffff:10.0.0.1`,
      `100.64.1.1`.
- [x] **P1** `absence` и `dns`-секции не ограничены top-N: на сканирующем
      захвате отчёт раздувается до сотен тысяч строк. Добавить лимит и
      общий счётчик; не считать «DNS без ответа» запрос, на который пришёл
      TXT/MX/SOA.
- [x] **P1** DNS: NXDOMAIN считается по каждому пакету ответа (ratio > 1.0),
      DNS-over-TCP не снимает 2-байтный length-prefix. Дедуп по
      `(client, qname, txid)`, снять префикс.
- [x] **P1** `CaptureState` — объявить `ndp_total`, `ndp_neighbors`,
      `ndp_routers` полями dataclass вместо `hasattr`/`getattr` в трёх местах.
- [x] **P2** YARA: нет `rules/default.yar` → детектор всегда пуст; правила
      компилируются заново каждый прогон; матчится только первые 64 байта.
      Добавить правила через `importlib.resources`, кэш по mtime, полное тело.
      Сделано: `paradox/rules/default.yar` (`.spec` + package-data), кэш по
      `(путь, mtime, размер)`, скан `CarvedFile.body` целиком.
- [x] **P2** X.509: сертификат, начинающийся не с handshake record или
      размазанный по нескольким TLS-записям, теряется; ошибки DER глотаются
      без счётчика. Добавить `tls_cert_parse_errors` и секцию `certificates`
      в отчёт.
      Сделано: handshake склеивается через границы записей, поиск записи
      начинается после мусорного префикса, ошибки DER считаются и попадают
      в summary и markdown (`## X.509 сертификаты`).

## 1.5 GUI-надёжность (мелкое, но видимое)

- [x] **P1** `Ctrl+,` открывает вкладку «Обогащение» вместо «Настроек»:
      `main_window.py` хардкодит `setCurrentIndex(3)`; заменить на
      `indexOf(self.settings_view)`.
- [x] **P1** В трёх слотах `finished` читается `self._worker`, а не
      `self.sender()` (`run_view`, `enrich_view`, `quick_check_window`) —
      можно потерять ссылку на живой `QThread` и уронить процесс.
- [x] **P1** У `QuickCheckWindow` нет `closeEvent`: закрытие во время
      запроса уничтожает работающий `QThread`. Добавить stop/wait.
- [x] **P1** Между прогонами не чистятся `observations`, `absence`,
      `highlights`; во время нового прогона на экране данные прошлого pcap.
      Добавить `clear()` и вызывать из `_reset_results`, а также сбрасывать
      `enrich_view`/`export_view` на `analysis_started`.
- [x] **P1** Настройки плагинов сохраняются, но не восстанавливаются:
      `_plugins_inputs` нет в кортеже `load_from_store`.
- [x] **P2** Удалить мёртвый код: `_PLACEHOLDER_TEXT`, `_placeholder_page`,
      `_add_bool_row`, `_add_int_row_pf`, `_reset_thresholds`, `_field_hints`,
      `_act_analyze_cfg`, `_stop_requested`, `findings_table` маркер
      `# ← ЭТА СТРОКА`, `tests/reports` и `tests/tests`.
      Сделано 2026-11-10: удалены `_PLACEHOLDER_TEXT`, `_placeholder_page`
      (в `main_window.py`; в `settings_view.py` он живой fallback),
      `_add_bool_row`, `_add_int_row_pf`, `_reset_thresholds`, пустые
      каталоги `tests/reports` и `tests/tests`. Список был устаревшим:
      `_field_hints`, `_act_analyze_cfg`, `_stop_requested` используются,
      маркер `# ← ЭТО СТРОКА` давно убран.
- [x] **P2** Удалить 13 `*.bak`-снимков из `paradox_gui/` и
      `tests/test_i18n.py.*.bak`; убрать `.pyc` без `.py`
      (`widgets/__pycache__/empty_states...`).
      Сделано: было не 13, а 18 `*.bak` — они сначала упакованы в
      `.qwen/tmp/paradox-baks-2026-11-10.zip`, потом удалены; удалены
      13 осиротевших `.pyc` (включая 11 от исчезнувших `tools/fixes/*.py`).
- [x] **P2** Экранировать данные отчёта перед `setHtml` в `timeline_view` и
      `host_story_dialog` (как уже сделано в `history_view`); убрать
      русский литерал-сентинел `"Другие внешние"` из `graph_dialog`.
      Сделано: `html.escape` на всех полях из отчёта; в графе остался
      только структурный признак подсети (`"/" in ip`).

## 1.6 Тесты, покрытие, гигиена

- [x] **P1** Удалить `tests/test_multi_pcap.py` — это ручной скрипт под
      `skip`, слияние уже покрыто `tests/test_multi_pcap_merge.py` (21 тест).
      Сделано: удалён; ручной прогон остался в `tools/test_multi_pcap.py`.
- [x] **P1** Расширить `tests/test_version_consistency.py`: сейчас сверяются
      только `pyproject` ↔ ядро ↔ GUI. Добавить `installer/version_info.txt`,
      `installer/paradox.iss`, `docs/index.html`, README; туда же — проверку
      `len(DETECTORS)`, `len(RULES)`, `len(EXTRACTORS)` и числа вкладок
      против чисел в README.
- [x] **P1** Локальный coverage-гейт: `tools/coverage_gate.py` с порогами
      (ядро ≥ 80%, GUI — не ниже базовой линии), обход `0xC0000005` через
      `--junitxml` и `coverage run`. Запускать перед релизом.
- [x] **P2** Тесты на жизненный цикл воркеров (`AnalysisWorker`,
      `EnrichmentWorker`, `QuickCheckWorker`): отмена, повторный запуск,
      закрытие окна. Сейчас на них нет ни одного теста.
      Сделано: `tests/test_gui_workers.py` (9 тестов) — успех, отмена
      через `PipelineCancelled`, ошибка, фильтр отключённых детекторов,
      кэш и сбой провайдера в `QuickCheckWorker`, закрытие оркестратора
      в `EnrichmentWorker`. Сигналы проверяются вызовом `run()` без
      event loop.
- [x] **P2** Регрессии разложены по трём пересекающимся файлам
      (`test_regressions`, `test_p0_regressions`, `test_p1_regressions`) —
      зафиксировать правило, куда писать новую.
      Сделано: `tests/README.md` — FP → `test_regressions`, аудиторские
      P0/P1 → `test_p0/1_regressions`, функциональность → тематический файл.
- [x] **P2** Пометить маркерами GUI/сетевые/pcap-тесты; `slow` сейчас только
      у двух тестов.
      Сделано 2026-11-10: `gui` в 22 Qt-модулях (128 тестов), `pcap` в
      `test_pipeline_e2e.py` (3), `network` зарегистрирован как задел —
      сетевых тестов нет. `slow` реально у одного файла
      (`test_performance.py`), а не у двух.

## 1.7 Воспроизводимость релиза

- [x] **P0** Сборка не воспроизводима: `Paradox.spec` и `paradox.ico`
      в `.gitignore`, в spec абсолютные пути
      `C:\Users\a.grigoryev\...`. Добавить в git, убрать пути.
- [x] **P0** Два расходящихся пути сборки: `tools/build_installer.py`
      не передаёт `--icon` и не использует spec; spec включает UPX.
      Оставить один путь и описать его.
- [x] **P1** `SHA256SUMS` в релизе + пометка «бинарник не подписан» рядом
      с кнопкой скачивания в README и на сайте.
- [x] **P1** Удалить легаси `installer/pcap-triage.iss` (v1.0.0, другой
      AppId) — он создаёт вторую запись в «Установке и удалении».
      Сделано: удалён; единственный установщик — `installer/paradox.iss`.
- [x] **P1** Починить mojibake `В© 2026` в `installer/paradox.iss`
      (шаблон в `tools/build_installer.py`).
- [x] **P2** Сайт: 28.1 с против 19 с в README на одном и том же захвате;
      «Windows, Linux, macOS» при наличии только Windows-артефактов;
      Schema.org `url` не совпадает с `CNAME` (`paradoxtool.ru`).
      Сделано: везде 23–28 с (замер 2026-11-10), на сайте явно «exe только
      для Windows, из исходников — три ОС», Schema.org `url` =
      `https://paradoxtool.ru/`. Числа тестов в README/MODULES/сайте
      синхронизированы с прогоном: 1312.
- [x] **P2** `tools/verify_all.py` ссылается на 4 отсутствующих скрипта и
      печатает «ALL GREEN», когда проверять нечего. `tools/README.md`
      документирует 7 несуществующих файлов.
      Сделано: verify_all = ruff + полный pytest с итогом из junit-отчёта
      (обход `0xC0000005`); фантомные «фиксы» и targeted-список удалены.
      README переписан по фактическому содержимому `tools/`.

---

# Волна 2 — Детекция (v1.6.x)

Цель: меньше ложных срабатываний при большем покрытии, каждое изменение —
с замером на трёх эталонных захватах.

Замеры 2026-11-10 (до/после): 2025-06-13 — 10 findings, FIRST-2015 — 0,
CyberCampTask — 7 → 8 (`successful_bruteforce`). Новые правила на
эталонах молчат — это проверено, а не предположено.

- [x] **P1** `rare_external_ip` — 1–2 соединения к внешнему IP.
      Наивный вариант на эталонах дал 52 «редких» адреса. Дизайн:
      обязательный фильтр «IP не встречался в `dns_answers_by_ip`»
      плюс «нет SNI/Host», «виден SYN», allowlist адресов и
      инфрапортов. На обоих эталонах — 0 кандидатов после фильтра.
      Без DNS-ответов в захвате детектор молчит.
      Сделано: `paradox/detectors/rare_external_ip.py`,
      `tests/test_rare_external_ip.py` (14 тестов).
- [x] **P1** `long_connections` — сессии > 30 минут. 39 длинных
      NTP/SMB/SSDP сессий на эталонах — это UDP-агрегаты по 5-tuple,
      а не сессии. Дизайн: только TCP, только видимый SYN, только
      внутренний→внешний, ≥ 30 мин, ≥ 5 пакетов, без имени из
      allowlist, порты SSH/почты/VPN/БД/RDP/VNC исключены.
      Замер: во всех трёх эталонах одна такая сессия — WNS
      (`client.wns.windows.com`), она в allowlist → 0 findings.
      Сделано: `paradox/detectors/long_connections.py`,
      `tests/test_long_connections.py` (13 тестов).
- [x] **P1** `sni_mismatch` — 73 FP на FIN-2015. Проверка 2026-11-10:
      детектор даёт **0** findings на FIN-2015. Сравнение с
      DNS-ответами и CDN-allowlist уже закрыли прежний шум (пункт
      описывал состояние до 1.5.1). Отдельный код не потребовался.
- [x] **P1** `SuccessfulBruteforceLogin` — cross-finding: `brute_force` +
      URI с `loginok/success/dashboard`. Сделано внутри
      `brute_force.py`: второй finding `successful_bruteforce` на тот
      же bucket. На CyberCampTask срабатывает (218 POST в
      `/loginok.html`), findings 7 → 8. HTTP-статуса в FlowStats нет,
      поэтому confidence ≤ 0.85 и `http_status_known=false`.
- [ ] **P2** JA3 браузеров — только проверенные хеши Chrome/Firefox,
      иначе источник FP; сейчас `ja3_ua_mismatch` работает на
      tool/malware. Проверено 2026-11-10: в эталонных захватах
      браузерные JA3 есть, но подтвердить их принадлежность Chrome/
      Firefox нечем (у клиента нет браузерного UA). Нужен список
      проверенных хешей от владельца — без него добавлять нельзя.
- [ ] **P2** Медленный beaconing: пороги описаны в
      `docs/OPERATIONS.md` (fast/slow, таблица и ограничения).
      Осталось прогнать на реальном C2 с интервалом > часа — такого
      pcap в эталонах нет; slow-путь покрыт синтетическими тестами.
- [x] **P2** `ja3s_malware`: `ja3s_known_tools` в Config не читался —
      ключ удалён (он был пустым и нигде не использовался).
- [x] **P1** `encoded_payload` (добавлено 2026-11-10 по кейсу
      `POST /wpfilebase-pro/stats-sink.php`): base64/hex в query или
      теле формы, декодирующийся в URL/домен. Реальный кейс:
      10-пакетный захват, `site=aHR0cHM6Ly9taW5maW4uc2FtcmVnaW9uLnJ1`,
      до детектора findings было 0. На трёх эталонах — 0 FP. Сделано:
      `paradox/detectors/encoded_payload.py`,
      `tests/test_encoded_payload.py` (10 тестов).

# Волна 3 — Архитектура и скорость (v1.7.0)

Цель: 335 МБ быстрее 15 с, предсказуемая память, файлы, которые можно
читать.

- [x] **P0** Разбить `paradox_gui/views/settings_view.py` (2218) на пакет
      `settings/`: `constants`, `parsers`, `builders`, `view`, `pages/*`.
      Сделано 2026-11-10: `view.py` (679) — сигналы, каркас, поиск,
      загрузка/сохранение; `builders.py` — общие строители форм;
      `constants.py` — секции/детекторы/правила; `parsers.py` — порты и
      строки; `pages/` — 13 миксинов по странице. `settings_view.py`
      остался совместимым фасадом на 30 строк, поэтому `main_window` и
      тесты не менялись. Набор из 85 методов сверен с прежним классом —
      потерь нет.
- [x] **P0** Разбить `paradox_gui/theme.py` (1296) на `theme/`:
      `palette`, `qss_global`, `qss_widgets`, `assets`, `apply`, `win32`.
      Сделано 2026-11-10: пакет `paradox_gui/theme/` — `palette.py`,
      `qss_global.py` (базовые правила), `qss_widgets.py` (служебные
      классы и виджеты), `qss.py` (сборка), `assets.py` (шевроны),
      `apply.py`; `__init__.py` реэкспортирует прежний API. Win32-кода
      в файле не было — `win32` в списке оказался лишним. QSS сверен
      с прежним шаблоном побайтово.
- [x] **P1** Разбить `main_window.py` (900) на `shortcuts`, `menus`,
      `export`, `actions`, `window`.
      Сделано 2026-11-10: пакет `paradox_gui/window/` (`window` 267,
      `actions` 306, `menus` 246, `export` 101, `shortcuts` 50);
      `main_window.py` — фасад на 23 строки. Все 36 методов на месте,
      окно проверено оффскрин; добавлен тест на совпадение
      `TAB_TITLES` с вкладками (попутно восстановлен `TAB_TITLES`,
      который импортировал `tools/docs_inventory.py`, но в файле его
      не было).
- [ ] **P1** Разбить `markdown_reporter.py` (992) на `markdown/format`,
      `sections_entities`, `sections_traffic`, `sections_analysis`.
- [ ] **P1** Разбить `facts.py` (950) на `facts_attack`, `facts_net`,
      `facts_tls`; убрать `extract_facts`, который не вызывается и уже
      потерял cert-факты.
- [ ] **P1** `config.py` (1017): вынести валидацию в таблицу
      `(name, predicate, message)`; убрать `mkdir` из `__post_init__`
      (создание `reports/` при каждом `Config()`).
- [ ] **P1** `pipeline.py` (689): `pipeline/extract.py`,
      `pipeline/summarize.py`, `pipeline/report.py`, тонкий фасад.
- [x] **P1** Профилирование и цель < 15 с на 335 МБ: один проход по flows в
      `build_entities`, `findings_indices` как `set`, `heapq.nlargest` в
      `flow_report`, один `findings_dicts` вместо трёх сериализаций.
      Сделано 2026-11-10: **24.2 → 14.4 с** на `CyberCampTask.pcap`
      (8 findings, 2 contradictions, sha256 сходится с файлом). Выигрыш
      дали не отчёты, а пакетный цикл: собственный читатель pcap
      `paradox/pcap_reader.py` вместо `RawPcapReader` (без обвязки
      scapy), заголовки Ethernet/IPv4/TCP одним `struct.unpack_from`,
      `FlowKey` как `NamedTuple`, `PacketRecord` со `slots`, быстрый
      выход reassembler'а на чистых ACK и sha256 пачками по 64 КБ.
      Профиль: 49.1 → 42.2 с под cProfile, то есть ускорение не за счёт
      отключения работы. Отчёты (`findings_dicts` и т.п.) остались в
      плане: на 8 findings их вклад < 0.5 с, оптимизировать раньше
      пакетного цикла было бессмысленно.
- [ ] **P1** Stream mode для pcap > 2 ГБ: не держать все потоки и отчёты в
      памяти, отдавать секции по мере готовности.
- [ ] **P2** Один HTTP-парсер: `http_parse.py` и `http_object.py` по-разному
      режут request-line (пробел в URI теряет объект).
- [ ] **P2** `attack_graph` и `entities` независимо выводят роли и фазы —
      свести к `taxonomy.py` + одному role engine.
- [ ] **P2** Слить два ASN.1 TLV-ридера (`x509_der`, `kerberos_parse`) в
      `paradox/der.py`.

# Волна 4 — Платформа v2.0

- [ ] **P1** SMB2-парсер и LDAP-экстрактор.
- [ ] **P1** AD-детекторы: Kerberoasting, DCSync, ADRecon.
- [ ] **P1** HTTP/2 framing + HPACK для внутреннего C2.
- [ ] **P2** MISP export (`iocs.misp.json`) для threat-sharing.
- [ ] **P2** REST API (FastAPI) + Web UI без PySide6.
- [ ] **P2** Нативный PDF (QPdfWriter) вместо печати HTML из браузера.
- [ ] **P2** `Paradox follow` — выгрузить TCP-поток в отдельный pcap.
- [ ] **P2** `Paradox diff-pcap` — сравнить два pcap, а не два отчёта.
- [ ] **P2** `Paradox filter` — фильтр по IP/порту/протоколу.

---

# Требует решения владельца

- [x] **CI-workflow** `.github/workflows/ci.yml` (ruff + pytest). Пока его
      нет, «1312 passed» — локальная цифра. Добавлять только по твоему
      явному согласию.
      Сделано 2026-11-10: ruff + `pytest -m "not slow"` на ubuntu-latest,
      Python 3.13, Qt-библиотеки для offscreen, junit в артефактах.
      Заработает после push.
- [x] **Подпись бинарника** — решение 2026-11-10: не подписываем,
      сертификат платный. Остаётся «unsigned + SHA256SUMS».
- [x] **Судьба `RoadmapView`** — решено 2026-11-10: удалён вместе с
      QSS-правилом `#roadmapBrowser`, десятая вкладка не нужна.
- [x] **Версия 1.3.0 в CHANGELOG** — восстановлена по коммитам
      (см. п. 1.1).

# Сделано в 1.5.0 (не повторять)

Плагины детекторов + секция в настройках, STIX 2.1, HTML-отчёт,
«Код инжекта» с выдержками и статическим предпросмотром,
`webshell_markers`, RU/EN-локализация, `http_binary_upload`, `php_payload`,
slow-beaconing, `by_l4`/`by_l7`, keep-alive HTTP-фикс (504 → 623 запросов).
