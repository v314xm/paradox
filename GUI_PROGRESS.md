# pcap-triage GUI — текущее состояние

Версия ядра: **0.7.0**. GUI — отдельный пакет `pcap_triage_gui/`,
ядро `pcap_triage/` **не тронуто**.

## Запуск

```powershell
cd C:\Users\a.grigoryev\PycharmProjects\Analityk
python -m pcap_triage_gui

Окно разворачивается на весь экран (showMaximized в app.py).

Что работает
Вкладка «Прогон» — полный цикл
Drop zone — drag&drop pcap, клик, меню Ctrl+O. После первого
прогона схлопывается в одну строку («📄 filename.pcap»), освобождая
место для таблицы. Drag&drop и клик продолжают работать.

Summary grid — 6 плиток: Пакеты, Flows, Findings, Противоречия
(красная рамка + красное число), Размер, Время.

Секция «Противоречия (N)» — карточки с severity-бейджем, rule,
subject, confidence, hint. Клик → inline facts. Кнопка «Подробнее»
→ модалка с полным разбором (facts, likely_causes, priority).

Таблица findings — Тип / Значение / Conf / MITRE / First seen.
Сортировка по любому столбцу. Двойной клик → модалка деталей.

Progress bar — бегающая полоска во время анализа (indeterminate,
setRange(0,0)).

Toast — уведомления в правом нижнем углу: зелёный «Готово»,
красный «Ошибка». Исчезают через 4 сек.

Статус-бар окна — «Готов / Анализ… / Готово · N findings ·
M противоречий». Справа версия.

Меню
Меню	Пункт	Статус
Файл	Открыть pcap… (Ctrl+O)	✅
Файл	Экспорт → JSON-отчёт…	✅ (enabled после анализа)
Файл	Экспорт → Markdown-отчёт…	✅
Файл	Экспорт → Flow report (conn.log)…	✅
Файл	Выход (Ctrl+Q)	✅
Прогон	Анализировать (F5)	✅
Прогон	Анализировать с настройками (Ctrl+F5)	⏳ disabled
Прогон	Остановить	⏳ disabled
Вид	5 вкладок	✅
Вид	Полноэкранный режим (F11)	✅
Помощь	О программе	✅
Помощь	Горячие клавиши	✅
Остальные вкладки
Заглушки: «Обогащение», «Настройки», «История», «Развитие».

Структура
text
pcap_triage_gui/
├── __main__.py                     python -m pcap_triage_gui
├── app.py                          QApplication + MainWindow + showMaximized
├── theme.py                        PALETTE + SEVERITY + QSS + apply_theme()
├── main_window.py                  menu bar + tabs + status bar + экспорт
├── views/
│   └── run_view.py                 вкладка «Прогон»
├── widgets/
│   ├── drop_zone.py                drag&drop + QFileDialog
│   ├── summary_grid.py             6 плиток
│   ├── contradiction_card.py       карточка противоречия
│   ├── contradictions_section.py   секция противоречий
│   ├── findings_table.py           таблица findings
│   └── toast.py                    всплывающие уведомления
├── dialogs/
│   ├── contradiction_dialog.py     модалка противоречия
│   └── finding_dialog.py           модалка finding'а
└── workers/
    └── analysis_worker.py          QThread над run_pipeline
Архитектурные правила
Ядро не знает про GUI. Импорт только в одну сторону:

python
from pcap_triage.pipeline import run_pipeline
from pcap_triage.config import Config
run_pipeline — только в QThread. Иначе UI зависает на 20+ сек.

Воркер дополняет report, но не меняет. В analysis_worker.py:
summary.setdefault("size_bytes", ...), summary.setdefault("duration_sec", ...).

QSS — единственный источник стилей. Все цвета в PALETTE, нигде
в виджетах хардкода hex.

Signal(object) для dict/list. Signal(dict) в PySide6 нестабилен.

Контракт данных от ядра
run_pipeline(pcap_path: Path, config: Config) -> dict

Используемые ключи:

python
report["summary"]         # packets, flows, findings, contradictions, ...
report["findings"]        # type, value, confidence, mitre_techniques,
                          # evidence, first_seen
report["contradictions"]  # rule, subject, severity, confidence, priority,
                          # likely_causes, resolution_hint, facts
report["provenance"]      # tool_version, pcap_path, pcap_sha256
report["flows"]           # top_by_bytes (используется в conn.log экспорте)
Ключевые решения и почему
Решение	Причина
Модалки, а не drawer для деталей	Проще, соответствует прототипу
Severity НЕ в таблице findings	В ядре её нет, маппинг type→severity = вторая правда
Progress bar indeterminate	Ядро пишет прогресс в stdout, callback не отдаёт. Правка ядра запрещена
Остановить отложено	Требует правки ядра или опасного worker.terminate()
Экспорт JSON через json.dump напрямую	Не зависим от имени функции в ядре (write_json/save_json/…)
Ctrl+O дублируется кириллицей	Qt матчит shortcut по символу, не по физической клавише
Drop zone схлопывается	Экономит ~120px для таблицы findings
Грабли, которые уже решены
Симптом	Причина	Решение
SyntaxError: invalid decimal literal в theme.py	Одинарные {} вокруг CSS-блока в .format()-строке	Удвоить: {{ }}
ModuleNotFoundError: pcap_triage_gui.views	Нет __init__.py в подпапке	Создать пустой файл
NameError: QSizePolicy в run_view.py	Патч скопирован не в тот файл	QSizePolicy только в summary_grid, contradictions_section, findings_table
Findings в 1 строку	addStretch(1) в конце _build_ui ИЛИ нет setMinimumHeight	Удалить stretch, добавить setMinimumHeight(280)
Ctrl+O не работает в русской раскладке	Qt матчит по символу	_act ставит setShortcuts([лат, кир])
«Файл → Открыть» не открывает диалог	Отступ метода 8 вместо 4	Select-String для проверки
AttributeError: 'RunView' object has no attribute 'last_report'	Не применён патч _last_report	Добавить 4 вставки в run_view.py
Toast не показывается	Файл toast.py в widgets/widgets/	Перенести в widgets/
Маркеры вставки в файлах
В main_window.py и run_view.py есть маркеры:

python
# >>> ИМЯ МАРКЕРА <<<
# ...
# >>> /ИМЯ МАРКЕРА <<<
Куда что вставлять — по имени маркера:

>>> ИМПОРТЫ VIEWS <<< (main_window) — импорты новых вкладок

>>> ДОБАВИТЬ МЕНЮ <<< (main_window) — вызовы _menu_xxx

>>> ФАЙЛ: ЭКСПОРТ <<< — новые форматы экспорта

>>> ДОБАВИТЬ ВКЛАДКИ <<< — замена заглушек на реальные view

>>> СИГНАЛЫ ОТ RunView <<< / >>> СИГНАЛЫ ОТ ДРУГИХ VIEWS <<< — слоты

>>> ИМПОРТЫ ВИДЖЕТОВ <<< (run_view) — импорты виджетов

>>> МЕСТО ДЛЯ FINDINGS_TABLE <<< / >>> МЕСТО ДЛЯ ... <<< — размещение

>>> ЗАПОЛНЕНИЕ ДРУГИХ СЕКЦИЙ <<< — в _on_ok

>>> СБРОС ДРУГИХ СЕКЦИЙ <<< — в _reset_results

>>> МЕСТО ДЛЯ ДРУГИХ МОДАЛОК <<< — обработчики модалок

>>> ДРУГИЕ МЕТОДЫ ДЛЯ МЕНЮ <<< — публичные методы RunView

В theme.py: >>> СЛЕДУЮЩИЙ ВИДЖЕТ ДОБАВЛЯТЬ СЮДА <<< — новые QSS-секции

Что осталось
#	Что	Время	Комментарий
E	Вкладка «Настройки»	3 ч	Config — frozen dataclass. Менять через object.__setattr__
F	Обогащение / История / Развитие	2 ч	Enrichment требует API-ключ и сеть, история — БД
G	Остановить анализ (Esc / кнопка)	1 ч	Требует правки ядра или опасного worker.terminate()
H	PyInstaller — .exe	1 ч	Финальный шаг
Рекомендация для следующего шага
H (PyInstaller) — даёт готовый .exe, практическая ценность сразу.

E (Настройки) — 4 ключевых секции (Пороги, Детекторы, Противоречия,
Allowlist) вместо всех 11. ~1.5 часа. Config в ядре — frozen dataclass:
менять поля из GUI через object.__setattr__, или создавать
Config(**overrides) каждый раз.

Как восстанавливать контекст в новом чате
Скопируй в начало нового чата:

Продолжаем GUI для pcap-triage на PySide6. Справка в GUI_PROGRESS.md.
Ядро pcap_triage/ не трогаем. Работает вкладка «Прогон» — drop zone,
summary grid, противоречия, findings, toast, progress, экспорт JSON/MD.
Остальные вкладки — заглушки. Приложи: run_view.py, main_window.py,
theme.py, markdown_reporter.py.

И приложи файлы из списка выше.

text

## Что это даёт

Файл `GUI_PROGRESS.md` — самодостаточная справка. В новом чате копируешь её + 4 файла, и продолжаешь с того же места, без пересказа всей истории.

## Опционально — короткая версия для меню «О программе»

Если хочешь **в самом GUI** нормальный текст «О программе» вместо того, что сейчас (просто версия + список компонентов) — замени в `main_window.py`:

```python
    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            "О программе",
            f"<b>pcap-triage v{APP_VERSION}</b><br><br>"
            "Оффлайн-триаж pcap без отправки данных наружу.<br><br>"
            "<b>Ядро:</b> 17 детекторов · 8 экстракторов · 7 правил "
            "ContradictionDetector.<br>"
            "<b>GUI:</b> Прогон, экспорт JSON/Markdown/conn.log.<br><br>"
            "Контракт: <code>run_pipeline(pcap_path, config) -&gt; dict</code>.<br>"
            "Отчёт содержит секции summary, findings, contradictions, "
            "entities, flows.<br><br>"
            "Справка для разработки — <code>GUI_PROGRESS.md</code> в корне.",   )