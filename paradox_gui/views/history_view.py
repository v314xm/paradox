"""Вкладка «История» — список прогонов в памяти.

Что это:
    Список всех успешных прогонов за сессию. Клик по записи — справа
    показывается тот же отчёт, что был в «Прогоне», но в компактном
    read-only виде: summary + противоречия + findings + обогащение.

Почему in-memory:
    По плану — без БД. Перезапуск приложения обнуляет историю. Когда
    появится потребность в persistence, заменим list на SQLite — интерфейс
    останется тем же (add_run / clear / refresh_current).

Почему QTextBrowser, а не переиспользование RunView-виджетов:
    RunView живёт один и уже занят текущим прогоном. Второй экземпляр
    тянул бы dialogs/widgets только ради read-only просмотра. HTML
    дешевле: одна функция _render_html(report), одна точка правки.

Обновление после обогащения:
    report — тот же объект, что в RunView и EnrichView. Обогащение
    мутирует его in-place (evidence.enrichment). QTextBrowser сам про
    это не узнает, поэтому main_window дёргает refresh_current()
    по сигналу enrich_view.enrichment_finished.

Что НЕ делает эта вкладка:
    - не хранит копии отчётов (иначе обогащение в них не отражалось бы);
    - не эмитит сигналов (никому не нужно знать про клики внутри);
    - не запускает фоновых задач (только показывает то, что уже есть).
"""
from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr
from paradox_gui.storage import HistoryDB


class HistoryView(QWidget):
    """Список прогонов текущей сессии.

    Публичный API:
        add_run(report)    — добавить успешный прогон (новая запись сверху);
        refresh_current()  — перерисовать выбранную запись (после обогащения);
        clear()            — очистить историю, не трогая текущий прогон.
    """

    # Сигнал для запроса сравнения выбранного прогона с текущим.
    # Передаёт словарь report из истории.
    compare_requested = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # Хранилище: каждый элемент — (timestamp, report). Список
        # параллелен QListWidget: index i ↔ записи i. Это главное
        # упрощение — не надо синхронизировать два независимых контейнера.
        #
        # report здесь — ССЫЛКА на тот же объект, что в RunView. Не копия.
        # Именно поэтому обогащение, мутирующее report in-place,
        # автоматически становится видимым истории.
        self._runs: list[tuple[datetime, dict, int | None]] = []
        self._db = HistoryDB()
        self._build_ui()
        self._load_from_db()

    # =========================================================================
    # UI
    # =========================================================================

    def _build_ui(self) -> None:
        # Внешний вертикальный слой: заголовок → подпись → две колонки →
        # кнопка «Очистить». Пропорции держим через stretch.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        title = QLabel(tr("history.title"))
        title.setObjectName("h1")  # QSS-стиль из theme.py
        outer.addWidget(title)

        subtitle = QLabel(tr("history.subtitle"))
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        # Две колонки: слева — список, справа — детали. Горизонталь
        # с фиксированной шириной у списка: так метки не «прыгают»
        # при разных именах файлов.
        columns = QHBoxLayout()
        columns.setSpacing(12)

        # Слева — список прогонов. Фиксированная ширина 320px: даёт
        # стабильную левую колонку и оставляет место под HTML справа.
        self._list = QListWidget()
        self._list.setObjectName("historyList")  # стиль в theme.py
        self._list.setFixedWidth(320)
        # Подписываемся на смену строки сразу при сборке UI. При
        # добавлении первой записи сработает автоматически — не надо
        # вручную вызывать _on_row_changed.
        self._list.currentRowChanged.connect(self._on_row_changed)

        # Контекстное меню для сравнения с текущим прогоном
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._on_context_menu)

        columns.addWidget(self._list)

        # Справа — детали выбранного прогона. QTextBrowser, потому что
        # рендерит HTML и умеет Ctrl+C / выделение / скролл из коробки.
        # QSS из theme сюда не течёт (QTextDocument), поэтому цвета
        # задаём инлайн в _render_html.
        self._details = QTextBrowser()
        self._details.setObjectName("historyDetails")
        self._details.setOpenExternalLinks(True)
        # Плейсхолдер вместо пустого белого прямоугольника: понятнее,
        # что здесь появится после первого прогона.
        self._details.setHtml(
            f'<p style="color:#a0a0b0;">{tr("history.empty")}</p>'
        )
        columns.addWidget(self._details, stretch=1)

        outer.addLayout(columns, stretch=1)

        # Кнопка снизу. Прижата вправо (addStretch(1) слева) — стандарт
        # для диалогов: главное действие справа внизу.
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        clear_btn = QPushButton(tr("history.clear_button"))
        clear_btn.clicked.connect(self.clear)
        buttons.addWidget(clear_btn)
        outer.addLayout(buttons)

    # =========================================================================
    # ПУБЛИЧНОЕ API
    # =========================================================================

    def _load_from_db(self) -> None:
        """Подтянуть последние 20 прогонов из БД при старте."""
        rows = self._db.load_recent(limit=20)
        for run_id, ts, report in rows:
            self._runs.append((ts, report, run_id))
            item = QListWidgetItem(self._label_for(ts, report))
            item.setData(Qt.ItemDataRole.UserRole, len(self._runs) - 1)
            self._list.addItem(item)
        if self._runs:
            self._list.setCurrentRow(0)

    def add_run(self, report: dict) -> None:
        """Добавить успешный прогон. Вызывается из main_window.

        report — то же, что отдаёт run_pipeline. Функция не падает на
        неполном report: ключи берём через .get с дефолтами.

        Важная деталь: report НЕ копируется. Мутации в ядре (или в
        enrich_view) будут видны здесь автоматически.
        """
        ts = datetime.now()
        run_id = self._db.insert(report)
        # insert(0, ...) — новые записи сверху. Старые уезжают вниз
        # по списку, визуально «проваливаются» в историю.
        # Держим ссылку на оригинальный report, чтобы обогащение,
        # мутирующее его in-place, было видно в истории.
        self._runs.insert(0, (ts, report, run_id))

        # Держим не больше MAX_RUNS записей. report'ы тяжёлые
        # (десятки МБ на больших pcap), история иначе съедает RAM
        # на длинной сессии. Обрезаем с хвоста — там самые старые.
        MAX_RUNS = 20
        while len(self._runs) > MAX_RUNS:
            self._runs.pop()
            if self._list.count() > 0:
                self._list.takeItem(self._list.count() - 1)

        # Параллельная вставка в QListWidget — тоже в начало списка,
        # чтобы индексы _runs и _list оставались согласованными.
        item = QListWidgetItem(self._label_for(ts, report))
        # UserRole хранит индекс — страховка от рассинхронизации.
        # Если когда-нибудь появится сортировка или фильтрация, сможем
        # однозначно сопоставить строку списка и элемент _runs.
        item.setData(Qt.ItemDataRole.UserRole, 0)
        self._list.insertItem(0, item)

        # После вставки в начало все индексы сдвинулись на 1 — пересобираем
        # UserRole у всех. Линейно по длине списка, но история редко
        # превышает десятки записей, это не bottleneck.
        for i in range(self._list.count()):
            self._list.item(i).setData(Qt.ItemDataRole.UserRole, i)

        # Автовыбор: показываем только что добавленный прогон. Это
        # срабатывает currentRowChanged → _on_row_changed → перерисовка
        # HTML. Пользователю не надо кликать — свежий результат сразу
        # виден справа.
        self._list.setCurrentRow(0)

    def refresh_current(self) -> None:
        """Перерисовать выбранную запись.

        Вызывается после обогащения: report мутируется in-place, но
        QTextBrowser не знает об этом и не перерисовывается сам. Также
        обновляем текст метки в списке — он показывает «✓ enriched».

        Идемпотентна: можно вызывать сколько угодно раз, ничего не
        сломается. Если запись не выбрана — тихо выходим.
        """
        row = self._list.currentRow()
        # Защита от «история пуста» и «индекс вне диапазона»: бывает
        # после clear() или сразу после инициализации до первого add_run.
        if row < 0 or row >= len(self._runs):
            return

        # 1) HTML справа — полностью пересобираем. Не пытаемся частично
        # обновлять секцию «Обогащение»: новая секция могла появиться
        # там, где раньше её не было. Проще пересобрать всё.
        _, report, run_id = self._runs[row]
        self._details.setHtml(self._render_html(report))

        # Обогащение мутировало report in-place — синхронизируем БД,
        # чтобы после перезапуска enriched-данные не потерялись.
        if run_id is not None and _count_enriched_iocs(report) > 0:
            self._db.update_report(run_id, report, enriched=True)

        # 2) Метка в списке — пересобираем текст. Меняется суффикс
        # «✓ enriched», потому что _label_for пересчитывает его от
        # текущего report. Выделение сохраняется: setText не сбрасывает
        # currentRow, только содержимое одного item.
        ts, _, _ = self._runs[row]
        item = self._list.item(row)
        if item is not None:
            item.setText(self._label_for(ts, report))

    def clear(self) -> None:
        """Очистить историю. Не трогает текущий прогон во вкладке «Прогон»."""
        # Три независимых обнуления: список данных, виджет, плейсхолдер.
        # Если забыть одно из них, останется либо «мёртвая» строка
        # в UI, либо старый HTML справа.
        self._runs.clear()
        self._list.clear()
        self._db.clear()
        self._details.setHtml(
            f'<p style="color:#a0a0b0;">{tr("history.cleared")}</p>'
        )

    # =========================================================================
    # ВНУТРЕННЕЕ
    # =========================================================================

    def _label_for(self, ts: datetime, report: dict) -> str:
        """Собрать трёхстрочную метку для записи в списке.

        Формат:
            2026-10-14 12:34:56
            CyberCampTask.pcap
            7 findings · 2 contra · ✓ enriched
        """
        # .get(...) с дефолтом + `or {}` — защита от report, где ключ
        # есть, но значение None (так бывает, если ядро вернуло null).
        s = report.get("summary", {}) or {}
        prov = report.get("provenance", {}) or {}
        pcap = prov.get("pcap_path", "") or "—"

        # Имя файла — только basename. rsplit сначала по Windows-разделителю,
        # потом по POSIX. Работает на обеих системах без os.path:
        # path приходит из ядра как строка, может быть любой.
        name = pcap.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "—"

        # Суффикс про обогащение появляется, только если оно было.
        # Это единственное место, где метка зависит от enrichment — при
        # обновлении через refresh_current она перечитается и обновится.
        suffix = ""
        if _count_enriched_iocs(report):
            suffix = " · ✓ enriched"

        return (
            f"{ts:%Y-%m-%d %H:%M:%S}\n"
            f"{name}\n"
            f"{s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} contra{suffix}"
        )

    def _on_context_menu(self, pos) -> None:
        """Правый клик по записи: меню действий."""
        item = self._list.itemAt(pos)
        if item is None:
            return

        row = self._list.row(item)
        if row < 0 or row >= len(self._runs):
            return

        _, report, _ = self._runs[row]

        menu = QMenu(self)
        action_compare = menu.addAction(tr("history.ctx_compare"))
        action_compare.triggered.connect(lambda: self.compare_requested.emit(report))
        menu.exec(self._list.viewport().mapToGlobal(pos))

    def _on_row_changed(self, row: int) -> None:
        """Слот на currentRowChanged. Просто перерисовать HTML справа."""
        # row < 0 — состояние «ничего не выбрано» (после clear или до
        # первого add_run). row >= len — не должно случаться, но
        # лучше перестраховаться: индексы могут разъехаться при
        # неаккуратных правках.
        if row < 0 or row >= len(self._runs):
            return
        _, report, _run_id = self._runs[row]
        self._details.setHtml(self._render_html(report))

    def _render_html(self, report: dict) -> str:
        """Компактный HTML-разбор отчёта.

        Цвета — вручную согласованы с PALETTE/theme.py. QTextBrowser
        рендерит свой QTextDocument, QSS из theme сюда не течёт.

        Структура: <style> + последовательность секций (Файл, Сводка,
        Противоречия, Findings, Обогащение). Секции опциональны —
        отсутствуют, если данных нет.
        """
        s = report.get("summary", {}) or {}
        prov = report.get("provenance", {}) or {}
        contradictions = report.get("contradictions", []) or []
        findings = report.get("findings", []) or []

        def esc(x) -> str:
            """Экранирование HTML. Без него вставка < в пути сломает
            разметку или, в теории, даст XSS, если отчёт откроют
            в браузере через Save-As-HTML."""
            return (
                str(x)
                .replace("&", "&amp;")   # сначала &, иначе съест артефакты
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )

        # Список частей вместо конкатенации через += . На больших
        # отчётах это заметно быстрее, а читается так же.
        parts: list[str] = []

        # Инлайн-стили. Имена классов не пересекаются с theme.py —
        # QTextDocument всё равно не читает внешний QSS, поэтому здесь
        # всё локально. Цвета подобраны вручную под PALETTE.
        parts.append(
            '<style>'
            'h2{color:#5b8cff;font-size:14px;margin:14px 0 6px 0;}'
            'table{border-collapse:collapse;margin:6px 0;font-size:12px;}'
            'th{color:#a0a0b0;text-align:left;padding:2px 12px 2px 0;'
            'font-weight:600;border-bottom:1px solid #3a3d4d;}'
            'td{padding:3px 12px 3px 0;color:#e0e0e0;vertical-align:top;}'
            '.muted{color:#a0a0b0;font-size:11px;}'
            '.sev-critical{color:#ff5555;font-weight:600;}'
            '.sev-high{color:#ffb86c;font-weight:600;}'
            '.sev-medium{color:#f1fa8c;font-weight:600;}'
            '.sev-low{color:#50fa7b;font-weight:600;}'
            '.ok{color:#50fa7b;font-weight:600;}'
            '.mono{font-family:Consolas,monospace;font-size:11px;}'
            '</style>'
        )

        # --- Provenance ---
        # Короткий блок «откуда данные»: путь + усечённый SHA256.
        # Полный хеш не показываем — 64 символа вылезут за экран,
        # для идентификации достаточно 32.
        parts.append("<h2>Файл</h2>")
        parts.append(f'<div class="muted">{esc(prov.get("pcap_path", "—"))}</div>')
        sha = prov.get("pcap_sha256", "")
        if sha:
            parts.append(f'<div class="muted">SHA256: {esc(sha[:32])}…</div>')

        # --- Summary ---
        # Таблица 3×4. :, — разделитель тысяч в f-string.
        parts.append("<h2>Сводка</h2>")
        parts.append(
            "<table>"
            f"<tr><th>Пакеты</th><td>{s.get('packets', 0):,}</td>"
            f"<th>Flows</th><td>{s.get('flows', 0):,}</td></tr>"
            f"<tr><th>Findings</th><td>{s.get('findings', 0)}</td>"
            f"<th>Противоречий</th><td>{s.get('contradictions', 0)}</td></tr>"
            f"<tr><th>Размер</th><td>{s.get('size_bytes', 0) / 1024 / 1024:.1f} МБ</td>"
            f"<th>Время</th><td>{s.get('duration_sec', 0):.1f} сек</td></tr>"
            "</table>"
        )

        # --- Contradictions ---
        # Секция опциональна: нет противоречий — нет заголовка.
        if contradictions:
            parts.append(f"<h2>Противоречия ({len(contradictions)})</h2>")
            parts.append(
                "<table><tr><th>Severity</th><th>Rule</th>"
                "<th>Subject</th><th>Conf</th></tr>"
            )
            for c in contradictions:
                # .lower() — на случай если ядро вернёт "Critical" с
                # большой буквы. Класс .sev-critical соответствует.
                sev = (c.get("severity") or "low").lower()
                parts.append(
                    f'<tr><td class="sev-{sev}">{esc(sev)}</td>'
                    f'<td>{esc(c.get("rule", "—"))}</td>'
                    f'<td>{esc(c.get("subject", "—"))}</td>'
                    f'<td>{c.get("confidence", 0):.2f}</td></tr>'
                )
            parts.append("</table>")

        # --- Findings ---
        # Ограничение 50 строк: HTML из 500 findings весит сотни КБ,
        # QTextBrowser рендерит его заметно дольше. Остальное — счётчик.
        if findings:
            parts.append(f"<h2>Findings ({len(findings)})</h2>")
            parts.append(
                "<table><tr><th>Тип</th><th>Значение</th>"
                "<th>Conf</th><th>MITRE</th></tr>"
            )
            for f in findings[:50]:
                # mitre_techniques бывает list или строка. Приводим оба
                # к строке через join/str.
                mitre = f.get("mitre_techniques", [])
                mitre_s = ", ".join(mitre) if isinstance(mitre, list) else str(mitre)
                parts.append(
                    f'<tr><td>{esc(f.get("type", "—"))}</td>'
                    f'<td>{esc(f.get("value", "—"))}</td>'
                    f'<td>{f.get("confidence", 0):.2f}</td>'
                    f'<td class="muted">{esc(mitre_s)}</td></tr>'
                )
            if len(findings) > 50:
                parts.append(
                    f'<tr><td colspan="4" class="muted">'
                    f'… ещё {len(findings) - 50}</td></tr>'
                )
            parts.append("</table>")

        # --- Обогащение ---
        # Секция появляется только если по этому прогону гоняли
        # Threat Intel. Источник — finding["evidence"]["enrichment"].
        # Собирается через модульный хелпер, потому что ту же логику
        # использует _label_for (там только считаем IOC).
        enriched_rows = _collect_enrichment_rows(report)
        if enriched_rows:
            parts.append(
                f"<h2>Обогащение ({len(enriched_rows)} строк)</h2>"
            )
            parts.append(
                "<table><tr><th>IOC</th><th>Провайдер</th>"
                "<th>Данные</th></tr>"
            )
            for ioc, source, summary in enriched_rows:
                # IOC — моно-шрифтом (.mono), провайдер — зелёным (.ok):
                # визуально сразу отличать «что обогащено» от «чем».
                parts.append(
                    f'<tr><td class="mono">{esc(ioc)}</td>'
                    f'<td class="ok">{esc(source)}</td>'
                    f'<td>{esc(summary)}</td></tr>'
                )
            parts.append("</table>")

        return "".join(parts)


# =============================================================================
# ХЕЛПЕРЫ (модульные, не методы класса)
# =============================================================================
#
# Почему не методы:
#   Все три — чистые функции «report → значение». Не используют self,
#   не зависят от состояния виджета. Могут тестироваться без
#   QApplication, и это большой плюс — pytest не тянет Qt.


def _collect_enrichment_rows(report: dict) -> list[tuple[str, str, str]]:
    """Собрать (ioc, provider, summary) из finding["evidence"]["enrichment"].

    Возвращает дедуплицированный список: один и тот же IOC часто
    встречается в нескольких findings (например, IP-атакующий в
    brute_force и ftp_brute_force). Без дедупа таблица раздуется
    в 3–5 раз, и её невозможно будет читать.
    """
    rows: list[tuple[str, str, str]] = []
    # seen — ключи (ioc, source). Уникальность на уровне пары.
    seen: set[tuple[str, str]] = set()

    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        # Вложенная структура: evidence.enrichment = {ioc: {source: data}}.
        # Тройные `.get(...) or {}` защищают от любого промежуточного None.
        enrichment = (f.get("evidence") or {}).get("enrichment") or {}
        if not isinstance(enrichment, dict):
            continue
        for ioc, per_source in enrichment.items():
            if not isinstance(per_source, dict):
                continue
            for source, data in per_source.items():
                key = (ioc, source)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((ioc, source, _summarize(source, data)))

    # Сортировка по (провайдер, IOC): все abuseipdb рядом, все shodan
    # рядом. Пользователь читает таблицу группами, а не вперемешку.
    rows.sort(key=lambda r: (r[1], r[0]))
    return rows


def _count_enriched_iocs(report: dict) -> int:
    """Сколько уникальных IOC обогащено. Нужно для маркера в метке.

    Считаем именно IOC, не пары (ioc × provider): пользователь думает
    «сколько адресов проверено», а не «сколько строк в таблице».
    """
    seen: set[str] = set()
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        enrichment = (f.get("evidence") or {}).get("enrichment") or {}
        if isinstance(enrichment, dict):
            seen.update(enrichment.keys())
    return len(seen)


def _summarize(source: str, data) -> str:
    """Краткая выжимка ответа провайдера для таблицы.

    Дублирует логику из enrich_view.py, но с меньшей детализацией:
    в истории нет двойного клика с полным JSON, поэтому важна
    компактность и читаемость одной строкой.
    """
    # Не dict? Скорее всего что-то странное от провайдера — показываем
    # как есть, но обрезаем, чтобы не вылезало за экран.
    if not isinstance(data, dict):
        return str(data)[:120]

    # AbuseIPDB: abuseConfidenceScore (0-100), countryCode, isp.
    # Эти три поля — то, что реально важно при триаже.
    if source == "abuseipdb":
        score = data.get("abuseConfidenceScore")
        country = data.get("countryCode")
        isp = data.get("isp", "")
        parts = []
        if score is not None:
            parts.append(f"score={score}")
        if country:
            parts.append(f"country={country}")
        if isp:
            parts.append(f"isp={isp[:40]}")  # ISP-строка бывает длинной
        return " · ".join(parts) or "—"

    # Shodan InternetDB: открытые порты, уязвимости, теги.
    # ports и vulns — самые информативные поля для триажа.
    if source == "shodan_internetdb":
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []
        parts = []
        if ports:
            parts.append(f"ports={ports[:8]}")  # 8 портов достаточно
        if vulns:
            parts.append(f"vulns={len(vulns)}")  # счётчик, не список CVE
        if tags:
            parts.append(f"tags={tags[:3]}")
        return " · ".join(parts) or "—"

    # Fallback для любых будущих провайдеров (VirusTotal, если его
    # подключат в ядре). Первые 4 пары ключ=значение, значения
    # обрезаются до 30 символов.
    bits = []
    for k, v in list(data.items())[:4]:
        bits.append(f"{k}={str(v)[:30]}")
    return " · ".join(bits) or "—"
