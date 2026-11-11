"""Вкладка «Обогащение» — выбор IOC и Threat Intel по ним.

Структура:
    Верхняя таблица — кандидаты IOC из findings. Одна строка = IOC.
    Чекбоксы, кнопки «Выбрать все / Снять все / Обогатить выбранные».

    Нижняя таблица — результаты обогащения. Одна строка = пара
    (IOC × провайдер). Заполняется по мере обогащения, разными партиями.

Почему две таблицы, а не одна:
    Список кандидатов нужен ДО обогащения (что выбрать). Результаты
    имеют другой формат (по провайдеру на строку), потому что у одного
    IOC может быть 2–3 источника с разной формой данных. Смешивать
    в одну таблицу — потеряем либо выбор, либо развёрнутость.

Ключи API:
    Ядро читает ABUSEIPDB_API_KEY из os.environ в момент запроса.
    Ключ выставляется в Настройках → Threat Intel.
"""
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr
from paradox_gui.theme import PALETTE
from paradox_gui.workers.enrichment_worker import EnrichmentWorker

# Индексы колонок верхней (кандидаты) и нижней (результаты) таблиц.
# Магические числа в коде читаемы, но именованные константы — надёжнее.
C_CHECK, C_IOC, C_TYPE, C_STATUS = range(4)
R_IOC, R_TYPE, R_PROVIDER, R_DATA = range(4)


class EnrichView(QWidget):
    """Вкладка «Обогащение» с выбором IOC и развёрнутыми результатами."""

    # Сигнал «обогащение успешно завершено». Эмитится один раз
    # после каждой партии. Нужен, чтобы main_window обновил
    # зависимые вкладки (История) без прямого знания про воркер.
    enrichment_finished = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._report: dict | None = None
        self._config_overrides: dict = {}
        self._worker: EnrichmentWorker | None = None
        self._base_status: str = ""
        # [(type, ioc), ...] — все кандидаты из последнего report.
        self._candidates: list[tuple[str, str]] = []
        # {(type, ioc): {source: data}} — накопленные результаты.
        # Мерджится между партиями обогащения.
        self._enrichment: dict = {}
        self._build_ui()

    # =========================================================================
    # UI
    # =========================================================================

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(16)

        title = QLabel(tr("enrich.title"))
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(tr("enrich.subtitle"))
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        # --- Панель управления ---
        controls = QHBoxLayout()
        controls.setSpacing(8)

        self._status = QLabel(tr("enrich.need_run"))
        self._status.setObjectName("muted")
        controls.addWidget(self._status, stretch=1)

        self._select_all_btn = QPushButton(tr("enrich.select_all"))
        self._select_all_btn.setObjectName("small")
        self._select_all_btn.clicked.connect(lambda: self._set_all(True))
        self._select_all_btn.setEnabled(False)
        controls.addWidget(self._select_all_btn)

        self._select_none_btn = QPushButton(tr("enrich.select_none"))
        self._select_none_btn.setObjectName("small")
        self._select_none_btn.clicked.connect(lambda: self._set_all(False))
        self._select_none_btn.setEnabled(False)
        controls.addWidget(self._select_none_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setTextVisible(False)
        self._progress.setVisible(False)
        controls.addWidget(self._progress)

        self._enrich_btn = QPushButton(tr("enrich.run"))
        self._enrich_btn.setObjectName("primary")
        self._enrich_btn.setEnabled(False)
        self._enrich_btn.clicked.connect(self._on_enrich)
        controls.addWidget(self._enrich_btn)

        outer.addLayout(controls)

        # --- Splitter: кандидаты сверху, результаты снизу ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)

        # Верх — кандидаты.
        top = QWidget()
        top_l = QVBoxLayout(top)
        top_l.setContentsMargins(0, 0, 0, 0)
        top_l.setSpacing(4)
        top_l.addWidget(_section_label(tr("enrich.section.candidates")))

        self._cand_table = QTableWidget()
        self._cand_table.setObjectName("iocCandidates")
        self._cand_table.setColumnCount(4)
        self._cand_table.setHorizontalHeaderLabels(
            ["", tr("enrich.col.ioc"), tr("enrich.col.type"),
             tr("enrich.col.status")]
        )
        self._cand_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._cand_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._cand_table.setAlternatingRowColors(True)
        self._cand_table.verticalHeader().setVisible(False)
        self._cand_table.horizontalHeader().setStretchLastSection(True)
        self._cand_table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self._cand_table.setColumnWidth(C_CHECK, 30)
        self._cand_table.setColumnWidth(C_IOC, 320)
        self._cand_table.setColumnWidth(C_TYPE, 100)
        self._cand_table.itemChanged.connect(self._on_candidate_changed)
        top_l.addWidget(self._cand_table, stretch=1)
        splitter.addWidget(top)

        # Низ — результаты.
        bottom = QWidget()
        bottom_l = QVBoxLayout(bottom)
        bottom_l.setContentsMargins(0, 0, 0, 0)
        bottom_l.setSpacing(4)
        bottom_l.addWidget(_section_label(tr("enrich.section.results")))

        self._res_table = QTableWidget()
        self._res_table.setObjectName("iocResults")
        self._res_table.setColumnCount(4)
        self._res_table.setHorizontalHeaderLabels(
            [tr("enrich.col.ioc"), tr("enrich.col.type"),
             tr("enrich.col.provider"), tr("enrich.col.data")]
        )
        self._res_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._res_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._res_table.setAlternatingRowColors(True)
        self._res_table.verticalHeader().setVisible(False)
        self._res_table.horizontalHeader().setStretchLastSection(True)
        self._res_table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self._res_table.setColumnWidth(R_IOC, 320)
        self._res_table.setColumnWidth(R_TYPE, 100)
        self._res_table.setColumnWidth(R_PROVIDER, 160)
        self._res_table.itemDoubleClicked.connect(self._on_result_double_clicked)
        bottom_l.addWidget(self._res_table, stretch=1)
        splitter.addWidget(bottom)

        # Приоритетные пропорции: кандидатов видим сразу много.
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        outer.addWidget(splitter, stretch=1)

        self._stats_label = QLabel("")
        self._stats_label.setObjectName("muted")
        outer.addWidget(self._stats_label)

    # =========================================================================
    # ПУБЛИЧНОЕ API
    # =========================================================================

    def set_report(self, report: dict | None) -> None:
        """Принять новый report из RunView. Сбрасывает накопленное."""
        self._report = report
        self._enrichment = {}

        if report is None:
            self._candidates = []
            self._refresh_candidates()
            self._refresh_results()
            self._update_status(tr("enrich.need_run"))
            return

        try:
            from paradox.integrations.enricher import (
                collect_iocs_from_findings,
            )
        except ImportError as e:
            self._candidates = []
            self._refresh_candidates()
            self._refresh_results()
            self._update_status(tr("enrich.status.import_error", err=e))
            return

        findings = report.get("findings") or []
        self._candidates = list(collect_iocs_from_findings(findings))
        self._refresh_candidates()
        self._refresh_results()

        if not self._candidates:
            self._update_status(tr("enrich.status.no_candidates"))
            return

        self._update_status(
            tr("enrich.status.ready", count=len(self._candidates))
        )

    def set_config_overrides(self, overrides: dict) -> None:
        """Мердж переопределений Config из Настроек. Как в RunView."""
        self._config_overrides.update(overrides)

    def focus_finding(self, finding: dict) -> int:
        """Отметить в списке кандидатов IOC конкретной находки.

        Переход из таблицы находок: IOC считаются тем же
        `collect_iocs_from_findings`, что и при заполнении таблицы,
        поэтому отмеченными оказываются ровно те строки, которые
        пользователь увидел бы глазами. Возвращает их число.
        """
        if not isinstance(finding, dict):
            return 0
        try:
            from paradox.integrations.enricher import (
                collect_iocs_from_findings,
            )
        except ImportError:
            return 0

        wanted = set(collect_iocs_from_findings([finding]))
        rows = [
            row for row, key in enumerate(self._candidates)
            if key in wanted
        ]
        if not rows:
            return 0

        self._cand_table.blockSignals(True)
        try:
            for row in rows:
                item = self._cand_table.item(row, C_CHECK)
                if item is not None:
                    item.setCheckState(Qt.CheckState.Checked)
        finally:
            self._cand_table.blockSignals(False)

        self._cand_table.selectRow(rows[0])
        first = self._cand_table.item(rows[0], C_IOC)
        if first is not None:
            self._cand_table.scrollToItem(first)
        self._update_status(None)
        return len(rows)

    # =========================================================================
    # HANDLERS
    # =========================================================================

    def _on_enrich(self) -> None:
        if not self._report:
            return
        if self._worker and self._worker.isRunning():
            return

        selected = self._selected_iocs()
        if not selected:
            QMessageBox.information(
                self,
                tr("enrich.nothing_title"),
                tr("enrich.nothing_body"),
            )
            return

        try:
            from paradox.config import Config
            config = Config()
            for k, v in self._config_overrides.items():
                if hasattr(config, k):
                    object.__setattr__(config, k, v)
        except ImportError as e:
            QMessageBox.critical(
                self,
                tr("enrich.error_title"),
                tr("enrich.config_import_error", err=e),
            )
            return

        self._set_busy(True)
        self._update_status(
            tr("enrich.status.running", done=len(selected))
        )

        self._worker = EnrichmentWorker(self._report, config, selected)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _on_ok(self, payload: object) -> None:
        data = payload or {}
        stats = data.get("stats") or {}
        new_enrichment = data.get("enrichment") or {}

        # Мерджим — уже обогащённые IOC не теряются.
        self._enrichment.update(new_enrichment)

        # Обновляем обе таблицы: статусы в верхней, строки в нижней.
        self._refresh_candidates()
        self._refresh_results()

        self._update_status(
            tr(
                "enrich.status.done",
                done=stats.get('iocs_enriched', 0),
                total=stats.get('iocs_total', 0),
                sec=f"{stats.get('duration_sec', 0):.1f}",
            )
        )
        self._stats_label.setText(
            tr(
                "enrich.status.cache",
                hits=stats.get('cache_hits', 0),
                misses=stats.get('cache_misses', 0),
                requests=stats.get('provider_calls', 0),
                errors=stats.get('errors', 0),
                limited=stats.get('rate_limited', 0),
            )
        )

        # Сигнал наружу: main_window обновит «Историю».
        self.enrichment_finished.emit()

    def _on_error(self, msg: str) -> None:
        self._update_status(tr("enrich.status.error", err=msg))
        QMessageBox.critical(self, tr("enrich.err_title"), msg)

    def _on_done(self) -> None:
        self._set_busy(False)
        # finished приходит до фактического завершения QThread: без
        # wait() последняя ссылка может умереть, пока поток ещё
        # раскручивается. Как в RunView._on_thread_done.
        w = self.sender()
        if isinstance(w, QThread):
            w.wait(2000)
            if self._worker is w:
                self._worker = None

    def is_busy(self) -> bool:
        return bool(self._worker and self._worker.isRunning())

    def wait_for_finish(self, timeout_ms: int = 10000) -> bool:
        """Как RunView.wait_for_finish: не дать QThread умереть с окном."""
        w = self._worker
        if w is None:
            return True
        return w.wait(timeout_ms)

    def _on_candidate_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != C_CHECK:
            return
        self._update_status(None)  # только счётчик пересчитать

    def _on_result_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        ioc = self._res_table.item(row, R_IOC).text()
        source = self._res_table.item(row, R_PROVIDER).text()
        data = self._find_enrichment(ioc, source)
        if data is None:
            return
        import json
        QMessageBox.information(
            self, f"{source} · {ioc}",
            f"<pre style='font-family: Consolas, monospace;'>"
            f"{json.dumps(data, indent=2, ensure_ascii=False)}"
            f"</pre>",
        )

    # =========================================================================
    # ВЕРХНЯЯ ТАБЛИЦА: КАНДИДАТЫ
    # =========================================================================

    def _refresh_candidates(self) -> None:
        self._cand_table.blockSignals(True)
        try:
            self._cand_table.setRowCount(len(self._candidates))
            for row, key in enumerate(self._candidates):
                self._fill_candidate_row(row, key)
        finally:
            self._cand_table.blockSignals(False)

        has = bool(self._candidates)
        self._select_all_btn.setEnabled(has)
        self._select_none_btn.setEnabled(has)
        self._enrich_btn.setEnabled(
            has and not (self._worker and self._worker.isRunning())
        )

    def _fill_candidate_row(self, row: int, key: tuple[str, str]) -> None:
        ioc_type, ioc = key

        check = QTableWidgetItem()
        check.setFlags(
            Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
        )
        # По умолчанию отмечено всё, что ещё не обогащено. Ранее
        # обогащённые — сняты, чтобы пользователь не гонял их снова.
        already = key in self._enrichment
        check.setCheckState(
            Qt.CheckState.Unchecked if already else Qt.CheckState.Checked
        )
        self._cand_table.setItem(row, C_CHECK, check)

        ioc_item = QTableWidgetItem(ioc)
        ioc_item.setForeground(QBrush(QColor(PALETTE["text"])))
        ioc_item.setToolTip(ioc)  # AUTO-FIXED-ENRICH-WIDTH: полное имя
        self._cand_table.setItem(row, C_IOC, ioc_item)

        type_item = QTableWidgetItem(ioc_type)
        type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        type_item.setForeground(QBrush(QColor(PALETTE["text_muted"])))
        self._cand_table.setItem(row, C_TYPE, type_item)

        if already:
            sources = list(self._enrichment.get(key, {}).keys())
            status_text = f"✓ {', '.join(sources)}"
            status_color = PALETTE["success"]
        else:
            status_text = tr("enrich.not_enriched")
            status_color = PALETTE["text_muted"]

        status_item = QTableWidgetItem(status_text)
        status_item.setForeground(QBrush(QColor(status_color)))
        self._cand_table.setItem(row, C_STATUS, status_item)

    def _set_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._cand_table.blockSignals(True)
        try:
            for row in range(self._cand_table.rowCount()):
                item = self._cand_table.item(row, C_CHECK)
                if item is not None:
                    item.setCheckState(state)
        finally:
            self._cand_table.blockSignals(False)
        self._update_status(None)

    def _selected_iocs(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for row in range(self._cand_table.rowCount()):
            item = self._cand_table.item(row, C_CHECK)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                if row < len(self._candidates):
                    out.append(self._candidates[row])
        return out

    # =========================================================================
    # НИЖНЯЯ ТАБЛИЦА: РЕЗУЛЬТАТЫ
    # =========================================================================

    def _refresh_results(self) -> None:
        """Развернуть self._enrichment в плоский список строк."""
        rows: list[tuple[str, str, str, str, dict]] = []
        for (ioc_type, ioc), per_source in self._enrichment.items():
            for source, data in per_source.items():
                rows.append((ioc, ioc_type, source, _summarize(source, data), data))

        # Сортировка: сначала IP, потом домены; внутри — по IOC, затем
        # по провайдеру. Стабильный порядок помогает глазами искать.
        rows.sort(key=lambda r: (r[1], r[0], r[2]))

        self._res_table.setRowCount(len(rows))
        for i, (ioc, t, source, summary, _) in enumerate(rows):
            ioc_item = QTableWidgetItem(ioc)
            ioc_item.setForeground(QBrush(QColor(PALETTE["text"])))
            ioc_item.setToolTip(ioc)  # AUTO-FIXED-ENRICH-WIDTH: полное имя
            self._res_table.setItem(i, R_IOC, ioc_item)

            type_item = QTableWidgetItem(t)
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            type_item.setForeground(QBrush(QColor(PALETTE["text_muted"])))
            self._res_table.setItem(i, R_TYPE, type_item)

            prov_item = QTableWidgetItem(source)
            prov_item.setForeground(QBrush(QColor(PALETTE["accent"])))
            self._res_table.setItem(i, R_PROVIDER, prov_item)

            data_item = QTableWidgetItem(summary)
            data_item.setToolTip(summary)  # AUTO-FIXED-ENRICH-WIDTH
            self._res_table.setItem(i, R_DATA, data_item)

        if not rows:
            self._stats_label.setText(tr("enrich.no_results"))

    def _find_enrichment(self, ioc: str, source: str):
        for (_, val), per_source in self._enrichment.items():
            if val == ioc and source in per_source:
                return per_source[source]
        return None

    # =========================================================================
    # ОБЩЕЕ
    # =========================================================================

    def _update_status(self, text: str | None) -> None:
        """Обновить строку статуса. text=None — только пересчёт счётчика.

        Базовый текст хранится отдельно (self._base_status) — не
        парсим собственный output, поэтому счётчик не накапливается.
        """
        if text is not None:
            self._base_status = text

        total = len(self._candidates)
        selected = len(self._selected_iocs()) if total else 0
        already = sum(1 for k in self._candidates if k in self._enrichment)

        counter_parts = []
        if total:
            counter_parts.append(
                tr("enrich.selected", selected=selected, total=total)
            )
        if already:
            counter_parts.append(tr("enrich.enriched_of", count=already))
        counter = " · ".join(counter_parts)

        base = self._base_status or ""
        if counter:
            self._status.setText(f"{base} · {counter}" if base else counter)
        else:
            self._status.setText(base)

    def _set_busy(self, busy: bool) -> None:
        self._enrich_btn.setEnabled(
            not busy and bool(self._candidates)
        )
        self._select_all_btn.setEnabled(not busy and bool(self._candidates))
        self._select_none_btn.setEnabled(not busy and bool(self._candidates))
        self._progress.setVisible(busy)


# =============================================================================
# ХЕЛПЕРЫ
# =============================================================================

def _section_label(text: str) -> QLabel:
    """Подпись раздела между таблицами: небольшой, приглушённый."""
    lbl = QLabel(text)
    lbl.setObjectName("panelTitle")
    return lbl


def _summarize(source: str, data) -> str:
    """Краткая выжимка ответа провайдера для колонки «Данные»."""
    if not isinstance(data, dict):
        return str(data)[:120]

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
            parts.append(f"isp={isp[:40]}")
        return " · ".join(parts) or "—"

    if source == "shodan_internetdb":
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []
        hostnames = data.get("hostnames") or []
        parts = []
        if ports:
            parts.append(f"ports={ports[:8]}")
        if vulns:
            parts.append(f"vulns={len(vulns)}")
        if tags:
            parts.append(f"tags={tags[:3]}")
        if hostnames:
            parts.append(f"hostnames={hostnames[:2]}")
        return " · ".join(parts) or "—"

    bits = []
    for k, v in list(data.items())[:4]:
        bits.append(f"{k}={str(v)[:30]}")
    return " · ".join(bits) or "—"

# AUTO-FIXED-ENRICH-WIDTH
