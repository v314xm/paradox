"""Часть главного окна: actions."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QMessageBox,
)

from paradox_gui import __version__ as APP_VERSION
from paradox_gui.i18n import tr


class ActionsMixin:
    def _on_open_pcap(self) -> None:
        try:
            self.tabs.setCurrentIndex(0)
            self.run_view.open_file_dialog()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self,
                tr("error.title"),
                tr(
                    "error.read.body",
                    type=type(e).__name__,
                    message=e,
                ),
            )


    def _on_open_report(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("dialog.file.open_report.title"),
            "",
            tr("dialog.file.open_report.filter"),
        )
        if not path:
            return

        p = Path(path)
        # Защита от больших JSON: > 100 МБ — предупредить.
        _JSON_LIMIT_MB = 100
        try:
            size_mb = p.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0
        if size_mb > _JSON_LIMIT_MB:
            answer = QMessageBox.question(
                self,
                tr("error.large_json_title"),
                tr("error.large_json_body",
                   size=size_mb, limit=_JSON_LIMIT_MB),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(
                self,
                tr("error.read.title"),
                tr("error.read.body", type=type(e).__name__, message=str(e)),
            )
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self,
                tr("error.wrong_file.title"),
                tr("error.wrong_file.body"),
            )
            return
        self.tabs.setCurrentIndex(0)
        self.run_view.load_report(data)
        self._on_analysis_finished(data)
        self.statusBar().showMessage(
            tr("status.report_loaded", path=path), 5000,
        )


    def _on_analyze(self) -> None:
        self.run_view.reanalyze()


    def _on_analyze_with_config(self) -> None:
        self.statusBar().showMessage(
            tr("status.analyze_with_config_wip"), 3000
        )


    def _on_stop(self) -> None:
        # >>> ОСТАНОВКА <<<
        self.run_view.stop_analysis()


    def _on_open_settings(self) -> None:
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.settings_view))


    # -------------------------------------------------------------------------
    # Переходы из панели действий у находок: кнопка-ссылка открывает
    # инструмент уже на выбранной находке, а не просто на вкладке.
    # -------------------------------------------------------------------------

    def _on_finding_payload(self, finding: object) -> None:
        if not isinstance(finding, dict):
            return
        report = self.run_view.last_report()
        if not report:
            return
        if not hasattr(self, "payload_view"):
            return

        if self.payload_view.select_finding(finding) < 0:
            # Выдержки ещё не собраны (например, отчёт открыт из JSON
            # раньше, чем вкладка получила данные) — собираем и ищем снова.
            self.payload_view.update_data(report)
            if self.payload_view.select_finding(finding) < 0:
                return

        index = self.tabs.indexOf(self.payload_view)
        if index >= 0:
            self.tabs.setCurrentIndex(index)
        self.statusBar().showMessage(
            tr("run.act.payload_status", value=finding.get("value", "")),
            4000,
        )

    def _on_finding_enrich(self, finding: object) -> None:
        if not isinstance(finding, dict) or not hasattr(self, "enrich_view"):
            return

        index = self.tabs.indexOf(self.enrich_view)
        if index >= 0:
            self.tabs.setCurrentIndex(index)

        count = self.enrich_view.focus_finding(finding)
        self.statusBar().showMessage(
            tr("run.act.enrich_status", count=count) if count
            else tr("run.act.enrich_none"),
            4000,
        )


    def _on_help_reference(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.help.title"),
            tr("dialog.help.body_html"),
        )


    def _on_about(self) -> None:
        """About-диалог с логотипом."""
        try:
            from PySide6.QtWidgets import (
                QDialog,
                QDialogButtonBox,
                QFrame,
                QLabel,
                QVBoxLayout,
            )

            from paradox_gui.logo import render_logo

            dlg = QDialog(self)
            dlg.setObjectName("aboutDialog")
            dlg.setWindowTitle(tr("dialog.about.title"))
            dlg.resize(460, 420)
            dlg.setMinimumSize(420, 380)
            v = QVBoxLayout(dlg)
            v.setContentsMargins(20, 20, 20, 16)
            v.setSpacing(10)

            logo_lbl = QLabel()
            logo_lbl.setPixmap(render_logo(96))
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(logo_lbl)

            title = QLabel(tr("dialog.about.app_title", version=APP_VERSION))
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setObjectName("aboutTitle")
            v.addWidget(title)

            subtitle = QLabel(tr("dialog.about.subtitle"))
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            subtitle.setObjectName("muted")
            v.addWidget(subtitle)

            modules = QLabel(tr("dialog.about.modules_html"))
            modules.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(modules)

            sep = QFrame()
            sep.setObjectName("hline")
            sep.setFrameShape(QFrame.Shape.HLine)
            v.addWidget(sep)

            copyright_lbl = QLabel(tr("dialog.about.copyright"))
            copyright_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            copyright_lbl.setObjectName("muted")
            v.addWidget(copyright_lbl)

            btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            btn.setObjectName("dialogButtons")
            btn.rejected.connect(dlg.reject)
            close = btn.button(QDialogButtonBox.StandardButton.Close)
            close.setText(tr("btn.close"))
            close.setDefault(True)
            v.addWidget(btn)

            dlg.exec()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self,
                tr("error.title"),
                f"{type(e).__name__}: {e}",
            )


    def _on_hotkeys(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.hotkeys.title"),
            tr("dialog.hotkeys.body"),
        )


    def _on_analysis_started(self, path: str) -> None:
        self._status_text.setText(tr("status.analyzing"))
        self._status_file.setText(path)
        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(True)
        self._act_analyze.setEnabled(False)
        # >>> /ОСТАНОВКА <<<
        # Новый прогон — старые выдержки уже не про этот отчёт.
        if getattr(self, "_payload_window", None) is not None:
            self._payload_window.clear()
        # Старые IOC и превью экспорта тоже относятся к прошлому pcap.
        if hasattr(self, "enrich_view"):
            self.enrich_view.set_report(None)
        if hasattr(self, "export_view"):
            self.export_view.clear()


    def _on_analysis_finished(self, report: object) -> None:
        s = report.get("summary", {}) if isinstance(report, dict) else {}
        self._status_text.setText(tr(
            "status.done",
            findings=s.get("findings", 0),
            contradictions=s.get("contradictions", 0),
        ))
        # Есть что сохранять — включаем экспорт.
        for a in (self._act_export_json, self._act_export_md, self._act_export_conn):
            a.setEnabled(True)

        # >>> ИСТОРИЯ <<<
        if isinstance(report, dict) and hasattr(self, "history_view"):
            self.history_view.add_run(report)
        # >>> /ИСТОРИЯ <<<

        # >>> КОД ИНЖЕКТА <<<
        if isinstance(report, dict):
            if hasattr(self, "payload_view"):
                self.payload_view.update_data(report)
            if getattr(self, "_payload_window", None) is not None:
                self._payload_window.set_report(report)
        # >>> /КОД ИНЖЕКТА <<<

        # >>> ОБОГАЩЕНИЕ <<<
        # Каждый новый прогон сбрасывает состояние вкладки «Обогащение»:
        # кнопка «Обогатить» снова активна, таблица очищена.
        if isinstance(report, dict) and hasattr(self, "enrich_view"):
            self.enrich_view.set_report(report)

        # >>> IPv6 <<<
        if isinstance(report, dict) and hasattr(self, "ipv6_view"):
            self.ipv6_view.update_data(report)

        if isinstance(report, dict) and hasattr(self, "timeline_view"):
            self.timeline_view.update_data(report)

        if isinstance(report, dict) and hasattr(self, "export_view"):
            self.export_view.update_data(report)

        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)


    # >>> /СИГНАЛЫ ОТ RunView <<<
    # >>> ОСТАНОВКА <<<
    def _on_analysis_cancelled(self) -> None:
        self._status_text.setText(tr("status.cancelled"))
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)


    # >>> ОСТАНОВКА <<<
    def _on_analysis_failed(self, msg: str) -> None:
        # Ошибку показывает RunView своим QMessageBox и toast.
        # Здесь только меню: даём пользователю снова нажать F5.
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)


    def _on_enrichment_finished(self) -> None:
        """После успешного обогащения — обновить текущую
        запись в «Истории».

        report в истории — тот же объект, что в run_view /
        enrich_view. Обогащение мутирует его in-place.
        QTextBrowser сам не перерисуется, поэтому дёргаем явно.
        """
        if hasattr(self, "history_view"):
            self.history_view.refresh_current()


    def _on_compare_history(self, old_report: dict) -> None:
        """Слот на сигнал compare_requested из HistoryView.

        Пользователь выбрал в истории старый прогон и хочет сравнить
        его с тем, что сейчас открыт в RunView.
        """
        current_report = self.run_view.last_report()
        if not current_report:
            QMessageBox.information(
                self,
                tr("error.no_current_run.title"),
                tr("error.no_current_run.body"),
            )
            return

        # Настраиваем DiffView и переключаемся на него
        self.diff_view.set_reports(old_report, current_report)

        # Ищем индекс вкладки DiffView
        idx = self.tabs.indexOf(self.diff_view)
        if idx >= 0:
            self.tabs.setCurrentIndex(idx)
