"""Зона drag&drop под pcap-файл.

Реальный виджет: принимает файлы из проводника, открывает QFileDialog
по клику, испускает pcap_selected(str) при валидном файле. Сигнал —
строка, а не Path: QThread-сигналы надёжнее с примитивами, а Path
восстановится в одной строке на той стороне.
"""
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QVBoxLayout,
)

from paradox_gui.i18n import tr


class DropZone(QFrame):
    pcap_selected = Signal(str)  # абсолютный путь к файлу

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("dragActive", False)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Логотип вместо эмодзи папки (v1.2)
        try:
            from paradox_gui.logo import render_logo
            self._icon = QLabel()
            self._icon.setPixmap(render_logo(64))
            self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        except Exception:
            self._icon = QLabel("📁")
            self._icon.setStyleSheet("font-size: 32px;")
            self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._title = QLabel(tr("run.drop_title"))
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._hint = QLabel(tr("run.drop_hint"))
        self._hint.setObjectName("muted")
        self._hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self._icon)
        layout.addWidget(self._title)
        layout.addWidget(self._hint)

    # ---------- мышь: клик = диалог ----------

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_dialog()   # было self._open_dialog()
        super().mousePressEvent(event)

    def open_dialog(self) -> None:
        """Открыть QFileDialog. Публичный метод — дёргается из меню Ctrl+O."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("run.open_pcap_dialog"),
            "",
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if path:
            self._emit_selected(path)

    # ---------- drag&drop ----------

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_drag_active(True)

    def dragLeaveEvent(self, event) -> None:
        self._set_drag_active(False)

    def dropEvent(self, event) -> None:
        self._set_drag_active(False)
        urls = event.mimeData().urls()
        if not urls:
            return
        local = urls[0].toLocalFile()  # берём первый файл, остальные игнорируем
        if local:
            self._emit_selected(local)

    # ---------- общее ----------


    # ---------- компактный режим ----------

    def set_compact(self, path: str, display_name: str | None = None) -> None:
        """Схлопнуть зону в одну строку после успешного прогона.

        Освобождает ~120px по вертикали. Drag&drop и клик остаются
        рабочими: пользователь по-прежнему может перетащить новый файл
        или кликнуть, чтобы открыть диалог.

        display_name — переопределяет отображаемое имя (для multi-pcap).
        Если не задано, берётся basename из path.
        """
        name = display_name or Path(path).name
        self._icon.hide()
        self._title.setText(f"📄 {name}")
        self._title.setStyleSheet("font-size: 14px;")
        self._hint.setText("Перетащите другой pcap или нажмите, чтобы сменить")

        # Паддинги — через layout. Иначе sizeHint останется прежним.
        self.layout().setContentsMargins(20, 10, 20, 10)
        self.setProperty("compact", True)
        self.style().unpolish(self)
        self.style().polish(self)

    def _emit_selected(self, path: str) -> None:
        p = Path(path)
        # Молча выходим, если файл не существует: сообщение об ошибке —
        # дело вызывающей стороны, а не зоны.
        if not p.exists() or not p.is_file():
            return
        self.pcap_selected.emit(str(p.resolve()))

    def _set_drag_active(self, active: bool) -> None:
        # Динамическое свойство + repolish — стандартный способ сказать QSS
        # «этот виджет в другом состоянии». Просто setStyleSheet не годится:
        # затрёт общую тему.
        self.setProperty("dragActive", active)
        self.style().unpolish(self)
        self.style().polish(self)
