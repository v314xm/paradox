"""Всплывающие уведомления в правом нижнем углу.

Показываются поверх всего, исчезают сами через N секунд. Отдельное
окно (Qt.Tool | Qt.FramelessWindowHint), а не виджет внутри окна:
так toast не влияет на layout и не сдвигает другие виджеты.

Очередь: несколько toast'ов стекаются снизу вверх с шагом 8px.
"""
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


_TOAST_WIDTH = 320
_TOAST_MARGIN = 20     # отступ от краёв экрана
_TOAST_GAP = 8         # зазор между соседними toast'ами
_TOAST_LIFETIME_MS = 4000


class Toast(QWidget):
    # kind: 'info' | 'success' | 'warn' | 'error'
    def __init__(self, message: str, kind: str = "info", parent=None) -> None:
        super().__init__(parent)
        self._kind = kind
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setFixedWidth(_TOAST_WIDTH)
        self._build_ui(message)
        self._schedule_close()

    def _build_ui(self, message: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)

        lbl = QLabel(message)
        lbl.setWordWrap(True)
        lbl.setObjectName("toastText")
        layout.addWidget(lbl)

        # objectName несёт kind — QSS красит по нему левую полосу.
        self.setObjectName(f"toast_{self._kind}")

    def _schedule_close(self) -> None:
        QTimer.singleShot(_TOAST_LIFETIME_MS, self.close)


class ToastManager:
    """Стекает активные toast'ы в правом нижнем углу экрана.

    Не виджет — просто координатор. Кладём в поле MainWindow
    (self.toasts = ToastManager(self)), чтобы окно было parent'ом
    и toast'ы автоматически закрывались вместе с приложением.
    """
    def __init__(self, parent_window) -> None:
        self._parent = parent_window
        self._active: list[Toast] = []

    def show(self, message: str, kind: str = "info") -> None:
        t = Toast(message, kind, parent=self._parent)
        t.destroyed.connect(lambda *_: self._drop(t))
        self._active.append(t)
        t.show()
        self._reposition()

    def _drop(self, t: Toast) -> None:
        if t in self._active:
            self._active.remove(t)
        self._reposition()

    def _reposition(self) -> None:
        """Снизу вверх: свежий toast над остальными."""
        if not self._active:
            return
        screen = self._parent.screen().availableGeometry()

        # Снизу растём: y убывает для каждого следующего toast'а.
        y_cursor = screen.bottom() - _TOAST_MARGIN
        for t in reversed(self._active):
            h = t.sizeHint().height()
            y_cursor -= h
            x = screen.right() - _TOAST_MARGIN - _TOAST_WIDTH
            t.move(x, y_cursor)
            y_cursor -= _TOAST_GAP