"""Fix: rewrite _build method (duplicate splitter bug)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"

NEW_BUILD = '''    def _build(self):
        root = QHBoxLayout(self)

        # --- Левая панель: список путей ---
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel(f"Пути атаки ({len(self._paths)})")
        lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        lv.addWidget(lbl)
        self._path_list = QListWidget()
        self._path_list.setMinimumWidth(320)
        for i, p in enumerate(self._paths):
            item = QListWidgetItem(self._fmt_path(p))
            item.setData(Qt.ItemDataRole.UserRole, i)
            col = _SEV_COLOR.get(p.get("severity", "medium"), "#d0c040")
            item.setForeground(QBrush(QColor(col)))
            self._path_list.addItem(item)
        self._path_list.currentRowChanged.connect(self._on_select)
        lv.addWidget(self._path_list, stretch=1)
        left.setFixedWidth(360)

        # --- Центральная панель: граф + таймлайн ---
        self._scene = QGraphicsScene(self)
        self._view = _Zoomable(self._scene)

        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.addWidget(self._view, stretch=1)

        # Временная шкала (Time Machine)
        timeline_row = QHBoxLayout()
        timeline_row.setContentsMargins(0, 10, 0, 10)

        self._btn_play = QPushButton("\\u25b6 \\u0412\\u043e\\u0441\\u043f\\u0440\\u043e\\u0438\\u0437\\u0432\\u0435\\u0441\\u0442\\u0438")
        self._btn_play.setFixedWidth(160)
        self._btn_play.clicked.connect(self._toggle_play)
        timeline_row.addWidget(self._btn_play)

        self._time_slider = QSlider(Qt.Orientation.Horizontal)
        self._time_slider.setRange(0, 1000)
        self._time_slider.setValue(1000)
        self._time_slider.valueChanged.connect(self._on_time_changed)
        timeline_row.addWidget(self._time_slider, stretch=1)

        self._time_label = QLabel("\\u2014")
        self._time_label.setStyleSheet("color: #a0a0b0; font-family: Consolas;")
        self._time_label.setFixedWidth(160)
        self._time_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        timeline_row.addWidget(self._time_label)

        center_layout.addLayout(timeline_row)

        # --- Правая панель: детали ---
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 8, 8, 8)
        r_lbl = QLabel("\\u0414\\u0435\\u0442\\u0430\\u043b\\u0438 \\u043f\\u0443\\u0442\\u0438")
        r_lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        rv.addWidget(r_lbl)
        self._details = QTextBrowser()
        rv.addWidget(self._details, stretch=1)
        right.setFixedWidth(360)

        # --- Splitter ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(center_widget)
        splitter.addWidget(right)
        splitter.setSizes([340, 700, 340])
        root.addWidget(splitter, stretch=1)

        # --- Кнопка закрыть ---
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn = QPushButton("\\u0417\\u0430\\u043a\\u0440\\u044b\\u0442\\u044c")
        btn.setObjectName("primary")
        btn.clicked.connect(self.accept)
        btn_row.addWidget(btn)
        root.addLayout(btn_row)

'''


def main():
    src = PATH.read_text(encoding="utf-8")

    # Находим начало метода _build
    start = src.find("    def _build(self):")
    if start < 0:
        print("[ERROR] _build not found", file=sys.stderr)
        return 1

    # Находим начало следующего метода (_fmt_path)
    end = src.find("    def _fmt_path(self, p: dict) -> str:", start)
    if end < 0:
        print("[ERROR] _fmt_path not found", file=sys.stderr)
        return 1

    new_src = src[:start] + NEW_BUILD + src[end:]
    PATH.write_text(new_src, encoding="utf-8")
    print("[OK] _build rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
