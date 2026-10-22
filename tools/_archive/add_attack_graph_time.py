"""Attack Graph: временная шкала и playback."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def add_ui():
    old = (
        '        self._view.fit()\n'
        '        # Вызываем fit ТОЛЬКО когда окно уже развернуто на весь экран\n'
        '        self._view.fit()\n'
    )
    if old not in PATH.read_text(encoding="utf-8"):
        # fallback на случай если showEvent отличается
        pass

    # Ищем _build и добавляем нижнюю панель со слайдером
    old_build = (
        '        splitter = QSplitter(Qt.Orientation.Horizontal)\n'
        '        splitter.addWidget(left)\n'
        '        splitter.addWidget(self._view)\n'
        '        splitter.addWidget(right)\n'
        '        splitter.setSizes([340, 700, 340])\n'
        '        root.addWidget(splitter)\n'
        '\n'
        '        btn = QPushButton("Закрыть")\n'
        '        btn.setObjectName("primary")\n'
        '        btn.clicked.connect(self.accept)\n'
        '        root.addWidget(btn, alignment=Qt.AlignmentFlag.AlignBottom)\n'
    )
    new_build = (
        '        splitter = QSplitter(Qt.Orientation.Horizontal)\n'
        '        splitter.addWidget(left)\n'
        '        splitter.addWidget(self._view)\n'
        '        splitter.addWidget(right)\n'
        '        splitter.setSizes([340, 700, 340])\n'
        '\n'
        '        # --- Временная шкала (Time Machine) ---\n'
        '        timeline_row = QHBoxLayout()\n'
        '        timeline_row.setContentsMargins(0, 10, 0, 10)\n'
        '        \n'
        '        self._btn_play = QPushButton("▶ Воспроизвести")\n'
        '        self._btn_play.setFixedWidth(140)\n'
        '        self._btn_play.clicked.connect(self._toggle_play)\n'
        '        timeline_row.addWidget(self._btn_play)\n'
        '\n'
        '        self._time_slider = QSlider(Qt.Orientation.Horizontal)\n'
        '        self._time_slider.setRange(0, 1000)\n'
        '        self._time_slider.setValue(1000)\n'
        '        self._time_slider.valueChanged.connect(self._on_time_changed)\n'
        '        timeline_row.addWidget(self._time_slider, stretch=1)\n'
        '\n'
        '        self._time_label = QLabel("—")\n'
        '        self._time_label.setStyleSheet("color: #a0a0b0; font-family: Consolas;")\n'
        '        self._time_label.setFixedWidth(160)\n'
        '        self._time_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)\n'
        '        timeline_row.addWidget(self._time_label)\n'
        '\n'
        '        # Контейнер под центральную часть (Граф + Таймлайн)\n'
        '        center_widget = QWidget()\n'
        '        center_layout = QVBoxLayout(center_widget)\n'
        '        center_layout.setContentsMargins(0, 0, 0, 0)\n'
        '        center_layout.addWidget(self._view, stretch=1)\n'
        '        center_layout.addLayout(timeline_row)\n'
        '\n'
        '        splitter = QSplitter(Qt.Orientation.Horizontal)\n'
        '        splitter.addWidget(left)\n'
        '        splitter.addWidget(center_widget)\n'
        '        splitter.addWidget(right)\n'
        '        splitter.setSizes([340, 700, 340])\n'
        '        root.addWidget(splitter, stretch=1)\n'
        '\n'
        '        btn_row = QHBoxLayout()\n'
        '        btn_row.addStretch(1)\n'
        '        btn = QPushButton("Закрыть")\n'
        '        btn.setObjectName("primary")\n'
        '        btn.clicked.connect(self.accept)\n'
        '        btn_row.addWidget(btn)\n'
        '        root.addLayout(btn_row)\n'
    )
    return _patch(PATH, old_build, new_build, "timeline UI")


def add_logic():
    # Добавляем импорты QSlider, QTimer
    old_imports = (
        '    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,\n'
        '    QGraphicsPathItem, QGraphicsTextItem, QSplitter,\n'
        ')\n'
    )
    new_imports = (
        '    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,\n'
        '    QGraphicsPathItem, QGraphicsTextItem, QSplitter,\n'
        '    QSlider,\n'
        ')\n'
    )
    if not _patch(PATH, old_imports, new_imports, "imports"):
        return False

    # Добавляем инициализацию таймера и переменных в __init__
    old_init = (
        '        self._node_items: dict[str, QGraphicsEllipseItem] = {}\n'
        '        self._edge_items: list[QGraphicsPathItem] = []\n'
    )
    new_init = (
        '        self._node_items: dict[str, QGraphicsEllipseItem] = {}\n'
        '        self._edge_items: list[QGraphicsPathItem] = []\n'
        '        self._t_min = 0.0\n'
        '        self._t_max = 0.0\n'
        '        self._play_timer = QTimer(self)\n'
        '        self._play_timer.timeout.connect(self._on_play_tick)\n'
    )
    if not _patch(PATH, old_init, new_init, "init timer"):
        return False

    # После отрисовки считаем t_min и t_max
    old_draw = (
        '        for n in self._nodes:\n'
        '            if n["ip"] in pos:\n'
        '                self._draw_node(pos[n["ip"]], n)\n'
        '\n'
        '        self._view.fit()\n'
    )
    new_draw = (
        '        for n in self._nodes:\n'
        '            if n["ip"] in pos:\n'
        '                self._draw_node(pos[n["ip"]], n)\n'
        '\n'
        '        self._setup_timeline()\n'
        '        self._view.fit()\n'
    )
    if not _patch(PATH, old_draw, new_draw, "draw hook"):
        return False

    # Добавляем сами методы в конец класса (перед _on_select)
    old_select = '    def _on_select(self, row: int):\n'
    new_methods = '''    def _setup_timeline(self):
        """Найти границы времени и настроить слайдер."""
        times = []
        for n in self._nodes:
            if n.get("first_ts"): times.append(n["first_ts"])
            if n.get("last_ts"): times.append(n["last_ts"])
        for e in self._edges:
            if e.get("first_ts"): times.append(e["first_ts"])
            if e.get("last_ts"): times.append(e["last_ts"])

        if not times:
            self._time_slider.setEnabled(False)
            self._btn_play.setEnabled(False)
            self._time_label.setText("—")
            return

        self._t_min = min(times)
        self._t_max = max(times)

        # Если всё произошло в одну секунду, слайдер бесполезен
        if self._t_max - self._t_min < 1.0:
            self._time_slider.setEnabled(False)
            self._btn_play.setEnabled(False)
            self._update_time_label(self._t_max)
        else:
            self._time_slider.setEnabled(True)
            self._btn_play.setEnabled(True)
            self._on_time_changed(self._time_slider.value())

    def _update_time_label(self, ts: float):
        from datetime import datetime
        if not ts:
            self._time_label.setText("—")
            return
        try:
            dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            self._time_label.setText(dt)
        except (OSError, ValueError):
            self._time_label.setText(f"{ts:.0f}")

    def _on_time_changed(self, val: int):
        """Плавно скрываем то, что ещё не произошло."""
        if self._t_max <= self._t_min:
            return

        frac = val / 1000.0
        current_t = self._t_min + (self._t_max - self._t_min) * frac
        self._update_time_label(current_t)

        for n in self._nodes:
            item = self._node_items.get(n["ip"])
            if not item:
                continue
            # Узел виден, если его время наступило (или у него нет таймстампа)
            visible = (not n.get("first_ts")) or (n["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)

        for item, e in zip(self._edge_items, self._edges):
            visible = (not e.get("first_ts")) or (e["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)

    def _toggle_play(self):
        if self._play_timer.isActive():
            self._play_timer.stop()
            self._btn_play.setText("▶ Воспроизвести")
        else:
            if self._time_slider.value() >= 1000:
                self._time_slider.setValue(0)
            self._play_timer.start(50)  # каждые 50 мс
            self._btn_play.setText("⏸ Пауза")

    def _on_play_tick(self):
        val = self._time_slider.value() + 5
        if val >= 1000:
            val = 1000
            self._play_timer.stop()
            self._btn_play.setText("▶ Воспроизвести")
        self._time_slider.setValue(val)

'''
    return _patch(PATH, old_select, new_methods + old_select, "timeline methods")


def main():
    print("=" * 60)
    print(" attack_graph: add time machine")
    print("=" * 60)
    ok = True
    for fn in (add_ui, add_logic):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
