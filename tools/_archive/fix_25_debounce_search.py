from pathlib import Path
from fix_utils import patch

FIX_ID = "fix_25"
TITLE = "GUI: debounce search filtering in FindingsTable"

def apply(root: Path) -> bool:
    changed = False
    rel = "paradox_gui/widgets/findings_table.py"

    # 1. Инициализация таймера (без привязки к комментариям)
    changed |= patch(
        root, rel,
        old=(
            "        self._findings_cache: list[dict] = []\n"
            "        self._build_ui()\n"
        ),
        new=(
            "        self._findings_cache: list[dict] = []\n"
            "        \n"
            "        # Дебаунсер для поиска (защита от лагов при вводе)\n"
            "        from PySide6.QtCore import QTimer\n"
            "        self._search_timer = QTimer(self)\n"
            "        self._search_timer.setSingleShot(True)\n"
            "        self._search_timer.setInterval(200)\n"
            "        self._search_timer.timeout.connect(self._apply_filters)\n"
            "        \n"
            "        self._build_ui()\n"
        )
    )

    # 2. Подключаем textChanged к таймеру
    changed |= patch(
        root, rel,
        old='        self._search.textChanged.connect(self._apply_filters)\n',
        new='        self._search.textChanged.connect(lambda: self._search_timer.start())\n'
    )

    # 3. В _reset_filters тоже нужно сбрасывать таймер
    changed |= patch(
        root, rel,
        old=(
            "        self._conf_filter.setCurrentIndex(0)\n"
            "        self._search.blockSignals(False)\n"
            "        self._type_filter.blockSignals(False)\n"
            "        self._conf_filter.blockSignals(False)\n"
            "        self._apply_filters()\n"
        ),
        new=(
            "        self._conf_filter.setCurrentIndex(0)\n"
            "        self._search.blockSignals(False)\n"
            "        self._type_filter.blockSignals(False)\n"
            "        self._conf_filter.blockSignals(False)\n"
            "        self._search_timer.stop()\n"
            "        self._apply_filters()\n"
        )
    )

    return changed
