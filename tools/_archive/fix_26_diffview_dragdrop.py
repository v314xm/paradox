from pathlib import Path
from fix_utils import patch

FIX_ID = "fix_26"
TITLE = "DiffView: add drag-and-drop support for JSON reports"


def apply(root: Path) -> bool:
    changed = False
    rel = "paradox_gui/views/diff_view.py"

    # 1. Включаем прием drag&drop в конструкторе
    changed |= patch(
        root, rel,
        old=(
            "        self._old: dict | None = None\n"
            "        self._new: dict | None = None\n"
            "        self._build_ui()\n"
        ),
        new=(
            "        self._old: dict | None = None\n"
            "        self._new: dict | None = None\n"
            "        self.setAcceptDrops(True)\n"
            "        self._build_ui()\n"
        )
    )

    # 2. Добавляем методы dragEnterEvent и dropEvent в конец класса
    # (вставляем перед методом set_reports)
    changed |= patch(
        root, rel,
        old=(
            "    def set_reports(self, old: dict | None, new: dict | None) -> None:\n"
        ),
        new=(
            "    def dragEnterEvent(self, event) -> None:\n"
            "        if event.mimeData().hasUrls():\n"
            "            event.acceptProposedAction()\n"
            "\n"
            "    def dropEvent(self, event) -> None:\n"
            "        urls = event.mimeData().urls()\n"
            "        if not urls:\n"
            "            return\n"
            "        path = urls[0].toLocalFile()\n"
            "        if not path.lower().endswith('.json'):\n"
            "            QMessageBox.warning(self, 'Ошибка', 'Ожидается JSON-отчёт.')\n"
            "            return\n"
            "\n"
            "        try:\n"
            "            data = json.loads(Path(path).read_text(encoding='utf-8'))\n"
            "        except Exception as e:\n"
            "            QMessageBox.critical(self, 'Ошибка', f'Ошибка чтения: {e}')\n"
            "            return\n"
            "\n"
            "        if not isinstance(data, dict) or 'findings' not in data:\n"
            "            QMessageBox.critical(self, 'Не тот файл', 'Это не JSON-отчёт Paradox.')\n"
            "            return\n"
            "\n"
            "        # Логика распределения: сначала заполняем старый, потом новый.\n"
            "        # Если оба заполнены — сдвигаем: старый <- новый, новый <- загруженный.\n"
            "        if self._old is None:\n"
            "            self._old = data\n"
            "            self._lbl_old.setText(Path(path).name)\n"
            "        elif self._new is None:\n"
            "            self._new = data\n"
            "            self._lbl_new.setText(Path(path).name)\n"
            "        else:\n"
            "            self._old = self._new\n"
            "            self._lbl_old.setText(self._lbl_new.text())\n"
            "            self._new = data\n"
            "            self._lbl_new.setText(Path(path).name)\n"
            "\n"
            "        self._refresh()\n"
            "\n"
            "    def set_reports(self, old: dict | None, new: dict | None) -> None:\n"
        )
    )

    return changed
