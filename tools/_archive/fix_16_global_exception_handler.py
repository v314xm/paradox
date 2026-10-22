# tools/fix_16_global_exception_handler.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "16-global-exception-handler"
TITLE = "GUI: глобальный обработчик исключений (QMessageBox вместо молчаливого падения)"
REL_APP = "paradox_gui/app.py"

_APP_IMPORTS_OLD = '''import sys

from PySide6.QtWidgets import QApplication'''

_APP_IMPORTS_NEW = '''import sys
import traceback

from PySide6.QtWidgets import QApplication'''

_APP_MAIN_OLD = '''def main() -> int:
    app = QApplication(sys.argv)
    # Иконка приложения (taskbar + title bar)'''

_APP_MAIN_NEW = '''def main() -> int:
    app = QApplication(sys.argv)

    # >>> ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ИСКЛЮЧЕНИЙ <<<
    # _runtime_hook.py уже подменил sys.excepthook, чтобы писать в файл.
    # Мы сохраняем его и оборачиваем: сначала показываем диалог, потом
    # вызываем оригинал (чтобы лог всё равно записался).
    _orig_hook = sys.excepthook

    def _gui_excepthook(exc_type, exc_value, exc_tb):
        tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            from PySide6.QtWidgets import QMessageBox
            if QApplication.instance():
                box = QMessageBox()
                box.setIcon(QMessageBox.Icon.Critical)
                box.setWindowTitle("Критическая ошибка")
                box.setText(
                    "Произошла непредвиденная ошибка.<br>"
                    "Подробности сохранены в <b>Paradox-error.log</b>."
                )
                box.setDetailedText(tb_text)
                box.exec()
        except Exception:
            # Если GUI сам сломался — не мешаем оригинальному хуку.
            pass

        if _orig_hook:
            _orig_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _gui_excepthook
    # >>> /ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ИСКЛЮЧЕНИЙ <<<

    # Иконка приложения (taskbar + title bar)'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_APP, _APP_IMPORTS_OLD, _APP_IMPORTS_NEW, required=False):
        changed = True
    if patch(root, REL_APP, _APP_MAIN_OLD, _APP_MAIN_NEW, required=False):
        changed = True

    if not fix_utils.DRY_RUN:
        text = (root / REL_APP).read_text(encoding="utf-8")
        if "_gui_excepthook" not in text:
            raise FixError(f"{REL_APP}: не удалось применить")
    return changed
