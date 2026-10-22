"""QApplication + главное окно.

Тема накладывается один раз на QApplication — дальше все виджеты
наследуют QSS. MainWindow — каркас (menu bar, вкладки, статус-бар);
логика вкладок появится по мере готовности views/*.
"""
import sys
import traceback

from PySide6.QtWidgets import QApplication

from paradox_gui.splash import ParadoxSplash
from paradox_gui.theme import apply_theme


def main() -> int:
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

    # Иконка приложения (taskbar + title bar)
    try:
        from paradox_gui.logo import get_app_icon
        app.setWindowIcon(get_app_icon())
    except Exception:
        pass

    # Splash ДО тяжёлых импортов (main_window тянет все views)
    splash = ParadoxSplash()
    splash.show()
    app.processEvents()

    # 1. Ключи Threat Intel из keyring -> os.environ
    splash.set_status("Загрузка ключей Threat Intel…")
    splash.set_progress(0.15)
    app.processEvents()
    try:
        from paradox_gui.secrets_store import SecretsStore
        SecretsStore().apply_all_to_env()
    except Exception:
        pass

    # 2. Тема
    splash.set_status("Применение тёмной темы…")
    splash.set_progress(0.35)
    app.processEvents()
    apply_theme(app)

    # 3. Тяжёлый импорт + сборка главного окна
    splash.set_status("Инициализация ядра и модулей…")
    splash.set_progress(0.55)
    app.processEvents()
    from paradox_gui.main_window import MainWindow
    w = MainWindow()

    # 4. Показ
    splash.set_status("Готово")
    splash.set_progress(1.0)
    app.processEvents()
    w.showMaximized()
    splash.finish(w)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
