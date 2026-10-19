"""QApplication + главное окно.

Тема накладывается один раз на QApplication — дальше все виджеты
наследуют QSS. MainWindow — каркас (menu bar, вкладки, статус-бар);
логика вкладок появится по мере готовности views/*.
"""
import sys
from PySide6.QtWidgets import QApplication

from pcap_triage_gui.main_window import MainWindow
from pcap_triage_gui.theme import apply_theme


def main() -> int:
    app = QApplication(sys.argv)
    # Ключи Threat Intel из keyring -> os.environ до первого lookup.
    try:
        from pcap_triage_gui.secrets_store import SecretsStore
        SecretsStore().apply_all_to_env()
    except Exception:
        pass
    apply_theme(app)
    w = MainWindow()
    w.showMaximized()      # вместо w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())