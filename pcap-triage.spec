# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec для pcap-triage GUI.

Собираем onedir (папка с .exe + _internal/), не onefile.
Причины:
  * быстрее стартует — не распаковывается в temp при каждом запуске
  * легче диагностировать: видно, какие DLL и модули подхватились
  * PySide6 весит ~150 МБ; onefile будет каждый раз их разворачивать

Про console:
  * console=True  — в .exe видна консоль. Нужна для отладки:
    traceback от Python-исключений и вывод ядра (например, scapy)
    идут прямо в это окно.
  * console=False — тихий запуск, как обычное десктоп-приложение.
    Для отладки при этом работает runtime_hook — см. ниже.

Текущее состояние — console=True. Переключим на False, когда
закончим разбираться с падениями при массовых прогонах.

runtime_hooks:
  pcap_triage_gui/_runtime_hook.py — при старте .exe подписывается
  на sys.excepthook и faulthandler. Ловит всё, что не поймал никто
  другой, и пишет в pcap-triage-error.log рядом с .exe. Это работает
  даже при console=False и ловит C-уровневые краши (segfault,
  abort из QThread).

hiddenimports:
  Ядро pcap_triage импортируется динамически (import внутри функций,
  monkey-patch модульных переменных), статический анализ PyInstaller
  его не всегда видит. Перечисляем явно — дешевле, чем ловить
  ImportError в .exe.
"""
from PyInstaller.utils.hooks import collect_submodules

# Все подмодули ядра — детекторы, экстракторы, правила, репортеры.
# collect_submodules рекурсивно обходит пакет и добавляет всё найденное.
# Так мы не забудем ни один детектор, даже если их добавят позже.
hidden = collect_submodules("pcap_triage")

# GUI-подмодули тоже динамические (views/widgets/dialogs/workers).
hidden += collect_submodules("pcap_triage_gui")

# sqlite3 для enrichment-кэша. Обычно PyInstaller его видит сам, но
# _sqlite3.dll иногда теряется в зависимости от окружения.
hidden += ["sqlite3", "_sqlite3"]


a = Analysis(
    ["pcap_triage_gui/__main__.py"],   # точка входа = то же, что python -m
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    # Runtime hook — подписывается на excepthook и faulthandler ДО
    # запуска app.py. Пишет всё в pcap-triage-error.log рядом с .exe.
    runtime_hooks=["pcap_triage_gui/_runtime_hook.py"],
    excludes=[
        # Не тащим тяжёлое, если оно случайно подтянется.
        "tkinter", "matplotlib", "numpy.testing", "pytest",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="pcap-triage",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                # UPX ломает Qt DLL — не используем
    # >>> Отладка массовых падений <<<
    # console=True пока разбираемся с крэшем на 3-м прогоне.
    # Когда починим — вернём False. Runtime hook при этом
    # продолжит писать лог — просто в фоне.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,                # позже, когда будет .ico
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="pcap-triage",       # папка dist/pcap-triage/
)