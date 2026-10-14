# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec для pcap-triage GUI.

Собираем onedir (папка с .exe + _internal/), не onefile.
Причины:
  * быстрее стартует — не распаковывается в temp при каждом запуске
  * легче диагностировать: видно, какие DLL и модули подхватились
  * PySide6 весит ~150 МБ; onefile будет каждый раз их разворачивать

Первая сборка — console=True: если .exe упадёт, увидим traceback в окне.
Когда убедимся, что всё стабильно — переключим на console=False.

hiddenimports: ядро pcap_triage импортируется динамически
(import внутри функций, monkey-patch модульных переменных),
статический анализ PyInstaller его не всегда видит.
Перечисляем явно — дешевле, чем ловить ImportError в .exe.
"""
from PyInstaller.utils.hooks import collect_submodules

# Все подмодули ядра — детекторы, экстракторы, правила, репортеры.
# collect_submodules рекурсивно обходит пакет и добавляет всё найденное.
# Так мы не забудем ни один детектор, даже если их добавят позже.
hidden = collect_submodules("pcap_triage")

# GUI-подмодули тоже динамические (views/widgets/dialogs/workers).
hidden += collect_submodules("pcap_triage_gui")


a = Analysis(
    ["pcap_triage_gui/__main__.py"],   # точка входа = то же, что python -m
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
    console=False,            # окна консоли нет; traceback идёт в QMessageBox
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