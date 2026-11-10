# -*- mode: python ; coding: utf-8 -*-
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(SPECPATH)

hiddenimports = ['PySide6.QtSvg']
hiddenimports += collect_submodules('paradox')
hiddenimports += collect_submodules('paradox_gui')


a = Analysis(
    [os.path.join(ROOT, 'paradox_gui', '__main__.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[(os.path.join(ROOT, 'paradox', 'rules'), 'paradox/rules')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Paradox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, 'paradox.ico'),
    version=os.path.join(ROOT, 'installer', 'version_info.txt'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Paradox',
)
