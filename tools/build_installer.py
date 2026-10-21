#!/usr/bin/env python3
"""РЎР±РѕСЂРєР° Paradox.exe (PyInstaller) Рё РёРЅСЃС‚Р°Р»Р»РµСЂР° (Inno Setup)."""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
INSTALLER_DIR = ROOT / "installer"
ISS = INSTALLER_DIR / "paradox.iss"
APP_NAME = "Paradox"
from paradox import __version__ as APP_VERSION

ISS_TEMPLATE = r'''; installer/paradox.iss вЂ” РіРµРЅРµСЂРёСЂСѓРµС‚СЃСЏ tools/build_installer.py
; РЎРѕР±СЂР°С‚СЊ: ISCC.exe installer\paradox.iss

#define AppName "{app_name}"
#define AppVersion "{app_version}"
#define AppPublisher "Andrey Grigoryev"
#define AppCopyright "В© 2026 Andrey Grigoryev (v314xm)"

[Setup]
AppId={{{{D4C7B3F1-9A2E-4E8B-B6F0-5E7A1C2D3F40}}}}
AppName={{#AppName}}
AppVersion={{#AppVersion}}
AppVerName={{#AppName}} {{#AppVersion}}
AppPublisher={{#AppPublisher}}
AppCopyright={{#AppCopyright}}
DefaultDirName={{autopf}}\{{#AppName}}
DefaultGroupName={{#AppName}}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename={{#AppName}}-{{#AppVersion}}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={{#AppName}} {{#AppVersion}}
UninstallDisplayIcon={{app}}\{{#AppName}}.exe

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{{cm:CreateDesktopIcon}}"; GroupDescription: "{{cm:AdditionalIcons}}"; Flags: unchecked

[Files]
Source: "..\dist\{{#AppName}}\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{{group}}\{{#AppName}}"; Filename: "{{app}}\{{#AppName}}.exe"
Name: "{{group}}\{{cm:UninstallProgram,{{#AppName}}}}"; Filename: "{{uninstallexe}}"
Name: "{{autodesktop}}\{{#AppName}}"; Filename: "{{app}}\{{#AppName}}.exe"; Tasks: desktopicon

[Run]
Filename: "{{app}}\{{#AppName}}.exe"; Description: "{{cm:LaunchProgram,{{#AppName}}}}"; Flags: nowait postinstall skipifsilent
'''


def find_iscc() -> Path | None:
    import os
    candidates = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
        Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe")), # <- РІРѕС‚ РѕРЅ
    ]
    for c in candidates:
        if c.exists():
            return c
    w = shutil.which("ISCC")
    return Path(w) if w else None


def run(cmd: list[str], cwd: Path | None = None) -> int:
    print("$", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, cwd=cwd or ROOT).returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-exe", action="store_true",
                    help="РЅРµ РїРµСЂРµСЃРѕР±РёСЂР°С‚СЊ PyInstaller, РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊ dist/Paradox")
    args = ap.parse_args()

    iscc = find_iscc()
    if iscc is None:
        print("вњ— ISCC.exe РЅРµ РЅР°Р№РґРµРЅ. РЈСЃС‚Р°РЅРѕРІРё Inno Setup 6: "
              "https://jrsoftware.org/isdl.php", file=sys.stderr)
        return 2
    print(f"вњ“ ISCC: {iscc}")

    # 1. PyInstaller
    if not args.skip_exe:
        print("\n[1/3] PyInstallerвЂ¦")
        shutil.rmtree(BUILD, ignore_errors=True)
        shutil.rmtree(DIST / APP_NAME, ignore_errors=True)
        rc = run([
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--windowed", "--onedir",
            "--name", APP_NAME,
            "--collect-submodules", "paradox",
            "--collect-submodules", "paradox_gui",
            "--hidden-import", "PySide6.QtSvg",
            str(ROOT / "paradox_gui" / "__main__.py"),
        ])
        if rc != 0:
            print("вњ— PyInstaller failed", file=sys.stderr)
            return rc
    else:
        print("[1/3] PyInstaller вЂ” РїСЂРѕРїСѓС‰РµРЅРѕ")

    if not (DIST / APP_NAME / f"{APP_NAME}.exe").exists():
        print(f"вњ— {DIST / APP_NAME / APP_NAME + '.exe'} РЅРµ РЅР°Р№РґРµРЅ вЂ” "
              f"СЃРЅР°С‡Р°Р»Р° СЃР±РѕСЂРєР° PyInstaller", file=sys.stderr)
        return 3
    print(f"вњ“ dist/{APP_NAME}/ РіРѕС‚РѕРІ")

    # 2. .iss
    print("\n[2/3] Р“РµРЅРµСЂР°С†РёСЏ installer/paradox.issвЂ¦")
    INSTALLER_DIR.mkdir(parents=True, exist_ok=True)
    ISS.write_text(
        ISS_TEMPLATE.format(app_name=APP_NAME, app_version=APP_VERSION),
        encoding="utf-8",
    )
    print(f"вњ“ {ISS.relative_to(ROOT)}")

    # 3. ISCC
    print("\n[3/3] Inno SetupвЂ¦")
    rc = run([str(iscc), str(ISS)])
    if rc != 0:
        print("вњ— ISCC failed", file=sys.stderr)
        return rc

    setup = DIST / f"{APP_NAME}-{APP_VERSION}-setup.exe"
    if setup.exists():
        size = setup.stat().st_size / (1024 * 1024)
        print(f"\nвњ“ Р“РѕС‚РѕРІРѕ: {setup.relative_to(ROOT)}  ({size:.1f} РњР‘)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
