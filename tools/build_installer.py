#!/usr/bin/env python3
"""Сборка Paradox.exe (PyInstaller) и инсталлера (Inno Setup)."""
import argparse
import hashlib
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

ISS_TEMPLATE = r'''; installer/paradox.iss — генерируется tools/build_installer.py
; Собрать: ISCC.exe installer\paradox.iss

#define AppName "{app_name}"
#define AppVersion "{app_version}"
#define AppPublisher "Andrey Grigoryev"
#define AppCopyright "© 2026 Andrey Grigoryev (v314xm)"

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
        Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe")), # <- вот он
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
                    help="не пересобирать PyInstaller, использовать dist/Paradox")
    args = ap.parse_args()

    iscc = find_iscc()
    if iscc is None:
        print("✗ ISCC.exe не найден. Установи Inno Setup 6: "
              "https://jrsoftware.org/isdl.php", file=sys.stderr)
        return 2
    print(f"✓ ISCC: {iscc}")

    # 1. PyInstaller
    if not args.skip_exe:
        print("\n[1/3] PyInstaller…")
        shutil.rmtree(BUILD, ignore_errors=True)
        shutil.rmtree(DIST / APP_NAME, ignore_errors=True)
        rc = run([
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean",
            str(ROOT / "Paradox.spec"),
        ])
        if rc != 0:
            print("✗ PyInstaller failed", file=sys.stderr)
            return rc
    else:
        print("[1/3] PyInstaller — пропущено")

    if not (DIST / APP_NAME / f"{APP_NAME}.exe").exists():
        print(f"✗ {DIST / APP_NAME / APP_NAME + '.exe'} не найден — "
              f"сначала сборка PyInstaller", file=sys.stderr)
        return 3
    print(f"✓ dist/{APP_NAME}/ готов")

    # 2. .iss
    print("\n[2/3] Генерация installer/paradox.iss…")
    INSTALLER_DIR.mkdir(parents=True, exist_ok=True)
    ISS.write_text(
        ISS_TEMPLATE.format(app_name=APP_NAME, app_version=APP_VERSION),
        encoding="utf-8-sig",
    )
    print(f"✓ {ISS.relative_to(ROOT)}")

    # 3. ISCC
    print("\n[3/3] Inno Setup…")
    rc = run([str(iscc), str(ISS)])
    if rc != 0:
        print("✗ ISCC failed", file=sys.stderr)
        return rc

    setup = DIST / f"{APP_NAME}-{APP_VERSION}-setup.exe"
    if setup.exists():
        size = setup.stat().st_size / (1024 * 1024)
        checksums = DIST / "SHA256SUMS"
        digest = hashlib.sha256(setup.read_bytes()).hexdigest()
        checksums.write_text(
            f"{digest}  {setup.name}\n", encoding="utf-8",
        )
        print(f"\n✓ Готово: {setup.relative_to(ROOT)}  ({size:.1f} МБ)")
        print(f"✓ SHA256: {checksums.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
