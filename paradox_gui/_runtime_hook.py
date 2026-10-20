"""Runtime hook: ловит падения и пишет их в файл.

Подключается PyInstaller через runtime_hooks в .spec. Запускается
в момент старта .exe, до импорта app.py.

Зачем:
    При console=False stderr уходит в os.devnull — traceback теряется.
    Особенно это касается падений C-уровня (segfault, abort), которые
    PySide/QThread умеют устраивать при работе с потоками. Стандартный
    sys.excepthook их не видит вообще — нужен faulthandler.

Что делает:
    1. Открывает файл Paradox-error.log рядом с .exe.
    2. faulthandler.enable() — пишет туда C-уровневые краши
       (с полным стеком всех потоков).
    3. sys.excepthook — пишет туда Python-исключения, которые
       не поймал никто другой.

Файл — append, между запусками не затирается. Разделители «=====»
помогают отделить один запуск от другого.
"""
import datetime
import faulthandler
import pathlib
import sys
import traceback

# --- Куда писать ---
# Если запущено как .exe (frozen) — рядом с .exe. Иначе — в CWD.
if getattr(sys, "frozen", False):
    _log_dir = pathlib.Path(sys.executable).parent
else:
    _log_dir = pathlib.Path.cwd()

_log_path = _log_dir / "Paradox-error.log"

# --- Ротация: не даём файлу расти бесконечно ---
# При размере >5 МБ обрезаем до последних 2.5 МБ. За
# несколько лет использования файл не превратится в гигабайт.
try:
    if _log_path.exists() and _log_path.stat().st_size > 5 * 1024 * 1024:
        _text = _log_path.read_text(encoding="utf-8", errors="ignore")
        _log_path.write_text(_text[-2_500_000:], encoding="utf-8")
except Exception:
    # Если не получилось обрезать — не критично, работаем дальше.
    pass

try:
    # line_buffering=True — каждая строка уходит на диск сразу.
    # Если процесс убьёт себя через os.abort(), буфер не потеряется.
    _log_file = open(_log_path, "a", encoding="utf-8", buffering=1)
    _log_file.write("\n" + "=" * 72 + "\n")
    _log_file.write(
        f"START {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"argv={sys.argv}\n"
        f"cwd={pathlib.Path.cwd()}\n"
        f"frozen={getattr(sys, 'frozen', False)}\n"
    )
    _log_file.flush()

    # --- C-уровневые краши ---
    # segfault, abort, деление на ноль в C-коде, поломанный GIL.
    # all_threads=True — стек ВСЕХ потоков, не только упавшего.
    # При QThread-крашах это критично: видим, что делал воркер.
    faulthandler.enable(file=_log_file, all_threads=True)

    # --- Python-исключения ---
    def _uncaught_hook(exc_type, exc_value, exc_tb) -> None:
        try:
            _log_file.write("\n" + "-" * 72 + "\n")
            _log_file.write(
                f"UNCAUGHT {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
            )
            traceback.print_exception(exc_type, exc_value, exc_tb, file=_log_file)
            _log_file.flush()
        except Exception:
            # Не даём хуку самому уронить процесс.
            pass

        # Если stderr ещё куда-то идёт (при console=True) — дублируем.
        try:
            traceback.print_exception(exc_type, exc_value, exc_tb)
        except Exception:
            pass

    sys.excepthook = _uncaught_hook

except Exception:
    # Если лог не открылся — не падаем на старте. Просто идём без него.
    pass