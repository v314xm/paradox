"""Точка входа: python -m paradox_gui.

Ключевой момент: PyInstaller в режиме --windowed (console=False)
зануляет sys.stdout и sys.stderr. Scapy (и часть ядра) при импорте
вызывает sys.stdout.isatty() — получает AttributeError и валит прогон.
Решение — подменить None на os.devnull ДО любых импортов ядра.

При обычном `python -m paradox_gui` это no-op: stdout уже есть,
проверки на None не срабатывают.
"""
import os
import sys

# >>> ЗАЩИТА ОТ --windowed <<<
# Должно стоять в самом начале, до `from paradox_gui.app import main`.
# Иначе scapy импортируется раньше и падает на isatty().
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
# >>> /ЗАЩИТА ОТ --windowed <<<

from paradox_gui.app import main

if __name__ == "__main__":
    sys.exit(main())
