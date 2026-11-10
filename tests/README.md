# tests/

Прогон:

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m pytest -q -k "not gui"   # без Qt
```

На Windows полный прогон может завершиться кодом `0xC0000005` уже после
всех тестов (баг выхода pytest/PySide6). Итог берите из отчёта:

```powershell
python -m pytest -q --junitxml=.qwen\tmp\junit.xml
```

`tools/verify_all.py` делает это сам.

## Куда писать новый тест

- **Новая функциональность** — в тематический файл `test_<модуль>.py`
  (`test_detectors.py`, `test_tls_cert.py`, `test_gui_*.py` …).
- **Ложное срабатывание на реальном трафике** — `test_regressions.py`.
  Один тест = один домен/IP/поток, который детектор не должен ловить.
- **Дефект из аудита, P0** (неверный вердикт, потеря данных, падение,
  сломанный релиз) — `test_p0_regressions.py`.
- **Дефект из аудита, P1** (заметная ошибка или риск, но не P0) —
  `test_p1_regressions.py`.

Три регрессионных файла не пересекаются по смыслу: FP → `test_regressions`,
аудиторские дефекты → `p0`/`p1` по приоритету. Не заводите четвёртый
`test_p2_regressions.py`: для P2 достаточно тематического файла.

## Маркеры

Зарегистрированы в `pyproject.toml`, чтобы `pytest -m` не ругался
на неизвестный маркер:

- `slow` — тяжёлые прогоны. Быстрый набор: `pytest -m "not slow"`.
- `gui` — нужен `QApplication` (offscreen). Такие файлы ставят
  `QT_QPA_PLATFORM=offscreen` до импорта Qt и объявляют
  `pytestmark = pytest.mark.gui`. Выбор: `pytest -m gui`,
  только ядро: `pytest -m "not gui"`.
- `pcap` — тест разбирает настоящий pcap-формат (файл или байты),
  а не подменяет читатель моком.
- `network` — тест ходит в реальную сеть. Сейчас таких нет: внешние
  сервисы замоканы, поэтому `pytest -m "not network"` ничего не
  меняет. Маркер зарезервирован, чтобы будущий сетевой тест нельзя
  было перепутать с обычным.
