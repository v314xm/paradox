"""
Пользовательские детекторы из плагинов.

Плагин — обычный .py-файл в `~/.paradox/plugins/`, который
экспортирует один из вариантов:

    DETECTORS = [MyDetector()]      # список экземпляров
    DETECTOR = MyDetector           # класс (будет создан)

Требования к детектору те же, что к встроенным: строковый `name`
и `run(state, config) -> list[Finding]`.

Почему так:
  - падение или синтаксическая ошибка плагина не должны валить
    пайплайн — ошибка попадает в state.extractor_errors["plugin"];
  - имя плагина не должно совпадать с встроенным детектором,
    иначе непонятно, кто дал finding;
  - по умолчанию загрузка выключена (plugins_enabled=False):
    исполнять чужой код без явного согласия нельзя.

Безопасность: плагин — это код на Python, он исполняется с правами
пользователя. Каталог задаётся явно через config.plugins_dir.
"""
import logging
from dataclasses import dataclass, field
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from paradox.config import Config

DEFAULT_PLUGINS_DIR = Path.home() / ".paradox" / "plugins"
_MODULE_PREFIX = "paradox_plugin_"


@dataclass
class PluginLoadResult:
    detectors: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _is_detector(obj) -> bool:
    name = getattr(obj, "name", None)
    run = getattr(obj, "run", None)
    return (
        isinstance(name, str)
        and bool(name.strip())
        and callable(run)
    )


def _candidates(module) -> list:
    """Экземпляры детекторов из модуля плагина."""
    candidates: list = []
    exported = getattr(module, "DETECTORS", None)
    if exported is not None:
        if isinstance(exported, (list, tuple)):
            candidates.extend(exported)
        else:
            candidates.append(exported)

    single = getattr(module, "DETECTOR", None)
    if single is not None:
        candidates.append(single() if isinstance(single, type) else single)

    return candidates


def _load_module(path: Path):
    spec = spec_from_file_location(f"{_MODULE_PREFIX}{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"не удалось создать spec для {path.name}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_detector_plugins(
    config: Config,
    reserved_names: set[str] | None = None,
) -> PluginLoadResult:
    """
    Загрузить плагины из config.plugins_dir.

    reserved_names — имена уже активных детекторов: плагин с таким
    именем пропускается, чтобы findings не путались.
    """
    result = PluginLoadResult()
    if not getattr(config, "plugins_enabled", False):
        return result

    directory = Path(config.plugins_dir).expanduser()
    if not directory.is_dir():
        return result

    reserved = set(reserved_names or ())

    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            module = _load_module(path)
        except Exception as exc:
            result.errors.append(f"{path.name}: загрузка не удалась: {exc!r}")
            continue

        for candidate in _candidates(module):
            if not _is_detector(candidate):
                result.errors.append(
                    f"{path.name}: объект не похож на детектор "
                    f"(нужны name: str и run())",
                )
                continue
            if candidate.name in reserved:
                result.errors.append(
                    f"{path.name}: имя '{candidate.name}' уже занято",
                )
                continue
            reserved.add(candidate.name)
            result.detectors.append(candidate)

    if result.errors:
        logging.getLogger(__name__).warning(
            "plugins: %d problem(s): %s",
            len(result.errors), "; ".join(result.errors),
        )
    return result
