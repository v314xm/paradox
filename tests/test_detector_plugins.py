"""
Тесты загрузчика плагинов-детекторов.

Плагин — .py в config.plugins_dir с DETECTORS = [...] или DETECTOR = Class.
По умолчанию плагины выключены.
"""
import textwrap

from paradox.config import Config
from paradox.detector_plugins import (
    DEFAULT_PLUGINS_DIR,
    load_detector_plugins,
)
from paradox.models import CaptureState
from paradox.pipeline import _detect

_PLUGIN = textwrap.dedent(
    """
    from paradox.models import Finding


    class MyDetector:
        name = "my_detector"

        def run(self, state, config):
            return [Finding(
                type="plugin_test",
                value="test-value",
                confidence=0.5,
            )]


    DETECTORS = [MyDetector()]
    """
)


def _write(tmp_path, name, source):
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")


def _config(tmp_path, enabled=True):
    return Config(plugins_enabled=enabled, plugins_dir=tmp_path)


def test_default_plugins_dir_is_home(tmp_path):
    assert str(DEFAULT_PLUGINS_DIR).endswith(".paradox\\plugins") or \
        str(DEFAULT_PLUGINS_DIR).endswith(".paradox/plugins")


def test_disabled_by_default(tmp_path):
    _write(tmp_path, "plugin.py", _PLUGIN)
    result = load_detector_plugins(Config(plugins_dir=tmp_path))
    assert result.detectors == []
    assert result.errors == []


def test_loads_detectors_list(tmp_path):
    _write(tmp_path, "plugin.py", _PLUGIN)
    result = load_detector_plugins(_config(tmp_path))
    assert [d.name for d in result.detectors] == ["my_detector"]
    assert result.errors == []


def test_loads_detector_class(tmp_path):
    _write(tmp_path, "plugin.py", """
        from paradox.models import Finding


        class ClassDetector:
            name = "class_detector"

            def run(self, state, config):
                return []


        DETECTOR = ClassDetector
    """)
    result = load_detector_plugins(_config(tmp_path))
    assert [d.name for d in result.detectors] == ["class_detector"]


def test_underscore_files_skipped(tmp_path):
    _write(tmp_path, "_private.py", _PLUGIN)
    result = load_detector_plugins(_config(tmp_path))
    assert result.detectors == []


def test_syntax_error_reported_not_raised(tmp_path):
    _write(tmp_path, "broken.py", "def oops(:\n")
    result = load_detector_plugins(_config(tmp_path))
    assert result.detectors == []
    assert len(result.errors) == 1
    assert "broken.py" in result.errors[0]


def test_invalid_object_reported(tmp_path):
    _write(tmp_path, "bad.py", """
        class NotADetector:
            name = ""


        DETECTORS = [NotADetector()]
    """)
    result = load_detector_plugins(_config(tmp_path))
    assert result.detectors == []
    assert result.errors


def test_duplicate_with_builtin_name_skipped(tmp_path):
    _write(tmp_path, "dup.py", """
        class Detector:
            name = "beaconing"

            def run(self, state, config):
                return []


        DETECTORS = [Detector()]
    """)
    result = load_detector_plugins(
        _config(tmp_path), reserved_names={"beaconing"},
    )
    assert result.detectors == []
    assert any("уже занято" in e for e in result.errors)


def test_duplicate_between_plugins_skipped(tmp_path):
    _write(tmp_path, "one.py", _PLUGIN)
    _write(tmp_path, "two.py", _PLUGIN)
    result = load_detector_plugins(_config(tmp_path))
    assert len(result.detectors) == 1
    assert len(result.errors) == 1


def test_missing_dir_is_noop(tmp_path):
    result = load_detector_plugins(_config(tmp_path / "absent"))
    assert result.detectors == []


def test_pipeline_includes_plugin_findings(tmp_path):
    _write(tmp_path, "plugin.py", _PLUGIN)
    state = CaptureState()
    findings = _detect(state, _config(tmp_path))
    assert [f.type for f in findings] == ["plugin_test"]


def test_pipeline_skips_plugins_when_disabled(tmp_path):
    _write(tmp_path, "plugin.py", _PLUGIN)
    state = CaptureState()
    findings = _detect(state, _config(tmp_path, enabled=False))
    assert findings == []


def test_plugin_error_counted_in_summary(tmp_path):
    _write(tmp_path, "broken.py", "raise RuntimeError('boom')\n")
    state = CaptureState()
    _detect(state, _config(tmp_path))
    assert state.extractor_errors["plugin"] == 1


def test_plugin_run_error_does_not_break_pipeline(tmp_path):
    _write(tmp_path, "boom.py", """
        class Boom:
            name = "boom"

            def run(self, state, config):
                raise RuntimeError("boom")


        DETECTORS = [Boom()]
    """)
    state = CaptureState()
    findings = _detect(state, _config(tmp_path))
    assert findings == []
    assert state.extractor_errors["detector:boom"] == 1
