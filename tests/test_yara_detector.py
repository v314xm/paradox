"""Тесты YARA-детектора.

Ключевой момент: не полагаемся на наличие yara-python.
Если его нет — проверяем graceful degradation через mock.
Если есть — проверяем реальный скан с корректным MockCarvedFile.
"""
from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from paradox.detectors.yara_detector import YARADetector
from paradox.models import CaptureState

# =============================================================================
# ОБЩИЕ ФИКСТУРЫ
# =============================================================================

@dataclass
class MockCarvedFile:
    """Минимальный слепок CarvedFile — только поля, которые читает yara_detector."""
    sha256: str = "abcdef1234567890" * 4
    uri: str = "/download/test.exe"
    saved_path: str | None = None
    first_bytes_hex: str = ""
    ext: str = ".exe"
    size: int = 100
    content_type: str | None = None
    src_ip: str = "10.0.0.5"
    dst_ip: str = "10.0.0.1"
    truncated: bool = False
    first_ts: float | None = None
    body: bytes | None = None


@dataclass
class MockConfig:
    yara_rules_path: str | None = None


def _has_yara() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


HAS_YARA = _has_yara()


# =============================================================================
# 1. GRACEFUL DEGRADATION — не падаем, если yara нет
# =============================================================================

def test_graceful_degradation_yara_not_installed():
    """Если yara-python не установлена — возвращаем [] без ошибок."""
    with patch("paradox.detectors.yara_detector.yara", None):
        detector = YARADetector()
        state = CaptureState()
        state.carved_files = [MockCarvedFile(first_bytes_hex="4d5a")]
        config = MockConfig(yara_rules_path="whatever.yar")

        findings = detector.run(state, config)
        assert findings == []


def test_no_rules_path_and_no_default():
    """Если не задан yara_rules_path и дефолтный файл не найден — возвращаем []."""
    if not HAS_YARA:
        pytest.skip("yara-python not installed")

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [MockCarvedFile(first_bytes_hex="4d5a")]
    config = MockConfig(yara_rules_path=None)

    # Мокаем os.path.exists так, чтобы дефолтный rules/default.yar "не нашёлся"
    with patch("paradox.detectors.yara_detector.os.path.exists", return_value=False):
        findings = detector.run(state, config)
        assert findings == []


def test_broken_yara_rules_file(tmp_path):
    """Битый .yar-файл → ловим ошибку компиляции, возвращаем []."""
    if not HAS_YARA:
        pytest.skip("yara-python not installed")

    bad_rule = tmp_path / "broken.yar"
    bad_rule.write_text("rule Broken { strings: $a = condition: }", encoding="utf-8")

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [MockCarvedFile(first_bytes_hex="4d5a")]
    config = MockConfig(yara_rules_path=str(bad_rule))

    findings = detector.run(state, config)
    assert findings == []


# =============================================================================
# 2. РЕАЛЬНЫЙ СКАН (если yara установлена)
# =============================================================================

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_real_scan_saved_path(tmp_path):
    """Скан файла на диске через saved_path."""
    import yara  # noqa: F401

    rule_file = tmp_path / "malware.yar"
    rule_file.write_text(
        'rule MalwareSignature {\n'
        '    strings: $a = "EVIL_PAYLOAD"\n'
        '    condition: $a\n'
        '}',
        encoding="utf-8",
    )

    target = tmp_path / "evil.bin"
    target.write_bytes(b"some prefix EVIL_PAYLOAD some suffix")

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [
        MockCarvedFile(saved_path=str(target), first_bytes_hex=""),
    ]
    config = MockConfig(yara_rules_path=str(rule_file))

    findings = detector.run(state, config)
    assert len(findings) == 1
    assert findings[0].type == "yara_match"
    assert findings[0].value == "MalwareSignature"
    assert findings[0].severity == "high"
    assert findings[0].evidence["rule"] == "MalwareSignature"
    # cf.src_ip — сервер, отдавший payload; dst — клиент.
    assert findings[0].src_ip == "10.0.0.5"
    assert findings[0].dst_ip == "10.0.0.1"


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_real_scan_first_bytes_fallback(tmp_path):
    """Fallback на first_bytes_hex, когда saved_path=None."""
    import yara  # noqa: F401

    rule_file = tmp_path / "malware.yar"
    rule_file.write_text(
        'rule MZHeader {\n'
        '    strings: $a = { 4D 5A }\n'  # MZ — сигнатура exe
        '    condition: $a\n'
        '}',
        encoding="utf-8",
    )

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [
        # "4d5a" — hex от b"MZ", первые байты PE-файла
        MockCarvedFile(saved_path=None, first_bytes_hex="4d5a9090"),
    ]
    config = MockConfig(yara_rules_path=str(rule_file))

    findings = detector.run(state, config)
    assert len(findings) == 1
    assert findings[0].value == "MZHeader"


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_invalid_hex_does_not_crash(tmp_path):
    """Если first_bytes_hex битый — не падаем."""
    import yara  # noqa: F401

    rule_file = tmp_path / "any.yar"
    rule_file.write_text(
        'rule Any { strings: $a = "x" condition: $a }',
        encoding="utf-8",
    )

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [
        MockCarvedFile(saved_path=None, first_bytes_hex="невалидный hex"),
    ]
    config = MockConfig(yara_rules_path=str(rule_file))

    # Не падаем, ловим warning через logger
    findings = detector.run(state, config)
    assert findings == []


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_no_duplicate_findings(tmp_path):
    """Один и тот же файл не должен давать два finding (saved_path + first_bytes)."""
    import yara  # noqa: F401

    rule_file = tmp_path / "dup.yar"
    rule_file.write_text(
        'rule Duplicate { strings: $a = "MARKER" condition: $a }',
        encoding="utf-8",
    )

    target = tmp_path / "dup.bin"
    target.write_bytes(b"MARKER_MARKER")
    mz_hex = target.read_bytes()[:64].hex()

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [
        MockCarvedFile(saved_path=str(target), first_bytes_hex=mz_hex),
    ]
    config = MockConfig(yara_rules_path=str(rule_file))

    findings = detector.run(state, config)
    # Правило одно, файл один → один finding, несмотря на два прогона сканера
    assert len(findings) == 1
    assert findings[0].value == "Duplicate"


# =============================================================================
# 3. МОК-ТЕСТ: сканер вызван, но ничего не нашёл
# =============================================================================

@patch("paradox.detectors.yara_detector.yara")
def test_yara_no_matches(mock_yara):
    """Сканер отработал, но совпадений нет → findings пустой."""
    mock_rules = MagicMock()
    mock_rules.match.return_value = []
    mock_yara.compile.return_value = mock_rules

    detector = YARADetector()
    state = CaptureState()
    state.carved_files = [MockCarvedFile(first_bytes_hex="4d5a")]
    config = MockConfig(yara_rules_path="dummy.yar")

    # os.path.exists должен вернуть True для dummy.yar
    with patch("paradox.detectors.yara_detector.os.path.exists", return_value=True):
        findings = detector.run(state, config)

    assert findings == []
    assert mock_yara.compile.called


# =============================================================================
# 4. ВСТРОЕННЫЕ ПРАВИЛА И КЭШ КОМПИЛЯЦИИ
# =============================================================================

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_default_rules_dir_is_shipped():
    """Встроенные правила есть в пакете, а не только в исходниках."""
    from paradox.detectors.yara_detector import _default_rules_path

    assert _default_rules_path() is not None


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_marker_beyond_first_64_bytes_is_found():
    """Матчится всё тело payload'а, а не только первые 64 байта."""
    body = b"JUNK" * 100 + b"meterpreter"
    state = CaptureState()
    state.carved_files = [
        # В первых 64 байтах маркера нет — только полное тело даёт матч.
        MockCarvedFile(first_bytes_hex=body[:64].hex(), body=body),
    ]

    findings = YARADetector().run(state, MockConfig())

    assert [f.value for f in findings] == ["Paradox_Meterpreter_Stage"]
    assert findings[0].severity == "high"


def test_rules_compilation_is_cached(tmp_path):
    """Правила компилируются один раз; правка файла сбрасывает кэш."""
    from paradox.detectors import yara_detector

    rule_file = tmp_path / "cached.yar"
    rule_file.write_text(
        'rule Cached { strings: $a = "X" condition: $a }',
        encoding="utf-8",
    )

    with patch.object(yara_detector, "yara") as mock_yara:
        mock_yara.compile.return_value = MagicMock(match=lambda **_: [])
        yara_detector._RULES_CACHE.clear()
        state = CaptureState()
        config = MockConfig(yara_rules_path=str(rule_file))

        YARADetector().run(state, config)
        YARADetector().run(state, config)
        assert mock_yara.compile.call_count == 1

        # Другой размер → другой ключ кэша.
        rule_file.write_text(
            'rule Cached2 { strings: $a = "XX" condition: $a }',
            encoding="utf-8",
        )
        YARADetector().run(state, config)
        assert mock_yara.compile.call_count == 2
