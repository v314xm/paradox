"""Тесты YARA-детектора."""
import pytest
from pcap_triage.detectors.yara_detector import YARADetector
from pcap_triage.models import CaptureState

def test_yara_graceful_degradation():
    """Если yara не установлена — не падаем, возвращаем []."""
    detector = YARADetector()
    state = CaptureState()
    findings = detector.run(state, config=None)
    assert findings == []

# Если yara установлена, тест ниже проверит реальное сканирование
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_real_scan():
    """Реальное сканирование фейкового файла."""
    import yara
    from dataclasses import dataclass

    @dataclass
    class MockCarvedFile:
        data: bytes
        filename: str

    @dataclass
    class MockConfig:
        yara_rules_path: str

    # Создаем временное правило
    import tempfile
    import os

    rule_src = 'rule TestRule { strings: $a = "MALWARE" condition: $a }'
    with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
        f.write(rule_src)
        tmp_path = f.name

    try:
        state = CaptureState()
        state.carved_files = [MockCarvedFile(data=b"this contains MALWARE string", filename="test.exe")]
        config = MockConfig(yara_rules_path=tmp_path)

        detector = YARADetector()
        findings = detector.run(state, config)

        assert len(findings) == 1
        assert findings[0].value == "TestRule"
        assert findings[0].type == "yara_match"
    finally:
        os.unlink(tmp_path)
