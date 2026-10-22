"""f01: удалить dead nested tests в tests/test_detectors.py.

Внутри test_vulnerable_path_queries_in_uri определены 6 вложенных
def test_* — pytest их не видит, код мёртвый. Часть дублирует
test_regressions.py.
"""
from pathlib import Path

from tools._patcher import assert_applied, assert_not_present, patch

NAME = "f01: drop dead nested tests in test_detectors.py"
FILES = ["tests/test_detectors.py"]

_OLD = '''def test_vulnerable_path_queries_in_uri():
    """Расширение с ?query — тоже должно ловиться."""
    from paradox.detectors.vulnerable_path import VulnerablePathDetector
    def test_typosquatting_sld_only():
        # googleads — поддомен doubleclick, не бренд
        detector = TyposquattingDetector()
        state = _make_state_with_dns(["googleads.g.doubleclick.net"])
        findings = detector.run(state, Config())
        assert not [f for f in findings if f.value == "googleads.g.doubleclick.net"]

    def test_typosquatting_app_subdomain_not_squat():
        # app.loadimpact.com — SLD loadimpact, не apple
        ...

    def test_typosquatting_still_catches_real():
        # micr0soft.com -> SLD micr0soft, levenshtein 1 до microsoft
        ...

    def test_dga_stackoverflow_not_flagged():
        detector = DGADetector()
        state = _make_state_with_dns(["stackoverflow.com"])
        findings = detector.run(state, Config())
        assert not findings

    def test_typosquatting_sld_only_doubleclick():
        """googleads.g.doubleclick.net — SLD doubleclick, не google."""
        detector = TyposquattingDetector()
        state = _make_state_with_dns(["googleads.g.doubleclick.net"])
        findings = detector.run(state, Config())
        assert not [f for f in findings if f.value == "googleads.g.doubleclick.net"]

    def test_typosquatting_app_subdomain_not_squat():
        """app.loadimpact.com — SLD loadimpact, не apple."""
        detector = TyposquattingDetector()
        state = _make_state_with_dns(["app.loadimpact.com"])
        findings = detector.run(state, Config())
        assert not findings

    def test_typosquatting_google_analytics_allowlisted():
        detector = TyposquattingDetector()
        state = _make_state_with_dns(["google-analytics.com"])
        findings = detector.run(state, Config())
        assert not findings

    def test_dga_stackoverflow_not_flagged():
        detector = DGADetector()
        state = _make_state_with_dns(["stackoverflow.com"])
        findings = detector.run(state, Config())
        assert not findings

    state = CaptureState()'''

_NEW = '''def test_vulnerable_path_queries_in_uri():
    """Расширение с ?query — тоже должно ловиться."""
    from paradox.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], _NEW)
    assert_not_present(
        root, FILES[0],
        "    def test_typosquatting_sld_only_doubleclick():",
    )
