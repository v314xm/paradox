"""Все экстракторы соблюдают контракт Protocol Extractor.

NDPExtractor раньше не объявлял layer — пайплайн это терпел, но
Protocol нарушался. Тест ловит такие расхождения на любом новом
экстракторе.
"""
from paradox.pipeline import EXTRACTORS


def test_extractors_have_name_layer_and_process():
    for extractor in EXTRACTORS:
        assert isinstance(extractor.name, str) and extractor.name
        assert isinstance(getattr(extractor, "layer", None), int), extractor.name
        assert callable(getattr(extractor, "process", None)), extractor.name


def test_extractor_names_are_unique():
    names = [extractor.name for extractor in EXTRACTORS]
    assert len(names) == len(set(names))
