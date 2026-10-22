"""Tests for file_carve write_body behavior (fix_22)."""
from pathlib import Path

from paradox.config import Config
from paradox.file_carve import carve_files
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey


def _state_with_payload(payload: bytes) -> CaptureState:
    state = CaptureState()
    key = FlowKey(
        proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=80, dst_port=12345,
    )
    obj = HttpObject(
        kind="response",
        status_code=200,
        headers={"content-type": "application/x-msdownload"},
        body=payload,
        body_size=len(payload),
    )
    state.http_objects = [(key, obj)]
    return state


def test_carve_metadata_only_no_disk_write(tmp_path):
    """write_body=False (default) — тело на диск не пишется."""
    payload = b"MZ" + b"\x00" * 100
    state = _state_with_payload(payload)
    cfg = Config(file_carve_write_body=False)

    files = carve_files(state, cfg, output_dir=tmp_path)

    assert len(files) == 1
    assert files[0].saved_path is None
    assert not list(tmp_path.iterdir())


def test_carve_writes_body_when_enabled(tmp_path):
    """write_body=True + output_dir — тело сохраняется как <sha256>.bin."""
    payload = b"MZ" + b"\x00" * 100
    state = _state_with_payload(payload)
    cfg = Config(file_carve_write_body=True)

    files = carve_files(state, cfg, output_dir=tmp_path)

    assert len(files) == 1
    saved = files[0].saved_path
    assert saved is not None
    p = Path(saved)
    assert p.exists()
    assert p.read_bytes() == payload
    assert p.suffix == ".bin"


def test_pipeline_passes_carved_subdir():
    """Регрессия fix_22: pipeline._extract передавал output_dir=None.

    carve_files корректно обрабатывает output_dir=None, но раньше
    pipeline именно так и вызывал — saved_path всегда был None даже
    при write_body=True. Ловим регрессию на уровне источника.
    """
    import inspect

    import paradox.pipeline

    src = inspect.getsource(paradox.pipeline._extract)
    assert '_carved_dir = config.output_dir / "carved"' in src, (
        "pipeline._extract должен передавать output_dir/carved "
        "в carve_files — иначе write_body не работает"
    )
