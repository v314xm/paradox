"""
Тесты FileCarve.

Вариант A: только метаданные. Никаких файлов на диск.
"""
from pcap_triage.config import Config
from pcap_triage.file_carve import carve_files
from pcap_triage.http_object import HttpObject
from pcap_triage.models import CaptureState, FlowKey


def _state(response_bodies):
    state = CaptureState()
    objs = []
    for i, (src_ip, uri, ct, body) in enumerate(response_bodies):
        key = FlowKey(
            proto="tcp", src_ip=src_ip, dst_ip="10.0.1.50",
            src_port=80, dst_port=50000 + i,
        )
        obj = HttpObject(
            kind="response",
            status_code=200,
            headers={"content-type": ct},
            body=body,
            body_size=len(body),
        )
        objs.append((key, obj))
    state.http_objects = objs
    return state


def test_carve_extracts_metadata_exe():
    """MZ + octet-stream → .exe, метаданные заполнены."""
    body = b"MZ" + b"\x00" * 2048
    state = _state([("10.0.1.50", "/x.exe", "application/octet-stream", body)])
    carved = carve_files(state, Config())
    assert len(carved) == 1
    c = carved[0]
    assert c.ext == ".exe"
    assert c.size == len(body)
    assert c.saved_path is None                # НЕ сохранили на диск
    assert len(c.sha256) == 64                 # sha256 hex
    assert c.first_bytes_hex.startswith("4d5a")  # MZ hex


def test_carve_shell_script():
    body = b"#!/bin/sh\n" + b"echo hi\n" * 200
    state = _state([("10.0.1.50", "/x.sh", "text/x-shellscript", body)])
    carved = carve_files(state, Config())
    assert len(carved) == 1
    assert carved[0].ext == ".sh"


def test_carve_skips_html():
    body = b"<html>" + b"x" * 2048 + b"</html>"
    state = _state([("10.0.1.50", "/index.html", "text/html", body)])
    carved = carve_files(state, Config())
    assert carved == []


def test_carve_skips_json():
    body = b'{"data": "' + b"x" * 2048 + b'"}'
    state = _state([("10.0.1.50", "/api", "application/json", body)])
    carved = carve_files(state, Config())
    assert carved == []


def test_carve_skips_small():
    # body 22 байта < file_carve_min_size=64
    body = b"MZ" + b"\x00" * 20
    state = _state([("10.0.1.50", "/x.exe", "application/octet-stream", body)])
    carved = carve_files(state, Config())
    assert carved == []


def test_carve_deduplicates_by_hash():
    body = b"MZ" + b"\x00" * 2048
    state = _state([
        ("10.0.1.50", "/a.exe", "application/octet-stream", body),
        ("10.0.1.50", "/b.exe", "application/octet-stream", body),
        ("10.0.1.50", "/c.exe", "application/octet-stream", body),
    ])
    carved = carve_files(state, Config())
    assert len(carved) == 1


def test_carve_ignores_requests():
    state = CaptureState()
    key = FlowKey(
        proto="tcp", src_ip="10.0.1.50", dst_ip="10.0.0.1",
        src_port=50000, dst_port=80,
    )
    obj = HttpObject(
        kind="request", method="POST", uri="/x",
        body=b"MZ" + b"\x00" * 2048,
        body_size=2050,
    )
    state.http_objects = [(key, obj)]
    carved = carve_files(state, Config())
    assert carved == []


def test_carve_empty_state():
    assert carve_files(CaptureState(), Config()) == []


def test_carve_no_body_written_by_default(tmp_path):
    """По умолчанию body НЕ пишется на диск, даже если output_dir задан."""
    body = b"MZ" + b"\x00" * 2048
    state = _state([("10.0.1.50", "/x.exe", "application/octet-stream", body)])
    carved = carve_files(state, Config(), output_dir=tmp_path)
    assert len(carved) == 1
    # Файл НЕ создан, потому что config.file_carve_write_body=False
    assert list(tmp_path.iterdir()) == []
    assert carved[0].saved_path is None