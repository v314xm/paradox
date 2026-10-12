"""
Тесты JA3/JA3S парсера и детектора.

ClientHello/ServerHello строятся синтетически — без сети и без scapy.
"""
import struct
import types
from dataclasses import replace

from pcap_triage.config import Config
from pcap_triage.detectors.ja3_malware import JA3MalwareDetector
from pcap_triage.ja3 import parse_client_hello, parse_server_hello
from pcap_triage.models import CaptureState, FlowKey, FlowStats


# ---------- helpers ----------

def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _build_client_hello(
    version: int = 0x0303,
    ciphers: tuple[int, ...] = (0x1301, 0x1302),
    extensions: tuple[tuple[int, bytes], ...] = (),
    sni: str | None = None,
    random: bytes = b"\x00" * 32,
    session_id: bytes = b"",
) -> bytes:
    exts_data = b""
    if sni is not None:
        name = sni.encode("ascii")
        entry = struct.pack(">B", 0) + struct.pack(">H", len(name)) + name
        sni_data = struct.pack(">H", len(entry)) + entry
        exts_data += _ext(0, sni_data)
    for et, ed in extensions:
        exts_data += _ext(et, ed)

    body = struct.pack(">H", version) + random
    body += struct.pack(">B", len(session_id)) + session_id
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += struct.pack(">B", 1) + b"\x00"
    body += struct.pack(">H", len(exts_data)) + exts_data

    hs = struct.pack(">B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack(">B", 0x16) + b"\x03\x01"
    record += struct.pack(">H", len(hs)) + hs
    return record


def _build_server_hello(
    version: int = 0x0303,
    cipher: int = 0x1301,
    extensions: tuple[tuple[int, bytes], ...] = (),
) -> bytes:
    exts_data = b""
    for et, ed in extensions:
        exts_data += _ext(et, ed)

    body = struct.pack(">H", version) + b"\x00" * 32
    body += struct.pack(">B", 0)
    body += struct.pack(">H", cipher)
    body += struct.pack(">B", 0)
    body += struct.pack(">H", len(exts_data)) + exts_data

    hs = struct.pack(">B", 0x02) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack(">B", 0x16) + b"\x03\x01"
    record += struct.pack(">H", len(hs)) + hs
    return record


# ---------- JA3 parser ----------

def test_ja3_minimal_client_hello():
    payload = _build_client_hello(
        version=0x0303,
        ciphers=(0x1301, 0x1302),
        extensions=(),
        sni=None,
    )
    r = parse_client_hello(payload)
    assert r is not None
    assert r["ja3_raw"] == "771,4865-4866,,,"
    assert len(r["ja3"]) == 32


def test_ja3_with_extensions_and_sni():
    sg = struct.pack(">H", 4) + struct.pack(">HH", 29, 23)
    pf = struct.pack(">B", 1) + b"\x00"

    payload = _build_client_hello(
        ciphers=(0x1301,),
        extensions=((10, sg), (11, pf)),
        sni="example.com",
    )
    r = parse_client_hello(payload)
    assert r is not None
    assert r["sni"] == "example.com"
    assert r["ja3_raw"] == "771,4865,0-10-11,29-23,0"


def test_ja3_not_client_hello():
    payload = b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00"
    assert parse_client_hello(payload) is None
    assert parse_client_hello(b"") is None
    assert parse_client_hello(b"\x00" * 100) is None


def test_ja3s_server_hello():
    payload = _build_server_hello(
        version=0x0303,
        cipher=0x1301,
        extensions=((43, b"\x00\x00"),),
    )
    r = parse_server_hello(payload)
    assert r is not None
    assert r["ja3s_raw"] == "771,4865,43"
    assert len(r["ja3s"]) == 32


# ---------- detector ----------

def test_ja3_detector_matches_known():
    config = replace(
        Config(),
        ja3_known_malware=types.MappingProxyType({
            "deadbeef" * 4: "TestMalware",
        }),
    )

    state = CaptureState()
    key = FlowKey(proto="tcp", src_ip="192.168.1.10",
                  dst_ip="203.0.113.5", src_port=50000, dst_port=443)
    fs = FlowStats(packets=10, bytes_sent=1000)
    fs.ja3 = "deadbeef" * 4
    state.flows[key] = fs

    findings = JA3MalwareDetector().run(state, config)
    assert len(findings) == 1
    assert findings[0].type == "ja3_malware"
    assert findings[0].evidence["tool_name"] == "TestMalware"


def test_ja3_detector_unknown_not_flagged():
    state = CaptureState()
    key = FlowKey(proto="tcp", src_ip="192.168.1.10",
                  dst_ip="203.0.113.5", src_port=50000, dst_port=443)
    fs = FlowStats(packets=10, bytes_sent=1000)
    fs.ja3 = "0" * 32
    state.flows[key] = fs

    findings = JA3MalwareDetector().run(state, Config())
    assert findings == []


def test_ja3_detector_empty_state():
    findings = JA3MalwareDetector().run(CaptureState(), Config())
    assert findings == []


def test_ja3_detector_aggregates():
    config = replace(
        Config(),
        ja3_known_malware=types.MappingProxyType({"cafe" * 8: "TestTool"}),
    )
    state = CaptureState()
    for i in range(3):
        key = FlowKey(proto="tcp", src_ip="192.168.1.10",
                      dst_ip="203.0.113.5", src_port=50000 + i, dst_port=443)
        fs = FlowStats(packets=10, bytes_sent=1000)
        fs.ja3 = "cafe" * 8
        state.flows[key] = fs

    findings = JA3MalwareDetector().run(state, config)
    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 3