"""NBNSExtractor: имя привязывается к ответившему хосту, не к спрашивающему.

Реальный frame 24 из MTA 2025-06-13 — запрос от 10.6.13.133
(«кто такой DESKTOP-5AVE44C?»). Раньше это имя записывалось
самому 10.6.13.133, даже если владелец — другой хост.
"""
from types import SimpleNamespace

from paradox.extractors.nbns import NBNSExtractor
from paradox.models import CaptureState

# NBNS-запрос: qdcount=1, QR=0, имя DESKTOP-5AVE44C<20>
NBNS_QUERY = bytes.fromhex(
    "840d29100001000000000001"
    "20454545464644454c46"
    "4545504641434e44464542464745464445444545444341"
    "0000200001"
    "c00c00200001000493e0000640000a060d85"
)


def _response(query: bytes) -> bytes:
    raw = bytearray(query)
    flags = int.from_bytes(raw[2:4], "big") | 0x8000
    raw[2:4] = flags.to_bytes(2, "big")
    return bytes(raw)


def _record(payload: bytes, src_ip: str = "10.6.13.133"):
    return SimpleNamespace(
        proto="udp", src_port=137, dst_port=137,
        payload=payload, src_ip=src_ip,
    )


def test_query_does_not_assign_name_to_sender():
    state = CaptureState()

    NBNSExtractor().process(_record(NBNS_QUERY), state)

    assert state.host_identities == {}


def test_response_assigns_name_to_responder():
    state = CaptureState()

    NBNSExtractor().process(
        _record(_response(NBNS_QUERY), src_ip="10.6.13.133"), state,
    )

    assert state.host_identities["10.6.13.133"].hostnames == {
        "DESKTOP-5AVE44C",
    }


def test_non_nbns_port_ignored():
    state = CaptureState()
    rec = _record(_response(NBNS_QUERY))
    rec.src_port = rec.dst_port = 53

    NBNSExtractor().process(rec, state)

    assert state.host_identities == {}
