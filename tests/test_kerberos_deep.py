"""Углублённые тесты Kerberos: TGS-REQ, AS-REP, экстрактор."""
import pytest

from paradox.kerberos_parse import parse_kerberos
from paradox.extractors.kerberos import KerberosExtractor
from paradox.models import CaptureState
from paradox.parsers import PacketRecord


# TGS-REQ: msg_type=12, та же структура req-body, что AS-REQ
# (cname=test, realm=EXAMPLE.COM, sname=krbtgt)
TGS_REQ_HEX = (
    "6a723070"
    "a103020105"
    "a20302010c"              # msg-type=12 (TGS-REQ)
    "a4643062"
    "a00703050040810010"
    "a111300fa003020101a10830061b0474657374"
    "a20d1b0b4558414d504c452e434f4d"
    "a3133011a003020101a10a30081b066b7262746774"
    "a511180f32303230303130313030303030305a"
    "a7050203123456"
    "a806300402020017"
)

# AS-REP: msg_type=11, минимальный — только pvno и msg-type
# (cname/crealm в полноценном AS-REP — но нам важно, что msg_type читается)
# [APPLICATION 11] SEQUENCE { [0] INTEGER 5, [1] INTEGER 11 }
# 6b 0c = APPLICATION 11, length 12
#   30 0a = SEQUENCE, length 10
#     a0 03 02 01 05 = [0] INTEGER 5
#     a1 03 02 01 0b = [1] INTEGER 11
AS_REP_MINIMAL_HEX = "6b0c300aa003020105a10302010b"


def test_parse_tgs_req():
    """TGS-REQ (msg_type=12) идёт по той же ветке, что AS-REQ."""
    info = parse_kerberos(bytes.fromhex(TGS_REQ_HEX))
    assert info is not None
    assert info.msg_type == 12
    assert info.cname == "test"
    assert info.realm == "EXAMPLE.COM"
    assert info.sname == "krbtgt"


def test_parse_as_rep_msg_type_only():
    """AS-REP (msg_type=11): парсер не падает, msg_type извлекается."""
    info = parse_kerberos(bytes.fromhex(AS_REP_MINIMAL_HEX))
    assert info is not None
    assert info.msg_type == 11


# ---- Тесты экстрактора (extractors/kerberos.py) ----------------------------


def _make_kerberos_record(payload_hex: str, src_port: int = 49152,
                          dst_port: int = 88) -> PacketRecord:
    """Собирает PacketRecord для Kerberos-пакета."""
    payload = bytes.fromhex(payload_hex)
    return PacketRecord(
        ts=100.0,
        length=len(payload) + 20,
        raw=payload,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
        proto="udp",
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
    )


def test_extractor_username_from_cname():
    """Из AS-REQ извлекается username из cname."""
    record = _make_kerberos_record(AS_REQ_HEX_FOR_EXTRACTOR)
    state = CaptureState()
    KerberosExtractor().process(record, state)

    assert "10.0.0.5" in state.host_identities
    ident = state.host_identities["10.0.0.5"]
    assert ident.username == "test"
    assert ident.realm == "EXAMPLE.COM"
    assert not ident.hostnames  # cname без $ — это user, hostnames пустой set


def test_extractor_hostname_from_cname_with_dollar():
    """cname с $ в конце → hostname (без $)."""
    record = _make_kerberos_record(AS_REQ_MACHINE_HEX)
    state = CaptureState()
    KerberosExtractor().process(record, state)

    ident = state.host_identities["10.0.0.5"]
    assert "DESKTOP-ABC" in ident.hostnames  # без $ — это hostname
    assert ident.username is None  # machine account, не user


def test_extractor_service_principal_ignored():
    """cname со / (SPN) — игнорируется."""
    record = _make_kerberos_record(AS_REQ_SPN_HEX)
    state = CaptureState()
    KerberosExtractor().process(record, state)

    ident = state.host_identities.get("10.0.0.5")
    if ident is not None:
        assert ident.username is None
        assert not ident.hostnames


def test_extractor_ignores_non_kerberos():
    """Не-Kerberos порт — пропускается."""
    record = _make_kerberos_record(AS_REQ_HEX_FOR_EXTRACTOR,
                                   src_port=5000, dst_port=9999)
    state = CaptureState()
    KerberosExtractor().process(record, state)
    assert state.host_identities == {}


def test_extractor_kdc_response():
    """Пакет от KDC (src_port=88) → client_ip = dst_ip."""
    payload = bytes.fromhex(AS_REP_MINIMAL_HEX)
    record = PacketRecord(
        ts=100.0,
        length=len(payload) + 20,
        raw=payload,
        src_ip="10.0.0.1",       # KDC
        dst_ip="10.0.0.5",       # клиент
        proto="udp",
        src_port=88,
        dst_port=49152,
        payload=payload,
    )
    state = CaptureState()
    KerberosExtractor().process(record, state)

    # identity создан для клиента (dst)
    assert "10.0.0.5" in state.host_identities


# ---- Hex-примеры для экстрактора ------------------------------------------

AS_REQ_HEX_FOR_EXTRACTOR = (
    "6a723070a103020105a20302010aa4643062"
    "a00703050040810010"
    "a111300fa003020101a10830061b0474657374"
    "a20d1b0b4558414d504c452e434f4d"
    "a3133011a003020101a10a30081b066b7262746774"
    "a511180f32303230303130313030303030305a"
    "a7050203123456"
    "a806300402020017"
)

# cname = "DESKTOP-ABC$" (12 символов, включая $)
AS_REQ_MACHINE_HEX = (
    "6a7a3078"
    "a103020105"
    "a20302010a"
    "a46c306a"
    "a00703050040810010"
    "a1193017a003020101a110300e1b0c4445534b544f502d41424324"  # DESKTOP-ABC$
    "a20d1b0b4558414d504c452e434f4d"
    "a3133011a003020101a10a30081b066b7262746774"
    "a511180f32303230303130313030303030305a"
    "a7050203123456"
    "a806300402020017"
)

# cname = "krbtgt/EXAMPLE.COM" (18 символов, SPN)
AS_REQ_SPN_HEX = (
    "6a7b3079a103020105a20302010aa46b3069"
    "a00703050040810010"
    "a11f301da003020101a11630141b126b72627467742f4558414d504c452e434f4d"
    "a20d1b0b4558414d504c452e434f4d"
    "a3133011a003020101a10a30081b066b7262746774"
    "a511180f32303230303130313030303030305a"
    "a7050203123456"
    "a806300402020017"
)
