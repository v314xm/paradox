"""Тесты SSH brute force детектора."""
from pcap_triage.config import Config
from pcap_triage.detectors.ssh_brute_force import SSHBruteForceDetector
from pcap_triage.extractors.ssh_banner import SSHBannerExtractor
from pcap_triage.models import CaptureState


class _Rec:
    """Заглушка PacketRecord."""
    def __init__(self, payload: bytes, src_port: int, dst_port: int,
                 src_ip: str = "10.0.0.5", dst_ip: str = "192.168.1.10"):
        self.payload = payload
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip


def _state_with_attempts(src, dst, port, n):
    """Собрать state напрямую, без экстрактора."""
    state = CaptureState()
    state.ssh_client_attempts[(src, dst, port)] = n
    return state


# ---------- детектор ----------

def test_triggers_at_threshold():
    state = _state_with_attempts("10.0.0.5", "192.168.1.10", 22, 20)
    findings = SSHBruteForceDetector().run(state, Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "ssh_brute_force"
    assert f.src_ip == "10.0.0.5"
    assert f.dst_ip == "192.168.1.10"
    assert f.dst_port == 22
    assert f.evidence["attempts"] == 20
    assert f.confidence == 0.75
    assert f.severity == "high"


def test_below_threshold():
    state = _state_with_attempts("10.0.0.5", "192.168.1.10", 22, 19)
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings == []


def test_confidence_85_at_50():
    state = _state_with_attempts("10.0.0.5", "192.168.1.10", 22, 50)
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings[0].confidence == 0.85


def test_confidence_95_at_100():
    state = _state_with_attempts("10.0.0.5", "192.168.1.10", 22, 100)
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings[0].confidence == 0.95


def test_isolated_by_dst():
    """25 попыток, но к 5 разным dst — не brute force."""
    state = CaptureState()
    for i in range(5):
        state.ssh_client_attempts[("10.0.0.5", f"1.1.1.{i}", 22)] = 5
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings == []


def test_isolated_by_src():
    """25 попыток к одному dst, но с 5 разных src — не brute force."""
    state = CaptureState()
    for i in range(5):
        state.ssh_client_attempts[(f"10.0.0.{i}", "192.168.1.10", 22)] = 5
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings == []


def test_isolated_by_port():
    """25 попыток, но на 5 разных портов — не brute force."""
    state = CaptureState()
    for port in (22, 2222, 2022, 22022, 22222):
        state.ssh_client_attempts[("10.0.0.5", "192.168.1.10", port)] = 5
    findings = SSHBruteForceDetector().run(state, Config())
    assert findings == []


def test_multiple_pairs():
    state = CaptureState()
    state.ssh_client_attempts[("10.0.0.5", "192.168.1.10", 22)] = 30
    state.ssh_client_attempts[("10.0.0.6", "192.168.1.11", 22)] = 40
    findings = SSHBruteForceDetector().run(state, Config())
    assert len(findings) == 2


def test_empty_state():
    findings = SSHBruteForceDetector().run(CaptureState(), Config())
    assert findings == []


def test_custom_threshold():
    cfg = Config()
    object.__setattr__(cfg, "ssh_brute_force_min_flows", 5)
    state = _state_with_attempts("10.0.0.5", "192.168.1.10", 22, 5)
    findings = SSHBruteForceDetector().run(state, cfg)
    assert len(findings) == 1


# ---------- экстрактор: инкремент попыток ----------

def test_extractor_increments_attempts():
    state = CaptureState()
    # 3 клиентских баннера к одному серверу.
    for _ in range(3):
        SSHBruteForce_Extractor_helper(state)
    key = ("10.0.0.5", "192.168.1.10", 22)
    assert state.ssh_client_attempts.get(key) == 3


def SSHBruteForce_Extractor_helper(state):
    rec = _Rec(
        b"SSH-2.0-libssh-0.10.4\r\n",
        src_port=54321, dst_port=22,
    )
    SSHBannerExtractor().process(rec, state)


def test_extractor_no_attempts_from_server():
    """Баннер от сервера не считается попыткой."""
    state = CaptureState()
    rec = _Rec(
        b"SSH-2.0-OpenSSH_8.2p1\r\n",
        src_port=22, dst_port=54321,
        src_ip="192.168.1.10", dst_ip="10.0.0.5",
    )
    SSHBannerExtractor().process(rec, state)
    assert not state.ssh_client_attempts


def test_config_default():
    assert Config().ssh_brute_force_min_flows == 20


# ---------- интеграция с MITRE, timeline, entities ----------

def test_mitre_map_has_ssh_brute_force():
    from pcap_triage.detectors.mitre_map import get_techniques
    techs = get_techniques("ssh_brute_force")
    assert "T1110.001" in techs
    assert "T1021.004" in techs


def test_facts_attacker_polarity():
    from pcap_triage.contradictions.facts import (
        extract_attack_facts,
    )
    from pcap_triage.models import Finding as F

    f = F(
        type="ssh_brute_force", value="10.0.0.5 -> 1.2.3.4:22",
        confidence=0.9,
        src_ip="10.0.0.5", dst_ip="1.2.3.4",
    )
    facts = extract_attack_facts([f])
    preds = {(x.subject, x.predicate) for x in facts}
    assert ("10.0.0.5", "attacker_of") in preds
    assert ("1.2.3.4", "victim_of") in preds


def test_timeline_phase_initial_access():
    from pcap_triage.timeline import _PHASE_BY_TYPE
    assert _PHASE_BY_TYPE["ssh_brute_force"] == "initial_access"
