from paradox.contradictions.facts import extract_attack_facts, extract_arp_facts
from paradox.models import Finding, CaptureState


def test_extract_attack_facts():
    findings = [
        Finding(type="brute_force", value="1.1.1.1 -> 2.2.2.2", confidence=0.9, src_ip="1.1.1.1", dst_ip="2.2.2.2"),
        Finding(type="large_transfer", value="A <-> B", confidence=0.8, src_ip="3.3.3.3", dst_ip="4.4.4.4",
                evidence={"direction": "outbound"})
    ]
    facts = extract_attack_facts(findings)

    # Проверяем, что из brute_force извлеклись роли
    assert any(f.predicate == "attacker_of" and f.subject == "1.1.1.1" for f in facts)
    assert any(f.predicate == "victim_of" and f.subject == "2.2.2.2" for f in facts)

    # Проверяем large_transfer (outbound = victim exfil)
    assert any(f.predicate == "victim_of" and f.subject == "3.3.3.3" for f in facts)


def test_extract_arp_facts():
    state = CaptureState()
    state.arp_macs = {
        "192.168.1.1": {
            "aa:bb:cc:dd:ee:ff": [100.0, 150.0, 5],  # 5 пакетов
            "11:22:33:44:55:66": [160.0, 200.0, 2],  # 2 пакета
        }
    }
    facts = extract_arp_facts(state)
    assert len(facts) == 2
    assert facts[0].subject == "192.168.1.1"
    assert facts[0].predicate == "has_mac"
    assert facts[0].confidence == 0.9  # 5 пакетов -> уверенность 0.9
    assert facts[1].confidence == 0.6  # 2 пакета -> уверенность 0.6