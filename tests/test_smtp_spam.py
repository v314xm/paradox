"""Тесты SMTP spam детектора."""
from pcap_triage.config import Config
from pcap_triage.detectors.smtp_spam import SMTP_SpamDetector
from pcap_triage.models import CaptureState


def _state_with_rcpt(src, count):
    """Собрать state с N получателями с одного src."""
    state = CaptureState()
    state.smtp_rcpt_by_src[src] = {f"user{i}@target.com" for i in range(count)}
    return state


# ---------- основной триггер ----------

def test_triggers_at_threshold():
    state = _state_with_rcpt("10.0.0.5", 50)
    findings = SMTP_SpamDetector().run(state, Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "smtp_spam"
    assert f.src_ip == "10.0.0.5"
    assert f.evidence["recipients_count"] == 50
    assert f.confidence == 0.7
    assert f.severity == "medium"


def test_below_threshold():
    state = _state_with_rcpt("10.0.0.5", 49)
    findings = SMTP_SpamDetector().run(state, Config())
    assert findings == []


def test_confidence_08_at_200():
    state = _state_with_rcpt("10.0.0.5", 200)
    findings = SMTP_SpamDetector().run(state, Config())
    assert findings[0].confidence == 0.8


def test_confidence_09_at_1000():
    state = _state_with_rcpt("10.0.0.5", 1000)
    findings = SMTP_SpamDetector().run(state, Config())
    assert findings[0].confidence == 0.9


# ---------- изоляция ----------

def test_isolated_by_src():
    """Много RCPT, но у разных src — не спам."""
    state = CaptureState()
    for i in range(5):
        state.smtp_rcpt_by_src[f"10.0.0.{i}"] = {
            f"u{j}@x.com" for j in range(20)
        }
    findings = SMTP_SpamDetector().run(state, Config())
    assert findings == []


def test_uniqueness_counts_only_unique():
    """Повторные RCPT не должны раздувать счётчик."""
    state = CaptureState()
    # set, поэтому дубликаты не считаются, но проверим явно.
    state.smtp_rcpt_by_src["10.0.0.5"] = {"a@x.com", "b@x.com", "c@x.com"}
    findings = SMTP_SpamDetector().run(state, Config())
    assert findings == []


def test_empty_state():
    findings = SMTP_SpamDetector().run(CaptureState(), Config())
    assert findings == []


# ---------- evidence ----------

def test_evidence_helo_and_mailer():
    state = _state_with_rcpt("10.0.0.5", 100)
    state.smtp_helo_by_src["10.0.0.5"] = "spam.evil.com"
    state.smtp_mailer_by_src["10.0.0.5"] = {"PHPMailer 6.6"}
    state.smtp_from_by_src["10.0.0.5"] = {"sender@evil.com"}

    findings = SMTP_SpamDetector().run(state, Config())
    f = findings[0]
    assert f.evidence["helo"] == "spam.evil.com"
    assert f.evidence["from_sample"] == "sender@evil.com"
    assert "phpmailer" in f.evidence["mailer_markers"]


def test_evidence_no_mailer_markers():
    state = _state_with_rcpt("10.0.0.5", 100)
    state.smtp_mailer_by_src["10.0.0.5"] = {"Microsoft Outlook 16.0"}
    findings = SMTP_SpamDetector().run(state, Config())
    # Outlook не содержит масс-мейлерных маркеров.
    assert findings[0].evidence["mailer_markers"] == []


def test_multiple_srcs():
    state = CaptureState()
    state.smtp_rcpt_by_src["A"] = {f"u{i}@x.com" for i in range(60)}
    state.smtp_rcpt_by_src["B"] = {f"u{i}@y.com" for i in range(70)}
    findings = SMTP_SpamDetector().run(state, Config())
    assert len(findings) == 2


def test_custom_threshold():
    cfg = Config()
    object.__setattr__(cfg, "smtp_spam_min_recipients", 10)
    state = _state_with_rcpt("10.0.0.5", 10)
    findings = SMTP_SpamDetector().run(state, cfg)
    assert len(findings) == 1


def test_config_default():
    assert Config().smtp_spam_min_recipients == 50


# ---------- интеграции ----------

def test_mitre_map():
    from pcap_triage.detectors.mitre_map import get_techniques
    techs = get_techniques("smtp_spam")
    assert "T1583.002" in techs


def test_facts_victim_polarity():
    """smtp_spam -> src=victim, dst=attacker (в _VICTIM_SIGNAL_TYPES)."""
    from pcap_triage.contradictions.facts import extract_attack_facts
    from pcap_triage.models import Finding as F

    f = F(
        type="smtp_spam", value="10.0.0.5 -> 100 recipients",
        confidence=0.8,
        src_ip="10.0.0.5", dst_ip="1.2.3.4",
    )
    facts = extract_attack_facts([f])
    preds = {(x.subject, x.predicate) for x in facts}
    assert ("10.0.0.5", "victim_of") in preds
    assert ("1.2.3.4", "attacker_of") in preds


def test_timeline_phase_impact():
    from pcap_triage.timeline import _PHASE_BY_TYPE, _PHASE_ORDER
    assert _PHASE_BY_TYPE["smtp_spam"] == "impact"
    assert _PHASE_ORDER["impact"] == 80


def test_registered_in_detectors():
    from pcap_triage.pipeline import DETECTORS
    names = [getattr(d, "name", "") for d in DETECTORS]
    assert "smtp_spam" in names
