"""ADRecon: перечисление каталога по запрошенным атрибутам."""
from paradox.config import Config
from paradox.detectors.ad_recon import ADReconDetector
from paradox.models import CaptureState

CLIENT = "10.0.0.5"


def _state(
    attrs: set[str],
    searches: int = 5,
    root_dse: int = 0,
) -> CaptureState:
    state = CaptureState()
    state.ldap_searches_by_src[CLIENT] = searches
    state.ldap_sensitive_attrs_by_src[CLIENT] = attrs
    state.ldap_root_dse_by_src[CLIENT] = root_dse
    return state


def test_four_sensitive_attributes_are_medium():
    state = _state({
        "memberof", "serviceprincipalname",
        "useraccountcontrol", "samaccounttype",
    })

    findings = ADReconDetector().run(state, Config())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "ad_recon"
    assert finding.severity == "medium"
    assert finding.src_ip == CLIENT
    assert finding.evidence["sensitive_attributes"] == [
        "memberof", "samaccounttype",
        "serviceprincipalname", "useraccountcontrol",
    ]


def test_six_attributes_are_high():
    state = _state({
        "memberof", "serviceprincipalname", "useraccountcontrol",
        "samaccounttype", "objectsid", "pwdlastset",
    })

    findings = ADReconDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_root_dse_spn_probe_is_enough():
    state = _state({"serviceprincipalname"}, searches=1, root_dse=1)

    findings = ADReconDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["spn_probe"] is True


def test_benign_root_dse_is_ignored():
    state = _state({"dnshostname"}, searches=11, root_dse=11)

    assert ADReconDetector().run(state, Config()) == []


def test_one_sensitive_attribute_is_ignored():
    state = _state({"memberof"}, searches=10)

    assert ADReconDetector().run(state, Config()) == []
