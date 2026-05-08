from __future__ import annotations
from pathlib import Path

from chimera.parsers.network_security_config import parse_nsc, NSCModel

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nsc"


def test_parse_clean_nsc():
    nsc = parse_nsc(FIXTURES / "clean.xml")
    assert isinstance(nsc, NSCModel)
    assert nsc.base_config.cleartext_traffic_permitted is False
    assert "system" in nsc.base_config.trust_anchors
    assert len(nsc.domain_configs) == 1
    dc = nsc.domain_configs[0]
    assert "api.example.com" in dc.domains
    assert dc.has_pin_set is True
    assert dc.cleartext_traffic_permitted is None


def test_parse_cleartext_permitted_nsc():
    nsc = parse_nsc(FIXTURES / "cleartext_permitted.xml")
    assert nsc.base_config.cleartext_traffic_permitted is True
    assert nsc.base_config.line > 0
    assert nsc.domain_configs[0].cleartext_traffic_permitted is True


def test_parse_user_ca_trusted_nsc():
    nsc = parse_nsc(FIXTURES / "user_ca_trusted.xml")
    assert "user" in nsc.base_config.trust_anchors
    assert "system" in nsc.base_config.trust_anchors
